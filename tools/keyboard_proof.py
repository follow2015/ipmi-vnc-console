"""Bounded keyboard proof: does a platform key event reach the host itself?"""
from __future__ import annotations

import argparse
import base64
import json
import multiprocessing
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from kvmhub.run import manager_process, worker_process  # noqa: E402
from kvmhub.store import Store  # noqa: E402
from tools.bootstrap import generate  # noqa: E402
from tools.browser_e2e import _find_chromium, _find_playwright  # noqa: E402
from tools.passthrough_check import session_state, wait_port  # noqa: E402

SETTLE_SECONDS = 4.0


def prepare(directory: Path, host: str, fingerprint: str, username: str, password: str):
    root = generate(directory)
    key = base64.b64decode((root / "encryption.key").read_text().strip())
    target = f"https://{host}"
    store = Store(root / "manager.sqlite3", key, passthrough_targets=(target,))
    try:
        store.seed_passthrough(target=target, fingerprint=fingerprint, username=username,
                               password=password, approver="tools/keyboard_proof.py")
    finally:
        store.close()
    manager_path = root / "manager.json"
    manager_cfg = json.loads(manager_path.read_text())
    manager_cfg["passthrough_targets"] = [target]
    manager_path.write_text(json.dumps(manager_cfg, indent=2) + "\n")
    return root, key, target


def run_browser(node: str, module: str, chromium: str, base: str, token: str, asset: str,
                shots: str | None = None):
    env = dict(os.environ, KVM_PLAYWRIGHT=module, KVM_CHROMIUM=chromium,
               KVM_BASE=base, KVM_TOKEN=token, KVM_ASSET=asset)
    if shots:
        env["KVM_SHOTS"] = shots
    completed = subprocess.run([node, "tools/keyboard_proof.cjs"], cwd=ROOT, env=env,
                               capture_output=True, text=True, timeout=180)
    payload = None
    for line in completed.stdout.splitlines():
        if line.startswith("RESULT "):
            payload = json.loads(line[len("RESULT "):])
    return payload, completed.returncode, completed.stderr[-800:]


def judge(payload: dict, state: dict | None) -> tuple[bool, dict]:
    idle = payload.get("canvas_idle") or {}
    typed = payload.get("canvas_typed") or {}
    restored = payload.get("canvas_restored") or {}

    idle_pixels = idle.get("pixels", -1)
    typed_pixels = typed.get("pixels", -1)
    restored_pixels = restored.get("pixels", -1)

    settled = payload.get("canvas_size_stable") is True
    control_valid = settled and idle_pixels >= 0
    threshold = max(200, (idle_pixels if idle_pixels > 0 else 0) * 5)
    visible = control_valid and typed_pixels > threshold and typed.get("bbox") is not None
    reversible = (settled and restored_pixels >= 0 and restored_pixels < typed_pixels
                  and restored_pixels <= max(idle_pixels * 3, 150))
    lifecycle = payload.get("state_after_input") == "normal" and state is not None \
        and state.get("cleanup") == "confirmed"

    verdict = {
        "keystroke_reached_host": visible,
        "echo_removed": reversible,
        "session_lifecycle": lifecycle,
        "framebuffer_settled": settled,
    }
    return (visible and reversible and lifecycle and not payload.get("errors")), verdict


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--host", required=True)
    parser.add_argument("--cert-sha256", required=True)
    parser.add_argument("--directory", default=".local-keyboard")
    parser.add_argument("--asset", default="real-1")
    parser.add_argument("--out")
    parser.add_argument("--shots", help="local PNG directory; never committed")
    parser.add_argument("--keep", action="store_true", help="keep the fixture directory")
    parser.add_argument("--playwright", default=os.environ.get("KVM_PLAYWRIGHT"))
    parser.add_argument("--chromium", default=os.environ.get("KVM_CHROMIUM"))
    parser.add_argument("--node", default="node")
    args = parser.parse_args()

    username, password = os.environ.get("BMC_USER"), os.environ.get("BMC_PASSWORD")
    if not username or not password:
        parser.error("BMC_USER and BMC_PASSWORD must be set")
    fingerprint = args.cert_sha256.replace(":", "").lower()
    if len(fingerprint) != 64 or any(c not in "0123456789abcdef" for c in fingerprint):
        parser.error("--cert-sha256 must be 64 hex characters")
    module = args.playwright or _find_playwright()
    chromium = args.chromium or _find_chromium()
    if not module or not chromium:
        parser.error("playwright-core and a Chromium build are required (see tools/browser_e2e.py)")

    from kvmhub.common import UI_ORIGIN, UI_PORT, WORKER_PORT

    directory = ROOT / args.directory
    if directory.exists():
        parser.error(f"{directory} already exists; choose a fresh --directory")
    root, key, target = prepare(directory, args.host, fingerprint, username, password)
    token = (root / "login-token").read_text().strip()

    ctx = multiprocessing.get_context("spawn")
    processes = [ctx.Process(target=manager_process, args=(str(root / "manager.json"),), name="manager"),
                 ctx.Process(target=worker_process, args=(str(root / "worker.json"),), name="worker")]
    evidence = {"target_host": args.host, "asset": args.asset,
                "adapter": "supermicro-x10-passthrough", "claim": "keyboard reaches the host",
                "steps": [], "errors": []}
    exit_code = 1
    try:
        for process in processes:
            process.start()
        ready = wait_port(UI_PORT) and wait_port(WORKER_PORT)
        evidence["services_ready"] = ready
        if not ready:
            evidence["errors"].append("services_not_ready")
            return 1
        payload, returncode, stderr = run_browser(args.node, module, chromium, UI_ORIGIN, token,
                                                  args.asset, args.shots)
        evidence["browser_exit"] = returncode
        if stderr:
            evidence["browser_stderr_tail"] = stderr
        if payload is None:
            evidence["errors"].append("browser_produced_no_result")
            return 1
        evidence.update(payload)

        time.sleep(SETTLE_SECONDS)
        state, actions = session_state(root, key, target)
        evidence["session"] = state
        evidence["audit_actions"] = actions[-12:]
        ok, verdict = judge(payload, state)
        evidence["verdict_checks"] = verdict
        evidence["verdict"] = "pass" if ok else "fail"
        exit_code = 0 if ok else 1
    finally:
        for process in processes:
            if process.is_alive():
                process.terminate()
        for process in processes:
            process.join(timeout=10)
            if process.is_alive():
                process.kill()
                process.join()
        if args.out:
            out = Path(args.out)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(json.dumps(evidence, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        if not args.keep:
            shutil.rmtree(root, ignore_errors=True)
    print(json.dumps({k: evidence.get(k) for k in
                      ("verdict", "verdict_checks", "canvas_size", "canvas_idle", "canvas_typed",
                       "canvas_erase_change", "canvas_restored", "keys_sent", "state_after_input",
                       "session", "errors")},
                     indent=2, ensure_ascii=False))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
