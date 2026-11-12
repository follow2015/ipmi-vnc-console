"""Bounded pointer proof: does a pointer event reach the host itself?"""
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
MIN_LIT_PIXELS = 500
MENU_MIN_PIXELS = 2000
CURSOR_MAX_PIXELS = 6000
HOVER_MAX_SPAN = 80


def prepare(directory: Path, host: str, fingerprint: str, username: str, password: str):
    root = generate(directory)
    key = base64.b64decode((root / "encryption.key").read_text().strip())
    target = f"https://{host}"
    store = Store(root / "manager.sqlite3", key, passthrough_targets=(target,))
    try:
        store.seed_passthrough(target=target, fingerprint=fingerprint, username=username,
                               password=password, approver="tools/pointer_proof.py")
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
    completed = subprocess.run([node, "tools/pointer_proof.cjs"], cwd=ROOT, env=env,
                               capture_output=True, text=True, timeout=240)
    payload = None
    for line in completed.stdout.splitlines():
        if line.startswith("RESULT "):
            payload = json.loads(line[len("RESULT "):])
    return payload, completed.returncode, completed.stderr[-800:]


def judge(payload: dict, state: dict | None) -> tuple[bool, dict]:
    lit = (payload.get("canvas_lit") or {}).get("lit", 0)
    idle = (payload.get("canvas_idle") or {}).get("pixels", -1)
    menu = (payload.get("canvas_menu") or {}).get("pixels", -1)
    dismissed = (payload.get("canvas_menu_dismissed") or {}).get("pixels", -1)

    signal_present = lit >= MIN_LIT_PIXELS
    control_valid = signal_present and idle >= 0 and (payload.get("canvas_size_stable") is True)

    steps = payload.get("cursor_steps") or []
    localised_hits = [step for step in steps
                      if step.get("hit") and 0 < step.get("pixels", 0) <= CURSOR_MAX_PIXELS]
    cursor_proven = control_valid and len(localised_hits) >= 2

    hovers = payload.get("hover") or []
    localised_hovers = [step for step in hovers
                        if (step.get("bbox") or [0, 0, 9999, 9999])[2] <= HOVER_MAX_SPAN
                        and (step.get("bbox") or [0, 0, 9999, 9999])[3] <= HOVER_MAX_SPAN
                        and step.get("pixels", 0) > 100]
    hover_proven = control_valid and len(localised_hovers) >= 1

    menu_proven = (control_valid and menu >= MENU_MIN_PIXELS
                   and 0 <= dismissed < menu / 4
                   and dismissed <= max(idle * 3, 300))
    lifecycle = payload.get("state_after_input") == "normal" and state is not None \
        and state.get("cleanup") == "confirmed"

    verdict = {
        "framebuffer_has_signal": signal_present,
        "cursor_followed_the_pointer": cursor_proven,
        "hover_reached_host": hover_proven,
        "context_menu_reached_host": menu_proven,
        "session_lifecycle": lifecycle,
    }
    ok = (cursor_proven or hover_proven or menu_proven) and lifecycle and not payload.get("errors")
    return ok, verdict


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--host", required=True)
    parser.add_argument("--cert-sha256", required=True)
    parser.add_argument("--directory", default=".local-pointer")
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
                "adapter": "supermicro-x10-passthrough", "claim": "pointer reaches the host",
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
                      ("verdict", "verdict_checks", "canvas_lit", "canvas_idle", "cursor_steps",
                       "cursor_hits", "best_hover", "canvas_menu", "canvas_menu_dismissed",
                       "moves", "right_clicks", "state_after_input", "session", "errors")},
                     indent=2, ensure_ascii=False))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
