"""Bounded click proof: does a left-button press reach the host itself?"""
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
CLICK_MIN_PIXELS = 1500
RESTORE_RATIO = 0.15
RESTORE_FLOOR = 2500


def prepare(directory: Path, host: str, fingerprint: str, username: str, password: str):
    root = generate(directory)
    key = base64.b64decode((root / "encryption.key").read_text().strip())
    target = f"https://{host}"
    store = Store(root / "manager.sqlite3", key, passthrough_targets=(target,))
    try:
        store.seed_passthrough(target=target, fingerprint=fingerprint, username=username,
                               password=password, approver="tools/click_proof.py")
    finally:
        store.close()
    manager_path = root / "manager.json"
    manager_cfg = json.loads(manager_path.read_text())
    manager_cfg["passthrough_targets"] = [target]
    manager_path.write_text(json.dumps(manager_cfg, indent=2) + "\n")
    return root, key, target


def run_browser(node: str, module: str, chromium: str, base: str, token: str, asset: str,
                *, shots: str | None = None, click: tuple[int, int] = (512, 384),
                unlock: bool = False, dismiss: tuple[int, int] | None = None):
    env = dict(os.environ, KVM_PLAYWRIGHT=module, KVM_CHROMIUM=chromium,
               KVM_BASE=base, KVM_TOKEN=token, KVM_ASSET=asset,
               KVM_CLICK_X=str(click[0]), KVM_CLICK_Y=str(click[1]))
    if shots:
        env["KVM_SHOTS"] = shots
    if unlock:
        env["KVM_UNLOCK"] = "1"
    if dismiss:
        env["KVM_DISMISS_X"], env["KVM_DISMISS_Y"] = str(dismiss[0]), str(dismiss[1])
    completed = subprocess.run([node, "tools/click_proof.cjs"], cwd=ROOT, env=env,
                               capture_output=True, text=True, timeout=300)
    payload = None
    for line in completed.stdout.splitlines():
        if line.startswith("RESULT "):
            payload = json.loads(line[len("RESULT "):])
    return payload, completed.returncode, completed.stderr[-800:]


def judge(payload: dict, state: dict | None) -> tuple[bool, dict]:
    lit = (payload.get("canvas_lit") or {}).get("lit", 0)
    idle = (payload.get("canvas_idle") or {}).get("pixels", -1)
    stable = payload.get("canvas_size_stable") is True
    clicked = (payload.get("clicked") or {}).get("pixels", -1)
    restored = (payload.get("restored") or {}).get("pixels", -1)

    signal_present = lit >= MIN_LIT_PIXELS
    control_valid = signal_present and stable and idle >= 0

    opened = clicked >= CLICK_MIN_PIXELS
    local = payload.get("change_at_target") is True
    ceiling = min(clicked * 0.5, max(clicked * RESTORE_RATIO, RESTORE_FLOOR)) if clicked > 0 else RESTORE_FLOOR
    undone = 0 <= restored <= ceiling
    proven = control_valid and opened and local and undone

    lifecycle = payload.get("state_after_input") == "normal" and state is not None \
        and state.get("cleanup") == "confirmed"
    verdict = {
        "framebuffer_has_signal": signal_present,
        "control_frame_quiet": control_valid,
        "click_changed_the_host_screen": opened,
        "change_landed_at_the_target": local,
        "change_reverted_when_dismissed": undone,
        "click_reached_host": proven,
        "session_lifecycle": lifecycle,
        "clicked_pixels": clicked,
        "restored_pixels": restored,
        "restore_ceiling": round(ceiling),
        "dismissed_by": payload.get("restored_by"),
    }
    ok = proven and lifecycle and not payload.get("errors")
    return ok, verdict


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--host", required=True)
    parser.add_argument("--cert-sha256", required=True)
    parser.add_argument("--directory", default=".local-click")
    parser.add_argument("--asset", default="real-1")
    parser.add_argument("--click", nargs=2, type=int, metavar=("X", "Y"), default=[512, 384],
                        help="target in framebuffer pixels")
    parser.add_argument("--unlock", action="store_true",
                        help="send the on-screen Ctrl+Alt+Delete gesture first")
    parser.add_argument("--dismiss", nargs=2, type=int, metavar=("X", "Y"),
                        help="fallback dismissal point if Escape leaves the panel open")
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
                "adapter": "supermicro-x10-passthrough", "claim": "a click reaches the host",
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
        payload, returncode, stderr = run_browser(
            args.node, module, chromium, UI_ORIGIN, token, args.asset,
            shots=args.shots, click=tuple(args.click), unlock=args.unlock,
            dismiss=tuple(args.dismiss) if args.dismiss else None)
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
                      ("verdict", "verdict_checks", "canvas_size", "canvas_lit", "canvas_idle",
                       "prepared_screen", "clicked", "restored", "restored_by", "clicks",
                       "wire_frames", "state_after_input", "session", "errors")},
                     indent=2, ensure_ascii=False))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
