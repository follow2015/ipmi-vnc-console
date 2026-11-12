"""Bounded end-to-end check of the passthrough console against one real BMC."""
from __future__ import annotations

import argparse
import base64
import json
import multiprocessing
import os
import shutil
import socket
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

STARTUP_TIMEOUT = 60.0
SETTLE_SECONDS = 5.0


def wait_port(port: int, timeout: float = STARTUP_TIMEOUT) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with socket.socket() as sock:
            sock.settimeout(0.5)
            if sock.connect_ex(("127.0.0.1", port)) == 0:
                return True
        time.sleep(0.2)
    return False


def prepare(directory: Path, host: str, fingerprint: str, username: str, password: str):
    root = generate(directory)
    key = base64.b64decode((root / "encryption.key").read_text().strip())
    target = f"https://{host}"
    store = Store(root / "manager.sqlite3", key, passthrough_targets=(target,))
    try:
        store.seed_passthrough(target=target, fingerprint=fingerprint, username=username,
                               password=password, approver="tools/passthrough_check.py")
    finally:
        store.close()
    manager_path = root / "manager.json"
    manager_cfg = json.loads(manager_path.read_text())
    manager_cfg["passthrough_targets"] = [target]
    manager_path.write_text(json.dumps(manager_cfg, indent=2) + "\n")
    return root, key, target


def session_state(root: Path, key: bytes, target: str):
    store = Store(root / "manager.sqlite3", key, passthrough_targets=(target,))
    try:
        row = store.db.execute(
            "SELECT status,cleanup,reason,consumed FROM session ORDER BY created DESC LIMIT 1").fetchone()
        actions = [r[0] for r in store.db.execute("SELECT action FROM audit ORDER BY id")]
        return (dict(row) if row else None), actions
    finally:
        store.close()


def run_browser(node: str, module: str, chromium: str, base: str, token: str, asset: str,
                screenshot: str | None = None):
    env = dict(os.environ, KVM_PLAYWRIGHT=module, KVM_CHROMIUM=chromium,
               KVM_BASE=base, KVM_TOKEN=token, KVM_ASSET=asset)
    if screenshot:
        env["KVM_SCREENSHOT"] = screenshot
    completed = subprocess.run([node, "tools/passthrough_browser.cjs"], cwd=ROOT, env=env,
                               capture_output=True, text=True, timeout=180)
    payload = None
    for line in completed.stdout.splitlines():
        if line.startswith("RESULT "):
            payload = json.loads(line[len("RESULT "):])
    return payload, completed.returncode, completed.stderr[-800:]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--host", required=True)
    parser.add_argument("--cert-sha256", required=True)
    parser.add_argument("--directory", default=".local-passthrough")
    parser.add_argument("--asset", default="real-1")
    parser.add_argument("--out")
    parser.add_argument("--screenshot", help="local PNG path; never committed")
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

    from kvmhub.common import UI_PORT, UI_ORIGIN, WORKER_PORT

    directory = ROOT / args.directory
    if directory.exists():
        parser.error(f"{directory} already exists; choose a fresh --directory")
    root, key, target = prepare(directory, args.host, fingerprint, username, password)
    token = (root / "login-token").read_text().strip()

    ctx = multiprocessing.get_context("spawn")
    processes = [ctx.Process(target=manager_process, args=(str(root / "manager.json"),), name="manager"),
                 ctx.Process(target=worker_process, args=(str(root / "worker.json"),), name="worker")]
    evidence = {"target_host": args.host, "asset": args.asset,
                "adapter": "supermicro-x10-passthrough", "steps": [], "errors": []}
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
                                                  args.asset, args.screenshot)
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
        ok = (not payload["errors"]
              and payload.get("canvas_initial", {}).get("non_black", 0) > 0
              and payload.get("state_after_input") == "normal"
              and payload.get("client_bytes_after", 0) > payload.get("client_bytes_before", 0)
              and state is not None and state["cleanup"] == "confirmed")
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
                      ("verdict", "services_ready", "steps", "errors", "canvas_initial",
                       "canvas_after_input", "state_after_input", "session")},
                     indent=2, ensure_ascii=False))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
