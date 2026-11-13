"""Operator driver for the passthrough console: send input, capture the screen."""
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
from tools.passthrough_check import wait_port  # noqa: E402


def prepare(directory: Path, host: str, fingerprint: str, username: str, password: str,
            reconnect_grace: float | None = None):
    root = generate(directory)
    key = base64.b64decode((root / "encryption.key").read_text().strip())
    target = f"https://{host}"
    store = Store(root / "manager.sqlite3", key, passthrough_targets=(target,))
    try:
        store.seed_passthrough(target=target, fingerprint=fingerprint, username=username,
                               password=password, approver="tools/console_ops.py")
    finally:
        store.close()
    manager_path = root / "manager.json"
    manager_cfg = json.loads(manager_path.read_text())
    manager_cfg["passthrough_targets"] = [target]
    manager_path.write_text(json.dumps(manager_cfg, indent=2) + "\n")
    if reconnect_grace is not None:
        worker_path = root / "worker.json"
        worker_cfg = json.loads(worker_path.read_text())
        worker_cfg["reconnect_grace_seconds"] = reconnect_grace
        worker_path.write_text(json.dumps(worker_cfg, indent=2) + "\n")
    return root, key, target


def run_browser(node: str, module: str, chromium: str, base: str, token: str, asset: str,
                actions: str, shots: str | None, timeout: int, *, attempt: int = 1,
                health_every: int = 20, recover_ms: int = 12000):
    env = dict(os.environ, KVM_PLAYWRIGHT=module, KVM_CHROMIUM=chromium,
               KVM_BASE=base, KVM_TOKEN=token, KVM_ASSET=asset, KVM_ACTIONS=actions,
               KVM_ATTEMPT=str(attempt), KVM_HEALTH_EVERY=str(health_every),
               KVM_RECOVER_MS=str(recover_ms))
    if shots:
        env["KVM_SHOTS"] = shots
    try:
        completed = subprocess.run([node, "tools/console_ops.cjs"], cwd=ROOT, env=env,
                                   capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"errors": ["browser_timeout"], "resume": json.loads(actions)}, -1, "browser timeout"
    payload = None
    for line in completed.stdout.splitlines():
        if line.startswith("RESULT "):
            payload = json.loads(line[len("RESULT "):])
    return payload, completed.returncode, completed.stderr[-800:]


def plan_retry(payload: dict | None, attempt: int, retries: int) -> list | None:
    if not payload or attempt > retries:
        return None
    errors = [str(error) for error in (payload.get("errors") or [])]
    lost = any(error.startswith("vnc_session_lost:") or error == "browser_timeout"
               for error in errors)
    resume = payload.get("resume") or []
    return resume if lost and resume else None


def load_actions(spec: str) -> list:
    if spec == "-":
        text = sys.stdin.read()
    elif spec.startswith("@"):
        text = Path(spec[1:]).read_text(encoding="utf-8")
    else:
        text = spec
    actions = json.loads(text)
    if not isinstance(actions, list) or not actions:
        raise SystemExit("--actions must be a non-empty JSON array")
    return actions


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--host", required=True)
    parser.add_argument("--cert-sha256", required=True)
    parser.add_argument("--actions", required=True,
                        help="JSON array, '-' for stdin, or @file")
    parser.add_argument("--shots", default=".local-console/shots")
    parser.add_argument("--directory", help="fixture directory; default .local-console/<utc stamp>")
    parser.add_argument("--asset", default="real-1")
    parser.add_argument("--out", help="write the action log here")
    parser.add_argument("--timeout", type=int, default=900, help="browser subprocess timeout")
    parser.add_argument("--retries", type=int, default=2,
                        help="session rebuilds allowed after a lost VNC connection (default 2)")
    parser.add_argument("--retry-delay", type=float, default=3.0,
                        help="seconds to let the Worker report the ended session before rebuilding")
    parser.add_argument("--health-every", type=int, default=20,
                        help="driver steps between console health probes (default 20)")
    parser.add_argument("--recover-ms", type=int, default=12000,
                        help="how long the driver waits for the in-page reconnect")
    parser.add_argument("--reconnect-grace", type=float, default=None,
                        help="override the Worker's reconnect grace window in seconds")
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
    if args.retries < 0 or args.retry_delay < 0 or args.health_every < 1 or args.recover_ms < 1000:
        parser.error("--retries/--retry-delay must be >= 0, --health-every >= 1, --recover-ms >= 1000")
    if args.reconnect_grace is not None and not 0.1 <= args.reconnect_grace <= 30:
        parser.error("--reconnect-grace must be within 0.1..30 seconds")

    from kvmhub.common import UI_ORIGIN, UI_PORT, WORKER_PORT

    actions = load_actions(args.actions)
    directory = Path(args.directory) if args.directory else \
        ROOT / ".local-console" / time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    if directory.exists():
        parser.error(f"{directory} already exists; choose a fresh --directory")
    shots = Path(args.shots)
    shots.mkdir(parents=True, exist_ok=True)

    root, _key, _target = prepare(directory, args.host, fingerprint, username, password,
                                  args.reconnect_grace)
    token = (root / "login-token").read_text().strip()

    ctx = multiprocessing.get_context("spawn")
    processes = [ctx.Process(target=manager_process, args=(str(root / "manager.json"),), name="manager"),
                 ctx.Process(target=worker_process, args=(str(root / "worker.json"),), name="worker")]
    record = {"target_host": args.host, "asset": args.asset, "purpose": "operator session",
              "actions": actions, "shots": str(shots), "errors": []}
    session_attempts = []
    record["session_attempts"] = session_attempts
    exit_code = 1
    try:
        for process in processes:
            process.start()
        ready = wait_port(UI_PORT) and wait_port(WORKER_PORT)
        record["services_ready"] = ready
        if not ready:
            record["errors"].append("services_not_ready")
            return 1

        pending = actions
        attempt = 1
        while True:
            payload, returncode, stderr = run_browser(
                args.node, module, chromium, UI_ORIGIN, token, args.asset,
                json.dumps(pending), str(shots), args.timeout,
                attempt=attempt, health_every=args.health_every,
                recover_ms=args.recover_ms)
            errors = list((payload or {}).get("errors") or [])
            resume = (payload or {}).get("resume") or []
            retry_actions = plan_retry(payload, attempt, args.retries)
            session_attempts.append({
                "attempt": attempt, "actions": len(pending), "browser_exit": returncode,
                "errors": errors, "health": (payload or {}).get("health"),
                "recovered": (payload or {}).get("recovered"),
                "resume_actions": len(resume),
            })
            if retry_actions is None:
                break
            time.sleep(args.retry_delay)
            pending = retry_actions
            attempt += 1

        record["browser_exit"] = returncode
        if stderr:
            record["browser_stderr_tail"] = stderr
        if payload is None:
            record["errors"].append("browser_produced_no_result")
            return 1
        record.update(payload)
        record["session_attempts"] = session_attempts
        exit_code = 0 if not payload.get("errors") else 1
        if exit_code and any("asset_busy" in str(error) or "Timeout 20000ms exceeded" in str(error)
                             for error in payload.get("errors") or []):
            record["recovery_hint"] = "session_rebuild_blocked_by_cleanup_pending"
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
            out.write_text(json.dumps(record, indent=2, ensure_ascii=False) + "\n",
                           encoding="utf-8")
        shutil.rmtree(root, ignore_errors=True)

    print(json.dumps({k: record.get(k) for k in
                      ("canvas_size", "action_log", "state_after", "errors",
                       "session_attempts", "recovery_hint") if record.get(k) is not None},
                     indent=2, ensure_ascii=False))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
