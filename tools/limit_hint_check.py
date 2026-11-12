"""Connection-limit drill: a second tab must be told why it cannot connect."""
from __future__ import annotations

import argparse
import json
import multiprocessing
import os
import queue
import shutil
import subprocess
import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from kvmhub.run import manager_process, worker_process  # noqa: E402
from kvmhub.store import Store  # noqa: E402
from tools.browser_e2e import _find_chromium, _find_playwright  # noqa: E402
from tools.passthrough_check import prepare, wait_port  # noqa: E402
from tools.revoke_check import Manager, finish_browser  # noqa: E402


def hint_verdict(evidence: dict) -> dict:
    reasons: list[str] = []
    if evidence.get("errors") or (evidence.get("browser") or {}).get("errors"):
        reasons.append("browser_errors")
    if (evidence.get("canvas_initial") or {}).get("non_black", 0) <= 0:
        reasons.append("no_picture_before_second_tab")
    tab = evidence.get("second_tab") or {}
    if tab.get("state") == "normal":
        reasons.append("second_tab_connected")
    elif tab.get("state") is not None:
        reasons.append("second_tab_attempted_connect")
    text = tab.get("status_text") or ""
    if "上限" not in text:
        reasons.append("message_missing")
    elif str(evidence.get("expected_limit")) not in text:
        reasons.append("message_wrong_limit")
    if evidence.get("state_after_second_tab") != "normal":
        reasons.append("first_tab_disturbed")
    if (evidence.get("session") or {}).get("status") != "active":
        reasons.append("session_not_active")
    return {"verdict": "pass" if not reasons else "fail", "reasons": reasons}


def run_browser(node: str, module: str, chromium: str, base: str, token: str, asset: str,
                screenshot: str | None):
    env = dict(os.environ, KVM_PLAYWRIGHT=module, KVM_CHROMIUM=chromium, KVM_BASE=base,
               KVM_TOKEN=token, KVM_ASSET=asset, KVM_SECOND_TAB="1")
    if screenshot:
        env["KVM_SCREENSHOT"] = screenshot
    process = subprocess.Popen([node, "tools/passthrough_browser.cjs"], cwd=ROOT, env=env,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
    lines: list[str] = []
    errors: list[str] = []
    done: queue.Queue = queue.Queue()

    def pump():
        for line in process.stdout:
            lines.append(line)
        done.put(None)

    def drain():
        for line in process.stderr:
            errors.append(line)

    threading.Thread(target=pump, daemon=True).start()
    threading.Thread(target=drain, daemon=True).start()
    try:
        done.get(timeout=180)
    except queue.Empty:
        pass
    return process, lines, errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--host", required=True)
    parser.add_argument("--cert-sha256", required=True)
    parser.add_argument("--directory", default=".local-limit")
    parser.add_argument("--protocol-versions", default="")
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
    versions = tuple(v.strip() for v in args.protocol_versions.split(",") if v.strip())
    module = args.playwright or _find_playwright()
    chromium = args.chromium or _find_chromium()
    if not module or not chromium:
        parser.error("playwright-core and a Chromium build are required (see tools/browser_e2e.py)")

    from kvmhub.common import UI_ORIGIN, UI_PORT, WORKER_PORT

    directory = ROOT / args.directory
    if directory.exists():
        parser.error(f"{directory} already exists; choose a fresh --directory")
    root, key, target = prepare(directory, args.host, fingerprint, username, password, versions)
    token = (root / "login-token").read_text().strip()
    asset = "real-1"

    ctx = multiprocessing.get_context("spawn")
    processes = [ctx.Process(target=manager_process, args=(str(root / "manager.json"),), name="manager"),
                 ctx.Process(target=worker_process, args=(str(root / "worker.json"),), name="worker")]
    evidence = {"target_host": args.host, "asset": asset, "expected_limit": 1,
                "adapter": "supermicro-x10-passthrough", "errors": []}
    exit_code = 1
    store = None
    try:
        for process in processes:
            process.start()
        evidence["services_ready"] = wait_port(UI_PORT) and wait_port(WORKER_PORT)
        if not evidence["services_ready"]:
            evidence["errors"].append("services_not_ready")
            return 1

        manager = Manager(root, UI_ORIGIN)
        manager.login(token)
        store = Store(root / "manager.sqlite3", key, passthrough_targets=(target,))

        browser, lines, stderr_lines = run_browser(
            args.node, module, chromium, UI_ORIGIN, token, asset, args.screenshot)
        result, code = finish_browser(browser, lines, stderr_lines)
        evidence["browser_exit"] = code
        if stderr_lines:
            evidence["browser_stderr_tail"] = "".join(stderr_lines)[-400:]
        evidence["browser"] = {k: result.get(k) for k in
                               ("steps", "errors", "console_errors", "http_404", "second_tab")}
        evidence.update({"canvas_initial": result.get("canvas_initial"),
                         "second_tab": result.get("second_tab"),
                         "state_after_second_tab": result.get("state_after_second_tab"),
                         "canvas_after_second_tab": result.get("canvas_after_second_tab")})

        row = store.db.execute(
            "SELECT id,status,cleanup,reason FROM session ORDER BY created DESC LIMIT 1").fetchone()
        evidence["session"] = dict(row) if row else None
        if row and row["id"]:
            evidence["audit_actions"] = [r[0] for r in store.db.execute(
                "SELECT action FROM audit WHERE session_id=? ORDER BY id", (row["id"],))]
            manager.revoke(row["id"])

        verdict = hint_verdict(evidence)
        evidence.update(verdict)
        exit_code = 0 if verdict["verdict"] == "pass" else 1
    finally:
        if store is not None:
            store.close()
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
            out.write_text(json.dumps(evidence, indent=2, ensure_ascii=False) + "\n",
                           encoding="utf-8")
        if not args.keep:
            shutil.rmtree(root, ignore_errors=True)
    print(json.dumps({k: evidence.get(k) for k in
                      ("verdict", "reasons", "errors", "expected_limit", "second_tab",
                       "state_after_second_tab", "session", "canvas_initial")},
                     indent=2, ensure_ascii=False))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
