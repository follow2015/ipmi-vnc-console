"""Revoke drill: cut a live real-BMC console from the Manager and prove the cut."""
from __future__ import annotations

import argparse
import contextlib
import http.cookiejar
import json
import multiprocessing
import os
import queue
import shutil
import signal
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from kvmhub.run import manager_process, worker_process  # noqa: E402
from kvmhub.store import Store  # noqa: E402
from tools.browser_e2e import _find_chromium, _find_playwright  # noqa: E402
from tools.passthrough_check import prepare, wait_port  # noqa: E402

MAX_CLOSE_MS = 5000

MAX_CLEANUP_MS = 8000

READY_TIMEOUT_MS = 20000


def parse_ready(line: str) -> dict | None:
    if not isinstance(line, str) or not line.startswith("READY "):
        return None
    try:
        payload = json.loads(line[len("READY "):])
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None


def revoke_verdict(evidence: dict) -> dict:
    reasons: list[str] = []
    expected = evidence.get("expected_reason", "revoked")
    if evidence.get("errors"):
        reasons.append("browser_errors")
    if (evidence.get("canvas_initial") or {}).get("non_black", 0) <= 0:
        reasons.append("no_picture")
    if evidence.get("state_after_input") != "normal":
        reasons.append("console_not_normal")
    session = evidence.get("session") or {}
    if session.get("status") not in ("closed", "failed", "lost"):
        reasons.append("status_not_closed")
    if session.get("reason") != expected:
        reasons.append(f"reason_not_{expected}")
    if session.get("cleanup") != "confirmed":
        reasons.append("cleanup_not_confirmed")
    if not evidence.get("slot_released"):
        reasons.append("slot_not_released")
    required = "session_revoked" if expected == "revoked" else "session_finished"
    if required not in (evidence.get("audit_actions") or []):
        reasons.append("revoke_not_audited" if expected == "revoked" else "end_not_audited")
    cut = evidence.get("cut") or {}
    if cut.get("timeout") or cut.get("final_state") in (None, "normal"):
        reasons.append("console_still_live")
    close_bound = evidence.get("close_bound_ms", MAX_CLOSE_MS)
    if (evidence.get("cut_to_close_ms") or close_bound + 1) > close_bound:
        reasons.append("close_too_slow")
    cleanup_bound = evidence.get("cleanup_bound_ms", MAX_CLEANUP_MS)
    if (evidence.get("cut_to_cleanup_ms") or cleanup_bound + 1) > cleanup_bound:
        reasons.append("cleanup_too_slow")
    return {"verdict": "pass" if not reasons else "fail", "reasons": reasons}


class Manager:

    def __init__(self, root: Path, origin: str):
        context = ssl.create_default_context(cafile=str(root / "ca.pem"))
        self.origin = origin
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=context),
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        self.csrf = ""

    def _call(self, method: str, path: str, body: dict | None = None) -> tuple[int, dict]:
        data = None if body is None else json.dumps(body).encode()
        request = urllib.request.Request(self.origin + path, data=data, method=method)
        request.add_header("Origin", self.origin)
        if data is not None:
            request.add_header("Content-Type", "application/json")
        if self.csrf:
            request.add_header("X-CSRF-Token", self.csrf)
        try:
            with self.opener.open(request, timeout=10) as response:
                return response.status, _json(response.read())
        except urllib.error.HTTPError as error:
            return error.code, _json(error.read())

    def login(self, token: str) -> None:
        status, body = self._call("POST", "/api/login", {"token": token})
        if status != 200:
            raise RuntimeError(f"manager login failed: HTTP {status} {body}")
        status, me = self._call("GET", "/api/me")
        if status != 200:
            raise RuntimeError(f"manager session not established: HTTP {status}")
        self.csrf = me["csrf"]

    def allocate(self, asset: str) -> tuple[int, dict]:
        return self._call("POST", f"/api/assets/{asset}/sessions")

    def revoke(self, sid: str) -> tuple[int, dict]:
        return self._call("POST", f"/api/sessions/{sid}/close")

    def release(self, sid: str) -> tuple[int, dict]:
        return self._call("POST", f"/api/sessions/{sid}/release")


def _json(raw: bytes) -> dict:
    try:
        value = json.loads(raw or b"{}")
    except json.JSONDecodeError:
        return {}
    return value if isinstance(value, dict) else {}


def run_browser(node: str, module: str, chromium: str, base: str, token: str, asset: str,
                timeout_ms: int, screenshot: str | None):
    env = dict(os.environ, KVM_PLAYWRIGHT=module, KVM_CHROMIUM=chromium, KVM_BASE=base,
               KVM_TOKEN=token, KVM_ASSET=asset, KVM_REVOKE_MODE="1",
               KVM_REVOKE_TIMEOUT_MS=str(timeout_ms))
    if screenshot:
        env["KVM_SCREENSHOT"] = screenshot
    process = subprocess.Popen([node, "tools/passthrough_browser.cjs"], cwd=ROOT, env=env,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
    lines: list[str] = []
    errors: list[str] = []
    ready: queue.Queue = queue.Queue()

    def pump():
        for line in process.stdout:
            lines.append(line)
            payload = parse_ready(line)
            if payload is not None:
                ready.put(payload)
        ready.put(None)

    def drain():
        for line in process.stderr:
            errors.append(line)

    threading.Thread(target=pump, daemon=True).start()
    threading.Thread(target=drain, daemon=True).start()

    handshake = None
    try:
        handshake = ready.get(timeout=timeout_ms / 1000 + 90)
    except queue.Empty:
        pass
    return process, handshake, lines, errors


def finish_browser(process, lines: list[str], stderr_lines: list[str]) -> tuple[dict, int]:
    try:
        code = process.wait(timeout=90)
    except subprocess.TimeoutExpired:
        process.kill()
        code = -1
    result = {}
    for line in reversed(lines):
        if line.startswith("RESULT "):
            try:
                value = json.loads(line[len("RESULT "):])
            except json.JSONDecodeError:
                continue
            if isinstance(value, dict):
                result = value
            break
    return result, code


def wait_state(store: Store, sid: str, cleanup: str, timeout: float = 15.0):
    from kvmhub.common import Problem

    deadline = time.monotonic() + timeout
    row = None
    while time.monotonic() < deadline:
        try:
            row = store.get(sid)
        except Problem:
            row = None
        if row and row["cleanup"] == cleanup:
            return row, time.time() * 1000
        time.sleep(0.05)
    return row, None


def slot_holder(store: Store, asset: str) -> str | None:
    row = store.db.execute("SELECT session_id FROM asset_slot WHERE asset_id=?", (asset,)).fetchone()
    return row["session_id"] if row else None


def audit_actions(store: Store, sid: str) -> list[str]:
    return [r[0] for r in store.db.execute(
        "SELECT action FROM audit WHERE session_id=? ORDER BY id", (sid,))]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--host", required=True)
    parser.add_argument("--cert-sha256", required=True)
    parser.add_argument("--directory", default=".local-revoke")
    parser.add_argument("--protocol-versions", default="",
                        help="comma-separated RFB greetings approved for this device")
    parser.add_argument("--out")
    parser.add_argument("--screenshot", help="local PNG path; never committed")
    parser.add_argument("--revoke-timeout-ms", type=int, default=READY_TIMEOUT_MS)
    parser.add_argument("--lose-manager", action="store_true",
                        help="hold the Manager instead of revoking, so only the worker's "
                             "lease can end the session (design §11 fallback)")
    parser.add_argument("--keep", action="store_true", help="keep the fixture directory")
    parser.add_argument("--playwright", default=os.environ.get("KVM_PLAYWRIGHT"))
    parser.add_argument("--chromium", default=os.environ.get("KVM_CHROMIUM"))
    parser.add_argument("--node", default="node")
    args = parser.parse_args()

    if args.lose_manager and os.name != "posix":
        parser.error("--lose-manager needs SIGSTOP/SIGCONT and is POSIX-only")

    username, password = os.environ.get("BMC_USER"), os.environ.get("BMC_PASSWORD")
    if not username or not password:
        parser.error("BMC_USER and BMC_PASSWORD must be set")
    fingerprint = args.cert_sha256.replace(":", "").lower()
    if len(fingerprint) != 64 or any(c not in "0123456789abcdef" for c in fingerprint):
        parser.error("--cert-sha256 must be 64 hex characters")
    versions = tuple(v.strip() for v in args.protocol_versions.split(",") if v.strip())
    browser_timeout = max(args.revoke_timeout_ms, 45_000) if args.lose_manager else args.revoke_timeout_ms
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
    evidence = {"target_host": args.host, "asset": asset,
                "adapter": "supermicro-x10-passthrough",
                "approved_protocol_versions": list(versions),
                "errors": []}
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

        browser, handshake, lines, stderr_lines = run_browser(
            args.node, module, chromium, UI_ORIGIN, token, asset, browser_timeout,
            args.screenshot)
        if handshake is None:
            evidence["errors"].append("browser_never_reached_normal")
            if browser.poll() is None:
                browser.kill()
            result, code = finish_browser(browser, lines, stderr_lines)
            if stderr_lines:
                evidence["browser_stderr_tail"] = "".join(stderr_lines)[-400:]
            evidence["browser"] = {k: result.get(k) for k in ("steps", "errors", "console_errors")}
            evidence["browser_exit"] = code
            evidence["verdict"] = "fail"
            return 1

        active = store.db.execute(
            "SELECT id FROM session WHERE status IN ('active','connecting') "
            "ORDER BY created DESC LIMIT 1").fetchone()
        evidence["services_ready"] = True
        evidence["console"] = {"state": handshake.get("state"),
                               "canvas": handshake.get("canvas"),
                               "client_bytes": handshake.get("client_bytes")}
        evidence["session_id_matches"] = bool(active and handshake.get("sid") == active["id"])
        if not active:
            evidence["errors"].append("no_active_session")
            evidence["verdict"] = "fail"
            return 1
        sid = active["id"]

        evidence["slot_held_at_cut"] = slot_holder(store, asset) == sid
        sent_at = time.time() * 1000
        if args.lose_manager:
            evidence["cut_kind"] = "manager_unreachable"
            evidence["expected_reason"] = "lease_expired"
            evidence["close_bound_ms"] = 40_000
            evidence["cleanup_bound_ms"] = 40_000 + MAX_CLEANUP_MS
            os.kill(processes[0].pid, signal.SIGSTOP)
            evidence["revoke_status"] = None
        else:
            evidence["cut_kind"] = "revoke"
            evidence["expected_reason"] = "revoked"
            evidence["close_bound_ms"] = MAX_CLOSE_MS
            evidence["cleanup_bound_ms"] = MAX_CLEANUP_MS
            status, body = manager.revoke(sid)
            evidence["revoke_status"] = status
            evidence["revoke_body"] = body
            evidence["slot_held_after_revoke_response"] = slot_holder(store, asset) == sid
            if status != 200:
                evidence["errors"].append("revoke_rejected")
                evidence["verdict"] = "fail"
                return 1

        result, code = finish_browser(browser, lines, stderr_lines)
        evidence["browser_exit"] = code
        if stderr_lines:
            evidence["browser_stderr_tail"] = "".join(stderr_lines)[-400:]
        evidence["browser"] = {
            key_name: result.get(key_name) for key_name in
            ("steps", "errors", "console_errors", "http_404", "cut",
             "canvas_after_cut", "canvas_after_cut_settled", "state_after_input")}
        evidence.update({
            "canvas_initial": result.get("canvas_initial"),
            "state_after_input": result.get("state_after_input"),
            "cut": result.get("cut"),
        })
        cut = result.get("cut") or {}
        if cut.get("closed_at"):
            evidence["cut_to_close_ms"] = int(cut["closed_at"] - sent_at)

        if args.lose_manager:
            os.kill(processes[0].pid, signal.SIGCONT)
            evidence["manager_resumed"] = True

        row, confirmed_at = wait_state(store, sid, "confirmed", timeout=60.0)
        evidence["session"] = {k: row[k] for k in ("status", "cleanup", "reason")} if row else None
        evidence["cut_to_cleanup_ms"] = int(confirmed_at - sent_at) if confirmed_at else None
        evidence["slot_released"] = slot_holder(store, asset) is None
        evidence["audit_actions"] = audit_actions(store, sid)

        status, again = manager.allocate(asset)
        evidence["reallocate_status"] = status
        if status == 200 and again.get("id"):
            manager.revoke(again["id"])
            spare, _ = wait_state(store, again["id"], "not_needed", timeout=5.0)
            evidence["spare_session"] = ({k: spare[k] for k in ("status", "cleanup", "reason")}
                                         if spare else None)
            evidence["spare_slot_released"] = slot_holder(store, asset) is None

        if args.screenshot:
            evidence["screenshot"] = True
        verdict = revoke_verdict(evidence)
        evidence.update(verdict)
        exit_code = 0 if verdict["verdict"] == "pass" else 1
    finally:
        if store is not None:
            store.close()
        if args.lose_manager and processes[0].is_alive():
            with contextlib.suppress(OSError):
                os.kill(processes[0].pid, signal.SIGCONT)
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
                      ("cut_kind", "verdict", "reasons", "errors", "cut_to_close_ms",
                       "cut_to_cleanup_ms", "slot_held_at_cut",
                       "slot_held_after_revoke_response", "slot_released", "session",
                       "audit_actions", "console")},
                     indent=2, ensure_ascii=False))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
