"""Silent-upstream drill: a BMC that stops answering must not look like a user leaving."""
from __future__ import annotations

import argparse
import json
import multiprocessing
import os
import select
import shutil
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from kvmhub.run import manager_process, worker_process  # noqa: E402
from kvmhub.store import Store  # noqa: E402
from tools.browser_e2e import _find_chromium, _find_playwright  # noqa: E402
from tools.passthrough_check import prepare, wait_port  # noqa: E402
from tools.revoke_check import Manager, finish_browser, run_browser  # noqa: E402

MIN_SILENT_MS = 15_000

MAX_SILENT_MS = 45_000

CUT_TIMEOUT_MS = 60_000


class Relay:

    def __init__(self, upstream_host: str, upstream_port: int, listen_host: str = "127.0.0.1"):
        self.upstream = (upstream_host, upstream_port)
        self.listen_host = listen_host
        self._frozen = threading.Event()
        self._stopped = threading.Event()
        self._pairs: list[tuple[socket.socket, socket.socket]] = []
        self._lock = threading.Lock()
        self._listener: socket.socket | None = None
        self._threads: list[threading.Thread] = []
        self._parked: set[int] = set()
        self._pumps = 0
        self._cond = threading.Condition()

    @property
    def port(self) -> int:
        assert self._listener is not None, "start() first"
        return self._listener.getsockname()[1]

    @property
    def connections(self) -> int:
        with self._lock:
            return len(self._pairs)

    def start(self) -> "Relay":
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((self.listen_host, 0))
        listener.listen(16)
        listener.settimeout(0.2)
        self._listener = listener
        thread = threading.Thread(target=self._accept_loop, daemon=True)
        thread.start()
        self._threads.append(thread)
        return self

    def freeze(self) -> None:
        self._frozen.set()
        with self._cond:
            self._cond.wait_for(lambda: len(self._parked) >= self._pumps, timeout=1.0)

    def unfreeze(self) -> None:
        self._frozen.clear()

    def stop(self) -> None:
        self._stopped.set()
        self._frozen.clear()
        if self._listener is not None:
            self._listener.close()
        with self._lock:
            pairs = list(self._pairs)
        for near, _far in pairs:
            _shutdown(near)

    def _accept_loop(self) -> None:
        while not self._stopped.is_set():
            try:
                client, _ = self._listener.accept()
            except (TimeoutError, OSError):
                continue
            try:
                far = socket.create_connection(self.upstream, timeout=5)
            except OSError:
                client.close()
                continue
            for sock in (client, far):
                sock.settimeout(0.2)
            with self._lock:
                self._pairs.append((client, far))
            for source, target in ((client, far), (far, client)):
                thread = threading.Thread(target=self._pump, args=(source, target), daemon=True)
                thread.start()
                self._threads.append(thread)

    def _pump(self, source: socket.socket, target: socket.socket) -> None:
        me = threading.get_ident()
        with self._cond:
            self._pumps += 1
        try:
            while not self._stopped.is_set():
                if self._frozen.is_set():
                    self._park(me)
                    continue
                try:
                    readable, _, _ = select.select([source], [], [], 0.05)
                except (OSError, ValueError):
                    break
                if not readable or self._frozen.is_set():
                    continue
                try:
                    data = source.recv(65536)
                except (TimeoutError, BlockingIOError):
                    continue
                except OSError:
                    break
                if not data:
                    break
                if self._frozen.is_set():
                    self._park(me)
                    while self._frozen.is_set() and not self._stopped.is_set():
                        self._frozen.wait(0.05)
                try:
                    target.sendall(data)
                except OSError:
                    break
        finally:
            with self._cond:
                self._pumps -= 1
                self._parked.discard(me)
                self._cond.notify_all()
            _shutdown(source)
            _shutdown(target)

    def _park(self, me: int) -> None:
        with self._cond:
            self._parked.add(me)
            self._cond.notify_all()
        while self._frozen.is_set() and not self._stopped.is_set():
            self._frozen.wait(0.05)
        with self._cond:
            self._parked.discard(me)

    def forget_closed(self) -> int:
        with self._lock:
            alive = [(near, far) for near, far in self._pairs if _is_open(near)]
            dropped = len(self._pairs) - len(alive)
            self._pairs = alive
            return dropped


def _shutdown(sock: socket.socket) -> None:
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    try:
        sock.close()
    except OSError:
        pass


def _is_open(sock: socket.socket) -> bool:
    return sock.fileno() != -1


def silent_verdict(evidence: dict) -> dict:
    reasons: list[str] = []
    if evidence.get("errors"):
        reasons.append("browser_errors")
    if (evidence.get("canvas_initial") or {}).get("non_black", 0) <= 0:
        reasons.append("no_picture")
    if evidence.get("state_after_input") != "normal":
        reasons.append("console_not_normal_before_silence")
    cut = evidence.get("cut") or {}
    if cut.get("timeout") or cut.get("final_state") in (None, "normal"):
        reasons.append("console_still_live")
    session = evidence.get("session") or {}
    if session.get("status") not in ("closed", "failed", "lost"):
        reasons.append("status_not_terminal")
    if session.get("reason") != "upstream_unresponsive":
        reasons.append("reason_not_upstream_unresponsive")
    if session.get("cleanup") != "pending":
        reasons.append("cleanup_not_pending")
    if not evidence.get("slot_held_after_session_end"):
        reasons.append("slot_released_early")
    blocked = evidence.get("blocked_while_pending") or {}
    if blocked.get("status") != 409 or blocked.get("code") != "asset_busy":
        reasons.append("asset_not_blocked")
    elapsed = evidence.get("silent_to_console_close_ms")
    if elapsed is None:
        reasons.append("browser_never_noticed")
    elif elapsed < MIN_SILENT_MS:
        reasons.append("silent_too_quick")
    elif elapsed > MAX_SILENT_MS:
        reasons.append("silent_too_slow")
    if evidence.get("release_status") != 200:
        reasons.append("release_rejected")
    if not evidence.get("slot_released_after_release"):
        reasons.append("slot_not_released_after_release")
    if evidence.get("reallocate_status") != 200:
        reasons.append("reallocate_rejected")
    if evidence.get("cleanup_after_release") != "confirmed":
        reasons.append("cleanup_downgraded")
    actions = evidence.get("audit_actions") or []
    if "session_finished" not in actions:
        reasons.append("end_not_audited")
    if "manual_slot_release" not in actions:
        reasons.append("release_not_audited")
    return {"verdict": "pass" if not reasons else "fail", "reasons": reasons}


def slot_holder(store: Store, asset: str) -> str | None:
    row = store.db.execute("SELECT session_id FROM asset_slot WHERE asset_id=?", (asset,)).fetchone()
    return row["session_id"] if row else None


def audit_actions(store: Store, sid: str) -> list[str]:
    return [r[0] for r in store.db.execute(
        "SELECT action FROM audit WHERE session_id=? ORDER BY id", (sid,))]


def wait_for(predicate, timeout: float, interval: float = 0.05):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value, time.monotonic() * 1000
        time.sleep(interval)
    return None, None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--host", required=True, help="the real BMC; the relay forwards to it")
    parser.add_argument("--cert-sha256", required=True)
    parser.add_argument("--directory", default=".local-silent")
    parser.add_argument("--protocol-versions", default="",
                        help="comma-separated RFB greetings approved for this device")
    parser.add_argument("--out")
    parser.add_argument("--screenshot", help="local PNG path; never committed")
    parser.add_argument("--close-timeout", type=float, default=90.0,
                        help="how long to wait for the session to end after the freeze")
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

    relay = Relay(args.host, 443).start()
    root, key, target = prepare(directory, f"127.0.0.1:{relay.port}", fingerprint,
                               username, password, versions)
    token = (root / "login-token").read_text().strip()
    asset = "real-1"

    ctx = multiprocessing.get_context("spawn")
    processes = [ctx.Process(target=manager_process, args=(str(root / "manager.json"),), name="manager"),
                 ctx.Process(target=worker_process, args=(str(root / "worker.json"),), name="worker")]
    evidence = {"target_host": args.host, "asset": asset, "via_relay": True,
                "relay_port": relay.port, "adapter": "supermicro-x10-passthrough",
                "approved_protocol_versions": list(versions), "errors": []}
    exit_code = 1
    store = None
    browser = None
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
            args.node, module, chromium, UI_ORIGIN, token, asset, CUT_TIMEOUT_MS,
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
        if not active:
            evidence["errors"].append("no_active_session")
            evidence["verdict"] = "fail"
            return 1
        sid = active["id"]
        evidence["session_id_matches"] = handshake.get("sid") == sid
        evidence["console"] = {"state": handshake.get("state"), "canvas": handshake.get("canvas"),
                               "client_bytes": handshake.get("client_bytes")}
        evidence["slot_held_before_silence"] = slot_holder(store, asset) == sid
        evidence["relay_connections_before_silence"] = relay.connections

        relay.freeze()
        frozen_at = time.monotonic() * 1000
        frozen_at_wall = time.time() * 1000

        def ended():
            row = store.get(sid)
            return row if row["status"] in ("closed", "failed", "lost") else None

        row, ended_at = wait_for(ended, args.close_timeout)
        evidence["silent_to_manager_record_ms"] = int(ended_at - frozen_at) if ended_at else None
        evidence["session"] = ({k: row[k] for k in ("status", "cleanup", "reason")} if row else None)
        evidence["slot_held_after_session_end"] = slot_holder(store, asset) == sid
        evidence["relay_connections_at_session_end"] = relay.connections

        status, body = manager.allocate(asset)
        evidence["blocked_while_pending"] = {"status": status, "code": body.get("error")}

        result, code = finish_browser(browser, lines, stderr_lines)
        evidence["browser_exit"] = code
        if stderr_lines:
            evidence["browser_stderr_tail"] = "".join(stderr_lines)[-400:]
        evidence["browser"] = {k: result.get(k) for k in
                               ("steps", "errors", "console_errors", "http_404", "cut",
                                "canvas_after_cut", "canvas_after_cut_settled")}
        evidence.update({"canvas_initial": result.get("canvas_initial"),
                         "state_after_input": result.get("state_after_input"),
                         "cut": result.get("cut")})
        evidence["canvas_after_cut"] = result.get("canvas_after_cut")
        cut = result.get("cut") or {}
        if cut.get("closed_at"):
            evidence["silent_to_console_close_ms"] = int(cut["closed_at"] - frozen_at_wall)

        relay.unfreeze()
        status, body = manager.release(sid)
        evidence["release_status"] = status
        evidence["release_body"] = body
        released, _ = wait_for(lambda: slot_holder(store, asset) is None, 15.0)
        evidence["slot_released_after_release"] = bool(released)
        time.sleep(3.0)
        evidence["cleanup_after_release"] = store.get(sid)["cleanup"]
        evidence["audit_actions"] = audit_actions(store, sid)

        status, again = manager.allocate(asset)
        evidence["reallocate_status"] = status
        if status == 200 and again.get("id"):
            manager.revoke(again["id"])
            evidence["spare_session"] = {"id": again["id"]}
            freed, _ = wait_for(lambda: slot_holder(store, asset) is None, 10.0)
            evidence["spare_slot_released"] = bool(freed)

        verdict = silent_verdict(evidence)
        evidence.update(verdict)
        exit_code = 0 if verdict["verdict"] == "pass" else 1
    finally:
        if store is not None:
            store.close()
        if browser is not None and browser.poll() is None:
            browser.kill()
        relay.stop()
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
                      ("verdict", "reasons", "errors", "silent_to_console_close_ms",
                       "silent_to_manager_record_ms", "session",
                       "blocked_while_pending", "slot_held_after_session_end",
                       "slot_released_after_release", "reallocate_status",
                       "cleanup_after_release", "audit_actions", "cut", "console")},
                     indent=2, ensure_ascii=False))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
