"""The silent-upstream drill: what counts as proof, and that the relay lies still."""
from __future__ import annotations

import socket
import threading
import time

from tools.silent_upstream_check import (MAX_SILENT_MS, MIN_SILENT_MS, Relay,
                                         silent_verdict)


def observation(**overrides) -> dict:
    evidence = {
        "errors": [],
        "canvas_initial": {"non_black": 118_000, "fingerprint": 3633},
        "state_after_input": "normal",
        "session": {"status": "closed", "cleanup": "pending", "reason": "upstream_unresponsive"},
        "slot_held_after_session_end": True,
        "blocked_while_pending": {"status": 409, "code": "asset_busy"},
        "silent_to_console_close_ms": 30_600,
        "silent_to_manager_record_ms": 36_100,
        "cut": {"final_state": "failed", "timeout": False, "requests_after_ready": 0},
        "release_status": 200,
        "slot_released_after_release": True,
        "reallocate_status": 200,
        "cleanup_after_release": "confirmed",
        "audit_actions": ["session_requested", "session_active", "session_finished",
                          "manual_slot_release"],
    }
    evidence.update(overrides)
    return evidence


def test_full_run_passes_with_no_reasons():
    assert silent_verdict(observation()) == {"verdict": "pass", "reasons": [],
                                             "reason": "upstream_unresponsive"}


def test_a_spent_rebuild_also_counts_as_an_upstream_ending():
    verdict = silent_verdict(observation(session={"status": "closed", "cleanup": "pending",
                                                  "reason": "upstream_reconnect_failed"}))
    assert verdict["verdict"] == "pass"
    assert verdict["reason"] == "upstream_reconnect_failed"


def test_console_that_stayed_normal_is_not_a_cut():
    evidence = observation(cut={"final_state": "normal", "timeout": True})
    assert "console_still_live" in silent_verdict(evidence)["reasons"]


def test_a_clean_upstream_close_is_not_a_silent_one():
    evidence = observation(session={"status": "closed", "cleanup": "pending",
                                    "reason": "upstream_error"})
    assert "reason_not_upstream_side" in silent_verdict(evidence)["reasons"]


def test_slot_freed_without_a_confirmed_logout_is_a_failure():
    evidence = observation(slot_held_after_session_end=False)
    assert "slot_released_early" in silent_verdict(evidence)["reasons"]


def test_pending_asset_must_refuse_new_work():
    evidence = observation(blocked_while_pending={"status": 200})
    assert "asset_not_blocked" in silent_verdict(evidence)["reasons"]


def test_detection_before_the_heartbeat_cannot_be_the_heartbeat():
    evidence = observation(silent_to_console_close_ms=MIN_SILENT_MS - 1)
    assert "silent_too_quick" in silent_verdict(evidence)["reasons"]


def test_slow_logout_does_not_get_reported_as_slow_detection():
    evidence = observation(silent_to_console_close_ms=30_600,
                           silent_to_manager_record_ms=MAX_SILENT_MS + 5_000)
    assert silent_verdict(evidence) == {"verdict": "pass", "reasons": [],
                                        "reason": "upstream_unresponsive"}


def test_a_run_where_the_browser_never_noticed_fails():
    evidence = observation(silent_to_console_close_ms=None)
    assert "browser_never_noticed" in silent_verdict(evidence)["reasons"]


def test_detection_past_the_bound_is_still_a_failure():
    evidence = observation(silent_to_console_close_ms=MAX_SILENT_MS + 1)
    assert "silent_too_slow" in silent_verdict(evidence)["reasons"]


def test_release_that_leaves_the_slot_held_is_not_a_release():
    evidence = observation(slot_released_after_release=False)
    assert "slot_not_released_after_release" in silent_verdict(evidence)["reasons"]


def test_slot_must_be_reusable_after_a_manual_release():
    evidence = observation(reallocate_status=409)
    assert "reallocate_rejected" in silent_verdict(evidence)["reasons"]


def test_late_pending_report_must_not_downgrade_a_confirmed_cleanup():
    evidence = observation(cleanup_after_release="pending")
    assert "cleanup_downgraded" in silent_verdict(evidence)["reasons"]


def test_release_and_end_must_both_be_audited():
    evidence = observation(audit_actions=["session_requested", "manual_slot_release"])
    reasons = silent_verdict(evidence)["reasons"]
    assert "end_not_audited" in reasons
    evidence = observation(audit_actions=["session_requested", "session_finished"])
    assert "release_not_audited" in silent_verdict(evidence)["reasons"]


def test_verdict_names_every_failure_at_once():
    evidence = observation(
        errors=["console_error"],
        session={"status": "active", "cleanup": "confirmed", "reason": "revoked"},
        slot_held_after_session_end=False,
        blocked_while_pending={"status": 200},
        release_status=409,
        silent_to_console_close_ms=MAX_SILENT_MS + 5_000,
        audit_actions=[],
    )
    reasons = set(silent_verdict(evidence)["reasons"])
    assert {"browser_errors", "status_not_terminal", "reason_not_upstream_side",
            "cleanup_not_pending", "slot_released_early", "asset_not_blocked",
            "silent_too_slow", "end_not_audited", "release_not_audited"} <= reasons



def _echo_server() -> tuple[socket.socket, int, threading.Event]:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(4)
    stop = threading.Event()

    def serve():
        try:
            conn, _ = listener.accept()
        except OSError:
            return
        try:
            while not stop.is_set():
                data = conn.recv(4096)
                if not data:
                    break
                conn.sendall(data)
        except OSError:
            pass
        finally:
            conn.close()

    threading.Thread(target=serve, daemon=True).start()
    return listener, listener.getsockname()[1], stop


def _relay_to(echo_port: int) -> Relay:
    relay = Relay("127.0.0.1", echo_port)
    relay.start()
    return relay


def test_relay_forwards_while_running():
    listener, port, stop = _echo_server()
    relay = _relay_to(port)
    client = socket.create_connection(("127.0.0.1", relay.port), timeout=5)
    try:
        client.sendall(b"ping")
        assert client.recv(16) == b"ping"
    finally:
        client.close()
        relay.stop()
        stop.set()
        listener.close()


def test_frozen_relay_keeps_the_socket_open_and_delivers_nothing():
    listener, port, stop = _echo_server()
    relay = _relay_to(port)
    client = socket.create_connection(("127.0.0.1", relay.port), timeout=5)
    try:
        client.sendall(b"a")
        assert client.recv(16) == b"a"
        relay.freeze()
        client.sendall(b"b")
        client.settimeout(0.5)
        try:
            got = client.recv(16)
            raise AssertionError(f"frozen relay delivered {got!r}")
        except TimeoutError:
            pass
        assert relay.connections == 1
        relay.unfreeze()
        client.settimeout(5)
        assert client.recv(16) == b"b"
    finally:
        client.close()
        relay.stop()
        stop.set()
        listener.close()


def test_stopping_the_relay_closes_the_client_side():
    listener, port, stop = _echo_server()
    relay = _relay_to(port)
    client = socket.create_connection(("127.0.0.1", relay.port), timeout=5)
    try:
        client.sendall(b"x")
        assert client.recv(16) == b"x"
        relay.stop()
        client.settimeout(3)
        assert client.recv(16) == b""
    finally:
        client.close()
        stop.set()
        listener.close()


def test_relay_connects_only_after_a_client_arrives():
    listener, port, stop = _echo_server()
    relay = _relay_to(port)
    try:
        time.sleep(0.1)
        assert relay.connections == 0
    finally:
        relay.stop()
        stop.set()
        listener.close()
