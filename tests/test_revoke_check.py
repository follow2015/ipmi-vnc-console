"""Contract tests for the revoke drill in tools/revoke_check.py."""
import json

import pytest

from tools.revoke_check import MAX_CLOSE_MS, MAX_CLEANUP_MS, parse_ready, revoke_verdict


def observation(**overrides):
    base = {
        "errors": [],
        "canvas_initial": {"non_black": 1627, "fingerprint": 2999},
        "state_after_input": "normal",
        "cut": {"ready_at": 1_700_000_000_000, "closed_at": 1_700_000_001_100,
                   "final_state": "disconnected", "timeout": False},
        "session": {"status": "closed", "reason": "revoked", "cleanup": "confirmed"},
        "cut_to_close_ms": 1100,
        "cut_to_cleanup_ms": 1800,
        "slot_released": True,
        "audit_actions": ["session_requested", "session_active", "session_revoked",
                          "session_finished"],
    }
    base.update(overrides)
    return base


def test_parse_ready_accepts_the_browser_handshake():
    payload = {"at": 1_700_000_000_000, "state": "normal",
               "canvas": {"non_black": 1627}, "client_bytes": 524}
    assert parse_ready("READY " + json.dumps(payload)) == payload


@pytest.mark.parametrize("line", [
    "",
    "READY",
    "READY {",
    "READY []",
    "READY null",
    "ready {\"state\": \"normal\"}",
    "RESULT {\"state\": \"normal\"}",
])
def test_parse_ready_ignores_anything_that_is_not_a_report(line):
    assert parse_ready(line) is None


def test_verdict_passes_when_the_console_is_cut_and_the_bmc_session_is_logged_out():
    verdict = revoke_verdict(observation())
    assert verdict == {"verdict": "pass", "reasons": []}


def test_verdict_fails_when_the_console_survives_the_revoke():
    evidence = observation(cut={"final_state": "normal", "timeout": True,
                                   "ready_at": 1, "closed_at": 2})
    verdict = revoke_verdict(evidence)
    assert verdict["verdict"] == "fail"
    assert "console_still_live" in verdict["reasons"]


def test_verdict_fails_when_a_worker_close_is_recorded_as_a_user_close():
    evidence = observation(session={"status": "closed", "reason": "client_closed",
                                    "cleanup": "confirmed"})
    verdict = revoke_verdict(evidence)
    assert "reason_not_revoked" in verdict["reasons"]


def test_verdict_fails_when_the_bmc_logout_was_not_confirmed():
    evidence = observation(session={"status": "closed", "reason": "revoked",
                                    "cleanup": "pending"})
    verdict = revoke_verdict(evidence)
    assert "cleanup_not_confirmed" in verdict["reasons"]


def test_verdict_fails_when_the_asset_slot_is_still_held():
    verdict = revoke_verdict(observation(slot_released=False))
    assert "slot_not_released" in verdict["reasons"]


def test_verdict_fails_when_the_revoke_is_not_audited():
    evidence = observation(audit_actions=["session_requested", "session_finished"])
    verdict = revoke_verdict(evidence)
    assert "revoke_not_audited" in verdict["reasons"]


def test_verdict_fails_when_the_cut_takes_longer_than_the_lease_bound():
    verdict = revoke_verdict(observation(cut_to_close_ms=MAX_CLOSE_MS + 1))
    assert "close_too_slow" in verdict["reasons"]


def test_verdict_tolerates_a_slow_but_bounded_cleanup_report():
    assert revoke_verdict(observation(cut_to_cleanup_ms=MAX_CLEANUP_MS + 1))["verdict"] == "fail"
    assert revoke_verdict(observation(cut_to_cleanup_ms=MAX_CLEANUP_MS - 1))["verdict"] == "pass"


def test_verdict_fails_without_a_picture_before_the_revoke():
    evidence = observation(canvas_initial={"non_black": 0}, state_after_input="normal")
    verdict = revoke_verdict(evidence)
    assert "no_picture" in verdict["reasons"]


def test_verdict_fails_when_the_console_never_reached_normal():
    verdict = revoke_verdict(observation(state_after_input="connecting"))
    assert "console_not_normal" in verdict["reasons"]


def test_verdict_reports_every_reason_at_once():
    evidence = observation(
        errors=["console_error"],
        session={"status": "active", "reason": None, "cleanup": "pending"},
        slot_released=False,
        cut={"final_state": None, "timeout": True, "ready_at": 1, "closed_at": 2},
        cut_to_close_ms=MAX_CLOSE_MS + 500,
        audit_actions=[],
    )
    reasons = revoke_verdict(evidence)["reasons"]
    assert {"browser_errors", "status_not_closed", "reason_not_revoked",
            "cleanup_not_confirmed", "slot_not_released", "revoke_not_audited",
            "console_still_live", "close_too_slow"} <= set(reasons)


def test_lease_fallback_passes_when_the_manager_could_not_be_reached():
    evidence = observation(
        cut_kind="manager_unreachable", expected_reason="lease_expired",
        session={"status": "lost", "reason": "lease_expired", "cleanup": "confirmed"},
        audit_actions=["session_requested", "session_active", "session_finished"],
    )
    assert revoke_verdict(evidence) == {"verdict": "pass", "reasons": []}


def test_lease_fallback_fails_when_the_outage_was_recorded_as_a_revoke():
    evidence = observation(
        cut_kind="manager_unreachable", expected_reason="lease_expired",
        session={"status": "closed", "reason": "revoked", "cleanup": "confirmed"},
        audit_actions=["session_requested", "session_active", "session_finished"],
    )
    assert "reason_not_lease_expired" in revoke_verdict(evidence)["reasons"]


def test_lease_fallback_fails_without_an_end_audit_event():
    evidence = observation(
        cut_kind="manager_unreachable", expected_reason="lease_expired",
        session={"status": "lost", "reason": "lease_expired", "cleanup": "confirmed"},
        audit_actions=["session_requested", "session_active"],
    )
    assert "end_not_audited" in revoke_verdict(evidence)["reasons"]


def test_lease_fallback_allows_a_cut_that_waits_for_the_lease():
    evidence = observation(
        cut_kind="manager_unreachable", expected_reason="lease_expired",
        session={"status": "lost", "reason": "lease_expired", "cleanup": "confirmed"},
        audit_actions=["session_requested", "session_active", "session_finished"],
        cut_to_close_ms=31_000, close_bound_ms=40_000,
        cut_to_cleanup_ms=32_500, cleanup_bound_ms=48_000,
    )
    assert revoke_verdict(evidence) == {"verdict": "pass", "reasons": []}


def test_lease_fallback_still_rejects_a_cut_past_its_own_bound():
    evidence = observation(
        cut_kind="manager_unreachable", expected_reason="lease_expired",
        session={"status": "lost", "reason": "lease_expired", "cleanup": "confirmed"},
        audit_actions=["session_requested", "session_active", "session_finished"],
        cut_to_close_ms=41_000, close_bound_ms=40_000,
        cut_to_cleanup_ms=42_000, cleanup_bound_ms=48_000,
    )
    assert "close_too_slow" in revoke_verdict(evidence)["reasons"]


def test_lease_fallback_still_rejects_a_cleanup_past_its_own_bound():
    evidence = observation(
        cut_kind="manager_unreachable", expected_reason="lease_expired",
        session={"status": "lost", "reason": "lease_expired", "cleanup": "confirmed"},
        audit_actions=["session_requested", "session_active", "session_finished"],
        cut_to_close_ms=31_000, close_bound_ms=40_000,
        cut_to_cleanup_ms=48_500, cleanup_bound_ms=48_000,
    )
    assert "cleanup_too_slow" in revoke_verdict(evidence)["reasons"]
