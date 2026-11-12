"""What counts as proof that the page explained a refused second tab."""
from __future__ import annotations

from tools.limit_hint_check import hint_verdict

LIMIT_TEXT = "此会话的控制台连接已达上限（1）。通常是同一会话开了多个标签页；关闭其它标签页后刷新本页。"


def observation(**overrides) -> dict:
    evidence = {
        "errors": [],
        "canvas_initial": {"non_black": 118_000, "fingerprint": 4040723622},
        "second_tab": {"status_text": LIMIT_TEXT, "state": None},
        "state_after_second_tab": "normal",
        "session": {"status": "active", "cleanup": "pending", "reason": None},
        "expected_limit": 1,
    }
    evidence.update(overrides)
    return evidence


def test_the_measured_refusal_passes():
    assert hint_verdict(observation()) == {"verdict": "pass", "reasons": []}


def test_a_second_tab_that_connected_is_not_a_refusal():
    evidence = observation(second_tab={"status_text": "", "state": "normal"})
    assert "second_tab_connected" in hint_verdict(evidence)["reasons"]


def test_the_vendor_word_failed_is_not_an_explanation():
    evidence = observation(second_tab={"status_text": "failed · Connection refused",
                                       "state": "failed"})
    assert "message_missing" in hint_verdict(evidence)["reasons"]


def test_a_message_naming_the_wrong_limit_fails():
    evidence = observation(second_tab={
        "status_text": "此会话的控制台连接已达上限（4）。", "state": "failed"})
    assert "message_wrong_limit" in hint_verdict(evidence)["reasons"]


def test_the_first_tab_must_survive_the_refusal():
    evidence = observation(state_after_second_tab="failed")
    assert "first_tab_disturbed" in hint_verdict(evidence)["reasons"]


def test_a_refusal_that_ends_the_session_is_a_regression():
    evidence = observation(session={"status": "closed", "cleanup": "pending", "reason": "revoked"})
    assert "session_not_active" in hint_verdict(evidence)["reasons"]


def test_an_unpainted_console_cannot_prove_a_limit():
    evidence = observation(canvas_initial={"non_black": 0})
    assert "no_picture_before_second_tab" in hint_verdict(evidence)["reasons"]


def test_verdict_names_every_failure_at_once():
    evidence = observation(
        errors=["console_error"],
        canvas_initial={"non_black": 0},
        second_tab={"status_text": "", "state": "normal"},
        state_after_second_tab="failed",
        session={"status": "closed"},
    )
    reasons = set(hint_verdict(evidence)["reasons"])
    assert {"browser_errors", "no_picture_before_second_tab", "second_tab_connected",
            "message_missing", "first_tab_disturbed", "session_not_active"} <= reasons


def test_a_refused_tab_must_not_build_a_console_client():
    evidence = observation(second_tab={"status_text": "connect", "state": "connect"})
    reasons = set(hint_verdict(evidence)["reasons"])
    assert "second_tab_attempted_connect" in reasons and "message_missing" in reasons


def test_a_tab_without_a_client_still_passes():
    evidence = observation(second_tab={"status_text": LIMIT_TEXT, "state": None})
    assert hint_verdict(evidence) == {"verdict": "pass", "reasons": []}
