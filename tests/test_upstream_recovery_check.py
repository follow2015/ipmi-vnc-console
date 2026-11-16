"""The recovery drill's verdict must fail for every way a run can lie."""
from __future__ import annotations

import copy
import socket

import pytest

from tools.upstream_recovery_check import (CutRelay, held_key_verdict, idle_churn,
                                           multi_cut_verdict, output_is_clean,
                                           recovery_evidence_verdict,
                                           refused_logout_verdict,
                                           refused_rebuild_verdict)

AUDIT = {
    "recoveries": 1,
    "recovery_attempts": 1,
    "recovery_latency_ms": 742,
    "client_bytes": 512,
    "server_bytes": 9000,
    "upstream_close_code": 1006,
}


def passing() -> dict:
    return {
        "errors": [],
        "handshake": {"state": "normal", "canvas": {"non_black": 1627}, "sid_matches": True},
        "cut": {"sockets_reset": 1, "at_ms": 1},
        "new_upstream_connections": 2,
        "recovery": {"state_never_failed": True, "requests_after_ready": 0,
                     "max_recoveries": 1, "sample_count": 40,
                     "server_bytes_first": 1000, "server_bytes_last": 9000,
                     "saw_recovering": True},
        "session_after_cut": {"status": "active", "cleanup": None, "reason": None},
        "session": {"status": "closed", "cleanup": "confirmed", "reason": "client_closed"},
        "audit_actions": ["session_created", "session_finished"],
        "audit_evidence": dict(AUDIT),
        "session_end_evidence": dict(AUDIT),
        "sentinel_leaked": False,
        "output_is_clean": True,
    }


def test_a_complete_run_passes():
    verdict = recovery_evidence_verdict(passing())
    assert verdict == {"verdict": "pass", "reasons": [], "end_reason": "client_closed"}


@pytest.mark.parametrize("path,value,expected", [
    (("errors",), ["browser_died"], "browser_errors"),
    (("handshake", "state"), "failed", "console_not_normal_before_cut"),
    (("handshake", "canvas", "non_black"), 0, "no_picture_before_cut"),
    (("cut", "sockets_reset"), 0, "upstream_link_not_reset"),
    (("new_upstream_connections",), 0, "no_rebuilt_socket"),
    (("recovery", "state_never_failed"), False, "browser_noticed_the_cut"),
    (("recovery", "requests_after_ready"), 3, "browser_reconnected"),
    (("recovery", "max_recoveries"), 0, "gateway_never_recovered"),
    (("recovery", "sample_count"), 1, "no_sampling_window"),
    (("recovery", "server_bytes_last"), 1000, "no_new_frames_after_recovery"),
    (("session_after_cut", "status"), "closed", "session_ended_on_upstream_loss"),
    (("session", "status"), "active", "session_not_ended"),
    (("session", "cleanup"), "pending", "cleanup_not_confirmed"),
    (("audit_actions",), [], "end_not_audited"),
    (("session_end_evidence",), None, "audit_row_disagrees"),
    (("sentinel_leaked",), True, "credential_in_audit"),
    (("output_is_clean",), False, "credential_in_output"),
])
def test_deleting_one_observation_fails_the_run(path, value, expected):
    evidence = passing()
    node = evidence
    for key in path[:-1]:
        node = node[key]
    node[path[-1]] = value
    verdict = recovery_evidence_verdict(evidence)
    assert verdict["verdict"] == "fail"
    assert expected in verdict["reasons"]


@pytest.mark.parametrize("extra,expected", [
    ({"peak_rate": 12}, "evidence_field_out_of_whitelist"),
    ({"sid": "a" * 32}, "forbidden_evidence_field"),
    ({"client_message_summary": "4:7"}, "forbidden_evidence_field"),
    ({"ticket": "one-time"}, "forbidden_evidence_field"),
])
def test_an_audit_row_cannot_carry_payload_or_unapproved_fields(extra, expected):
    evidence = passing()
    evidence["audit_evidence"] = dict(AUDIT, **extra)
    evidence["session_end_evidence"] = dict(evidence["audit_evidence"])
    verdict = recovery_evidence_verdict(evidence)
    assert expected in verdict["reasons"]


def test_the_audit_row_must_record_the_recovery():
    evidence = passing()
    evidence["audit_evidence"] = {k: v for k, v in AUDIT.items() if k != "recoveries"}
    evidence["session_end_evidence"] = dict(evidence["audit_evidence"])
    reasons = recovery_evidence_verdict(evidence)["reasons"]
    assert "recovery_not_in_audit" in reasons


@pytest.mark.parametrize("value", ["742", True, 1.5, None])
def test_a_counter_must_be_a_bounded_integer(value):
    evidence = passing()
    evidence["audit_evidence"] = dict(AUDIT, recovery_latency_ms=value)
    evidence["session_end_evidence"] = dict(evidence["audit_evidence"])
    assert "non_integer_counter" in recovery_evidence_verdict(evidence)["reasons"]


def test_the_two_durable_copies_must_agree():
    evidence = passing()
    evidence["session_end_evidence"] = copy.deepcopy(AUDIT)
    evidence["session_end_evidence"]["recoveries"] = 2
    assert "audit_row_disagrees" in recovery_evidence_verdict(evidence)["reasons"]


def test_a_missing_server_view_is_a_failure_not_a_silent_pass():
    evidence = passing()
    evidence["recovery"]["server_bytes_first"] = None
    evidence["recovery"]["server_bytes_last"] = None
    assert "no_server_view" in recovery_evidence_verdict(evidence)["reasons"]


def test_output_is_clean_rejects_credentials_but_ignores_empty_markers():
    assert output_is_clean({"detail": "clean"}, ["", None, ""]) is True
    assert output_is_clean({"detail": "credential=Zx9Qv"}, ["Zx9Qv"]) is False
    assert output_is_clean({"detail": "credential=Zx9Qv"}, [""]) is True


def test_cut_resets_every_pair_and_leaves_room_for_the_rebuilt_socket():
    relay = CutRelay("127.0.0.1", 1)
    first, first_far = socket.socketpair()
    second, second_far = socket.socketpair()
    fresh = fresh_far = None
    relay._pairs = {0: (first, first_far), 1: (second, second_far)}
    try:
        assert relay.cut() == 2
        assert (relay.cut_count, relay.last_cut_pairs) == (1, 2)
        assert relay.connections == 0
        assert all(sock.fileno() == -1 for sock in (first, first_far, second, second_far))
        fresh, fresh_far = socket.socketpair()
        relay._pairs[2] = (fresh, fresh_far)
        assert relay.connections == 1
    finally:
        for sock in (first, first_far, second, second_far, fresh, fresh_far):
            if sock is None:
                continue
            try:
                sock.close()
            except OSError:
                pass


def test_cut_on_an_empty_relay_is_not_a_success():
    relay = CutRelay("127.0.0.1", 1)
    assert relay.cut() == 0
    assert relay.last_cut_pairs == 0



def multi_passing() -> dict:
    evidence = passing()
    evidence.pop("cut")
    evidence["cuts_requested"] = 4
    evidence["policy_max_total"] = 3
    evidence["ended_at_cut"] = 4
    evidence["cuts"] = [
        {"index": 1, "sockets_reset": 1, "recovery_ms": 690, "new_connections": 1,
         "session_status": "active", "session_reason": None},
        {"index": 2, "sockets_reset": 1, "recovery_ms": 705, "new_connections": 1,
         "session_status": "active", "session_reason": None},
        {"index": 3, "sockets_reset": 1, "recovery_ms": 712, "new_connections": 1,
         "session_status": "active", "session_reason": None},
        {"index": 4, "sockets_reset": 1, "recovery_ms": None, "new_connections": 0,
         "session_status": "closed", "session_reason": "upstream_reconnect_failed"},
    ]
    evidence["session"] = {"status": "closed", "cleanup": "confirmed",
                           "reason": "upstream_reconnect_failed"}
    evidence["audit_evidence"] = dict(AUDIT, recoveries=3, recovery_attempts=3)
    evidence["session_end_evidence"] = dict(evidence["audit_evidence"])
    return evidence


def test_a_run_that_reaches_the_ceiling_passes():
    verdict = multi_cut_verdict(multi_passing())
    assert verdict == {"verdict": "pass", "reasons": [],
                       "end_reason": "upstream_reconnect_failed"}


def test_a_run_under_the_ceiling_passes_when_every_loss_was_rebuilt():
    evidence = multi_passing()
    evidence["cuts_requested"] = 2
    evidence["ended_at_cut"] = None
    evidence["cuts"] = evidence["cuts"][:2]
    evidence["session"] = {"status": "closed", "cleanup": "confirmed",
                           "reason": "client_closed"}
    evidence["audit_evidence"] = dict(AUDIT, recoveries=2, recovery_attempts=2)
    evidence["session_end_evidence"] = dict(evidence["audit_evidence"])
    assert multi_cut_verdict(evidence)["verdict"] == "pass"


@pytest.mark.parametrize("mutate,expected", [
    (lambda e: (e["cuts"][3].update(recovery_ms=700, session_status="active"),
                e.update(ended_at_cut=3)), "session_died_before_cap"),
    (lambda e: (e["cuts"][3].update(recovery_ms=700, session_status="active",
                                    session_reason=None),
                e.update(ended_at_cut=None),
                e["session"].update(reason="client_closed"),
                e["audit_evidence"].update(recoveries=4),
                e["session_end_evidence"].update(recoveries=4)), "cap_not_enforced"),
    (lambda e: e["cuts"][1].update(sockets_reset=0), "upstream_link_not_reset"),
    (lambda e: e["cuts"][1].update(recovery_ms=None), "no_rebuilt_socket_at_cut_2"),
    (lambda e: (e["audit_evidence"].update(recoveries=2),
                e["session_end_evidence"].update(recoveries=2)),
     "recovery_count_disagrees"),
    (lambda e: (e["session"].update(reason="upstream_unresponsive"),
                e["audit_evidence"].update(recoveries=3)), "wrong_end_reason_for_cap"),
    (lambda e: (e.update(cuts=e["cuts"][:2], cuts_requested=3, ended_at_cut=None),
                e["session"].update(reason="client_closed"),
                e["audit_evidence"].update(recoveries=2),
                e["session_end_evidence"].update(recoveries=2)),
     "fewer_cuts_than_requested"),
    (lambda e: e.update(cuts=[], cuts_requested=4), "no_cut_observed"),
    (lambda e: e["recovery"].update(server_bytes_last=1000), "no_new_frames_after_recovery"),
    (lambda e: e["session"].update(cleanup="pending"), "cleanup_not_confirmed"),
    (lambda e: e.update(audit_actions=[]), "end_not_audited"),
    (lambda e: e.update(sentinel_leaked=True), "credential_in_audit"),
])
def test_a_multi_cut_run_fails_for_every_way_it_can_lie(mutate, expected):
    evidence = multi_passing()
    mutate(evidence)
    verdict = multi_cut_verdict(evidence)
    assert verdict["verdict"] == "fail"
    assert expected in verdict["reasons"]


def test_a_multi_cut_run_needs_a_known_ceiling():
    evidence = multi_passing()
    evidence.pop("policy_max_total")
    assert "no_policy_ceiling" in multi_cut_verdict(evidence)["reasons"]




def refused(**overrides) -> dict:
    evidence = {
        "handshake": {"state": "normal", "canvas": {"non_black": 2576}},
        "listener_closed": True,
        "cuts": [{"index": 1, "sockets_reset": 1, "recovery_ms": None,
                  "frames_bytes": 0, "session_reason": None}],
        "session": {"status": "closed", "cleanup": "confirmed",
                    "reason": "upstream_reconnect_failed"},
        "audit_actions": ["session_requested", "session_finished"],
        "recovery": {"recoveries": 0, "state_never_failed": False},
        "audit_evidence": {"recoveries": 0, "recovery_attempts": 2,
                           "recovery_last_error": "upstream_unavailable"},
        "session_end_evidence": {"recoveries": 0, "recovery_attempts": 2,
                                 "recovery_last_error": "upstream_unavailable"},
        "output_is_clean": True,
    }
    evidence.update(overrides)
    return evidence


def test_a_refused_rebuild_that_ends_cleanly_passes():
    assert refused_rebuild_verdict(refused()) == {
        "verdict": "pass", "reasons": [], "end_reason": "upstream_reconnect_failed"}


def test_a_rebuild_after_the_listener_closed_is_not_a_refusal():
    evidence = refused()
    evidence["cuts"][0]["recovery_ms"] = 900
    assert "console_rebuilt_after_refusal" in refused_rebuild_verdict(evidence)["reasons"]


def test_giving_up_without_one_attempt_is_a_different_failure():
    evidence = refused()
    evidence["audit_evidence"] = {"recoveries": 0, "recovery_attempts": 0}
    evidence["session_end_evidence"] = dict(evidence["audit_evidence"])
    assert "no_rebuild_attempt_recorded" in refused_rebuild_verdict(evidence)["reasons"]


def test_blaming_the_network_for_a_failed_rebuild_fails_the_drill():
    evidence = refused(session={"status": "closed", "cleanup": "confirmed",
                                "reason": "upstream_error"})
    assert "wrong_end_reason_for_failed_rebuild" in refused_rebuild_verdict(evidence)["reasons"]


def test_successful_accept_but_no_frames_is_not_a_rebuild():
    evidence = refused()
    evidence["recovery"] = {"recoveries": 1}
    assert "rebuild_succeeded_after_refusal" in refused_rebuild_verdict(evidence)["reasons"]



READY = 1_000_000
BASELINE_STEP = 250


def _timeline(start: int, span: int, sig: int) -> list[list[int]]:
    return [[start + i * BASELINE_STEP, sig] for i in range(span // BASELINE_STEP + 1)]


def held(**overrides) -> dict:
    evidence = passing()
    down_at = READY + 5000
    cut_at = down_at + 200
    up_at = down_at + 4000
    after_start = READY + 10_200
    samples = _timeline(READY, 5000, 3) + _timeline(after_start, 5000, 7)
    evidence["recovery"] = dict(evidence["recovery"], ready_at=READY,
                                hold={"key": "Shift", "down_at": down_at, "up_at": up_at,
                                      "held_ms": up_at - down_at, "idle_window_ms": 5000},
                                samples_sig=samples,
                                input_counters={"replayed": 0, "dropped": 0})
    evidence["cuts"] = [{"index": 1, "sockets_reset": 1, "cut_at_ms": cut_at,
                         "recovery_ms": 900, "observed_recoveries": 1,
                         "session_status": "active", "session_reason": None}]
    evidence.update(overrides)
    return evidence


def test_a_key_held_across_the_cut_and_released_after_the_rebuild_passes():
    assert held_key_verdict(held())["verdict"] == "pass"
    assert held_key_verdict(held())["reasons"] == []


def test_a_release_that_landed_inside_the_rebuild_must_be_replayed():
    evidence = held()
    evidence["recovery"]["hold"]["up_at"] = 1_005_800
    evidence["recovery"]["hold"]["held_ms"] = 600
    assert "release_during_rebuild_was_not_replayed" in held_key_verdict(evidence)["reasons"]
    evidence["recovery"]["input_counters"]["replayed"] = 1
    assert held_key_verdict(evidence)["verdict"] == "pass"


def test_a_dropped_release_fails_even_when_the_run_is_otherwise_clean():
    evidence = held()
    evidence["recovery"]["hold"]["up_at"] = 1_005_800
    evidence["recovery"]["input_counters"] = {"replayed": 1, "dropped": 1}
    assert "input_dropped_during_rebuild" in held_key_verdict(evidence)["reasons"]


@pytest.mark.parametrize("path,value,expected", [
    (("down_at",), None, "key_never_pressed"),
    (("up_at",), None, "key_never_released"),
    (("down_at",), 1_005_500, "key_pressed_after_the_cut"),
])
def test_a_hold_that_never_happened_is_named(path, value, expected):
    evidence = held()
    node = evidence["recovery"]["hold"]
    for key in path[:-1]:
        node = node[key]
    node[path[-1]] = value
    assert expected in held_key_verdict(evidence)["reasons"]


def test_a_release_before_the_cut_did_not_ask_the_question():
    evidence = held()
    evidence["recovery"]["hold"]["up_at"] = 1_005_100
    assert "key_released_before_the_cut" in held_key_verdict(evidence)["reasons"]


def test_a_screen_that_keeps_drawing_after_the_release_fails():
    evidence = held()
    busy = [[at, 100 + (i % 2)] for i, (at, _) in
            enumerate(evidence["recovery"]["samples_sig"]) if at >= READY + 10_200]
    evidence["recovery"]["samples_sig"] = _timeline(READY, 5000, 3) + busy
    assert "screen_changed_after_release" in held_key_verdict(evidence)["reasons"]


def test_an_idle_screen_that_was_already_busy_is_recorded_as_undiscriminating():
    evidence = held()
    noisy = [[at, 100 + (i % 2)] for i, (at, _) in
             enumerate(evidence["recovery"]["samples_sig"])]
    evidence["recovery"]["samples_sig"] = noisy
    verdict = held_key_verdict(evidence)
    assert verdict["verdict"] == "pass"
    assert evidence["stuck_watch"]["discriminating"] is False


def test_a_saturated_tail_is_caught_even_against_a_busy_baseline():
    evidence = held()
    busy = [[at, 100 + (i % 2)] for i, (at, _) in
            enumerate(evidence["recovery"]["samples_sig"]) if at >= READY + 10_200]
    baseline = [[at, 1 if (i // 2) % 2 == 0 else 2] for i, (at, _) in
                enumerate(_timeline(READY, 5000, 3))]
    evidence["recovery"]["samples_sig"] = baseline + busy
    verdict = held_key_verdict(evidence)
    assert "screen_changed_after_release" in verdict["reasons"]
    assert evidence["stuck_watch"]["baseline"]["change_ratio"] == 0.5
    assert evidence["stuck_watch"]["discriminating"] is False


def test_a_quiet_window_too_short_to_mean_anything_fails():
    evidence = held()
    evidence["recovery"]["samples_sig"] = _timeline(READY, 5000, 3) + [[READY + 10_200, 7]]
    assert "no_quiet_window" in held_key_verdict(evidence)["reasons"]


def test_idle_churn_counts_changes_not_distinct_values():
    samples = [[0, 1], [250, 1], [500, 2], [750, 1], [1000, 1]]
    assert idle_churn(samples, 0, 1000) == {"samples": 5, "changes": 2, "pairs": 4,
                                            "window_ms": 1000, "distinct": 2,
                                            "change_ratio": 0.5}


def test_short_and_long_windows_are_compared_by_ratio_not_by_count():
    busy = [[0, 1], [250, 2], [500, 1], [750, 2], [1000, 1], [1250, 2]]
    short = [[9000, 1], [9250, 2], [9500, 1]]
    long_window = idle_churn(busy, 0, 1250)
    short_window = idle_churn(short, 9000, 9500)
    assert long_window["changes"] > short_window["changes"]
    assert long_window["change_ratio"] == short_window["change_ratio"] == 1.0


def test_a_pending_cleanup_may_name_why_it_stayed_pending():
    evidence = refused()
    evidence["audit_evidence"] = dict(evidence["audit_evidence"], cleanup_outcome="status_401")
    evidence["session_end_evidence"] = dict(evidence["audit_evidence"])
    verdict = refused_rebuild_verdict(evidence)
    assert "evidence_field_out_of_whitelist" not in verdict["reasons"]



def refused_logout(**overrides) -> dict:
    audit = dict(AUDIT, cleanup_outcome="status_404")
    evidence = {
        "errors": [],
        "handshake": {"state": "normal", "canvas": {"non_black": 1627}, "sid_matches": True},
        "cuts": [],
        "recovery": {"state_never_failed": True, "sample_count": 12},
        "session": {"status": "closed", "cleanup": "pending", "reason": "client_closed"},
        "slot_released": False,
        "cleanup_outcome": "status_404",
        "audit_actions": ["session_created", "session_finished"],
        "audit_evidence": audit,
        "session_end_evidence": dict(audit),
        "sentinel_leaked": False,
        "output_is_clean": True,
    }
    evidence.update(overrides)
    return evidence


def test_a_refused_logout_with_the_slot_held_passes():
    assert refused_logout_verdict(refused_logout()) == {
        "verdict": "pass", "reasons": [], "end_reason": "client_closed"}


def test_a_logout_that_never_reached_the_device_is_not_a_refusal():
    for outcome in ("timeout", "error_clientconnectorerror", None, ""):
        evidence = refused_logout(cleanup_outcome=outcome,
                                  audit_evidence=dict(AUDIT, cleanup_outcome=outcome))
        assert "logout_never_reached_the_device" in refused_logout_verdict(evidence)["reasons"]


def test_an_accepted_logout_cannot_be_reported_as_pending():
    evidence = refused_logout(cleanup_outcome="status_204",
                              audit_evidence=dict(AUDIT, cleanup_outcome="status_204"))
    assert "logout_was_accepted" in refused_logout_verdict(evidence)["reasons"]


def test_a_pending_cleanup_that_freed_the_slot_is_a_contradiction():
    assert "slot_released_despite_pending" in refused_logout_verdict(
        refused_logout(slot_released=True))["reasons"]


def test_a_console_that_failed_on_its_own_does_not_answer_this_question():
    assert "console_failed_without_a_cut" in refused_logout_verdict(
        refused_logout(recovery={"state_never_failed": False, "sample_count": 12}))["reasons"]


def test_a_logout_drill_that_cut_the_link_is_a_different_experiment():
    evidence = refused_logout(cuts=[{"index": 1, "sockets_reset": 1}])
    assert "upstream_was_cut" in refused_logout_verdict(evidence)["reasons"]


def test_the_wrong_end_reason_is_not_a_departure():
    evidence = refused_logout(session={"status": "closed", "cleanup": "pending",
                                       "reason": "upstream_error"})
    assert "wrong_end_reason" in refused_logout_verdict(evidence)["reasons"]


def test_the_audit_must_agree_about_why_cleanup_stayed_pending():
    evidence = refused_logout(audit_evidence=dict(AUDIT, cleanup_outcome="status_500"),
                              session_end_evidence=dict(AUDIT, cleanup_outcome="status_500"))
    assert "audit_disagrees_on_logout_outcome" in refused_logout_verdict(evidence)["reasons"]
