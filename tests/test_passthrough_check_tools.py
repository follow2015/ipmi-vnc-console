"""M6.4 / M6.5 / POST safety: pure helpers in tools/passthrough_check.py."""
from __future__ import annotations

import json

import pytest

from tools.passthrough_check import (
    DIRECTION_KEYS,
    FIRST_KEY_MAX_ROUNDS,
    LATENCY_FIELDS,
    LATENCY_NOTE,
    POST_PHASE_NOTE,
    PROBE_CASE_LABEL,
    PROBE_LABEL,
    build_report,
    clamp_first_key_rounds,
    describe_steps,
    first_key_report,
    first_key_rounds,
    is_probe_step,
    parse_type_script,
    post_key_blockers,
    post_key_findings,
    script_env,
    step_report,
)


def _step(**overrides):
    base = {"label": "s", "text": "", "keys": "", "reload": False, "enter": False,
            "wait": 1200, "delay": 55, "hold": 0, "shot": "", "shot_before": "",
            "expect_change": False}
    base.update(overrides)
    return base


def _forward(before=10, after=12):
    return {"label": "round", "key_events_before": before, "key_events_after": after,
            "client_bytes_before": before, "client_bytes_after": after}


def _lost(before=10, after=10):
    return {"label": "round", "key_events_before": before, "key_events_after": after,
            "client_bytes_before": before, "client_bytes_after": after}



def test_a_normal_step_has_no_post_key():
    steps = parse_type_script('[{"label":"login","text":"root"}]')
    assert "post" not in steps[0]
    assert set(steps[0]) == {"label", "text", "keys", "reload", "enter", "wait",
                            "delay", "hold", "shot", "shot_before", "expect_change"}


def test_post_flag_is_parsed_only_when_true():
    steps = parse_type_script(json.dumps([
        {"label": "boot", "keys": "F2", "post": True, "hold": 0},
    ]))
    assert steps[0]["post"] is True


def test_post_must_be_a_boolean():
    with pytest.raises(ValueError, match="post"):
        parse_type_script(json.dumps([{"label": "x", "keys": "F2", "post": "yes"}]))


def test_script_env_shape_is_unchanged():
    env = script_env([])
    assert set(env) == {"KVM_SCRIPT", "KVM_MODIFIERS"}


def test_describe_steps_keeps_post_text_as_shape_only():
    steps = parse_type_script(json.dumps([{"label": "boot", "text": "hello", "post": True}]))
    assert describe_steps(steps) == [{"label": "boot", "chars": 5}]



def test_first_key_rounds_have_the_standard_step_shape():
    rounds = first_key_rounds(3)
    assert len(rounds) == 3
    assert [r["label"] for r in rounds] == [
        "first_key_reload_1", "first_key_reload_2", "first_key_reload_3"]
    for step in rounds:
        assert step["reload"] is True and step["hold"] == 0
        assert set(step) == set(_step())


def test_first_key_rounds_zero_is_empty():
    assert first_key_rounds(0) == []


def test_first_key_rounds_flow_through_the_existing_helpers_unchanged():
    rounds = first_key_rounds(2)
    env = script_env(rounds)
    assert json.loads(env["KVM_SCRIPT"]) == rounds
    assert describe_steps(rounds) == [
        {"label": "first_key_reload_1", "reload": True},
        {"label": "first_key_reload_2", "reload": True},
    ]


def test_clamp_first_key_rounds_caps_and_rejects():
    assert clamp_first_key_rounds(3) == 3
    assert clamp_first_key_rounds(999) == FIRST_KEY_MAX_ROUNDS
    assert clamp_first_key_rounds("2") == 2
    with pytest.raises(ValueError, match="integer"):
        clamp_first_key_rounds("many")
    with pytest.raises(ValueError, match="non-negative"):
        clamp_first_key_rounds(-1)


def test_first_key_report_not_run_has_no_loss_rate():
    report = first_key_report([])
    assert report["conclusion"] == "not_run"
    assert report["rounds"] == 0
    assert report["first_key_loss_rate"] is None


def test_first_key_report_all_forwarded_is_reliable():
    probes = [_forward(10, 12), _forward(12, 14), _forward(14, 16)]
    report = first_key_report(probes, rounds_requested=3)
    assert report["conclusion"] == "first_key_reliable"
    assert report["forwarded"] == 3 and report["lost"] == 0
    assert report["first_key_loss_rate"] == 0.0
    assert "incomplete" not in report


def test_first_key_report_counts_lost_first_keys():
    probes = [_forward(10, 12), _lost(12, 12), _lost(12, 12), _forward(12, 14)]
    report = first_key_report(probes)
    assert report["conclusion"] == "first_key_lossy"
    assert report["forwarded"] == 2 and report["lost"] == 2
    assert report["first_key_loss_rate"] == 0.5


def test_first_key_report_unusable_counter_is_unknown_not_a_loss():
    probes = [{"label": "r", "key_events_before": None, "key_events_after": None,
              "client_bytes_before": None, "client_bytes_after": None}]
    report = first_key_report(probes)
    assert report["unknown"] == 1 and report["lost"] == 0
    assert report["measured_rounds"] == 0
    assert report["conclusion"] == "no_usable_counter"
    assert report["notes"]


def test_first_key_report_falls_back_to_client_bytes():
    probe = {"label": "r", "key_events_before": None, "key_events_after": None,
            "client_bytes_before": 100, "client_bytes_after": 108}
    report = first_key_report([probe])
    assert report["forwarded"] == 1
    assert report["conclusion"] == "first_key_reliable"


def test_first_key_report_rejects_bool_counters():
    probe = {"label": "r", "key_events_before": True, "key_events_after": False,
             "client_bytes_before": None, "client_bytes_after": None}
    assert first_key_report([probe])["unknown"] == 1


def test_first_key_report_flags_incomplete_rounds():
    report = first_key_report([_forward()], rounds_requested=5)
    assert report["incomplete"] is True
    assert any("fewer rounds" in note for note in report["notes"])


def test_first_key_report_ignores_non_dict_probes():
    assert first_key_report([None, 3, "x"])["rounds"] == 0



def test_direction_keys_cover_the_four_arrows():
    assert DIRECTION_KEYS == {"ArrowUp", "ArrowDown", "ArrowLeft", "ArrowRight"}


def test_post_long_press_is_an_overridable_finding():
    steps = [_step(label="boot", keys="F2", hold=200, post=True)]
    findings = post_key_findings(steps)
    assert len(findings) == 1
    assert findings[0]["reason"] == "long_press_in_post"
    assert findings[0]["overridable"] is True


def test_post_direction_long_press_is_absolute():
    steps = [_step(label="menu", keys="ArrowDown", hold=3000, post=True)]
    findings = post_key_findings(steps)
    assert findings[0]["reason"] == "direction_long_press_in_post"
    assert findings[0]["keys"] == ["ArrowDown"]
    assert findings[0]["overridable"] is False


def test_a_short_direction_tap_in_post_is_allowed():
    steps = [_step(label="menu", keys="ArrowDown", hold=0, post=True)]
    assert post_key_findings(steps) == []


def test_a_chord_with_a_direction_key_is_caught():
    steps = [_step(label="cad", keys="Control+ArrowUp", hold=150, post=True)]
    assert post_key_findings(steps)[0]["keys"] == ["ArrowUp"]


def test_non_post_long_press_is_not_a_finding():
    assert post_key_findings([_step(label="x", hold=500)]) == []


def test_default_policy_refuses_post_long_press():
    steps = [_step(label="boot", keys="F2", hold=200, post=True)]
    assert len(post_key_blockers(steps, False)) == 1


def test_allow_post_keys_lifts_a_soft_long_press():
    steps = [_step(label="boot", keys="F2", hold=200, post=True)]
    assert post_key_blockers(steps, True) == []


def test_allow_post_keys_never_lifts_the_direction_veto():
    steps = [_step(label="menu", keys="ArrowDown", hold=3000, post=True)]
    blockers = post_key_blockers(steps, True)
    assert blockers and blockers[0]["reason"] == "direction_long_press_in_post"



def test_is_probe_step_only_marks_probe_labels():
    assert is_probe_step(_step(label=PROBE_LABEL))
    assert is_probe_step(_step(label=PROBE_CASE_LABEL))
    assert not is_probe_step(_step(label="login"))


def test_step_report_never_invents_latency():
    row = step_report(_step(label="x", hold=120))
    for field in LATENCY_FIELDS:
        assert row[field] is None
    assert row["latency_status"] == "not_measured"
    assert LATENCY_NOTE in row["latency_note"]
    assert row["hold"] == 120
    assert row["accuracy"] is None and row["accuracy_status"] == "not_measured"


def test_step_report_marks_a_measured_accuracy():
    row = step_report(_step(label=PROBE_LABEL), accuracy=0.75)
    assert row["accuracy"] == 0.75
    assert row["accuracy_status"] == "measured"


def test_step_report_treats_bool_accuracy_as_not_measured():
    assert step_report(_step(), accuracy=True)["accuracy_status"] == "not_measured"


def test_build_report_rows_cover_every_step():
    steps = [_step(label="a"), _step(label=PROBE_LABEL), _step(label="z", hold=50)]
    report = build_report({}, steps)
    assert [row["label"] for row in report["steps"]] == ["a", PROBE_LABEL, "z"]
    assert report["steps"][2]["hold"] == 50


def test_build_report_attaches_accuracy_only_to_probe_steps():
    evidence = {"probe_readback": {"accuracy": 0.5}}
    steps = [_step(label="login"), _step(label=PROBE_LABEL), _step(label=PROBE_CASE_LABEL)]
    report = build_report(evidence, steps)
    assert report["steps"][0]["accuracy"] is None
    assert report["steps"][1]["accuracy"] == 0.5
    assert report["steps"][2]["accuracy"] == 0.5
    assert report["accuracy_measured_steps"] == 2


def test_build_report_latency_summary_is_not_measured():
    report = build_report({}, [])
    assert report["latency"]["status"] == "not_measured"
    assert all(value is None for value in report["latency"]["quantiles"].values())
    assert set(report["latency"]["quantiles"]) == set(LATENCY_FIELDS)


def test_build_report_no_safety_note_without_post_or_flag():
    safety = build_report({}, [_step()])["safety"]
    assert safety["manual_check_required"] is False
    assert safety["note"] is None
    assert safety["allow_post_keys"] is False


def test_build_report_requires_manual_check_with_allow_flag():
    safety = build_report({}, [_step()], allow_post_keys=True)["safety"]
    assert safety["allow_post_keys"] is True
    assert safety["manual_check_required"] is True
    assert safety["note"] == POST_PHASE_NOTE


def test_build_report_requires_manual_check_for_post_steps():
    steps = [_step(label="boot", keys="F2", post=True)]
    safety = build_report({}, steps)["safety"]
    assert safety["post_steps"] == ["boot"]
    assert safety["manual_check_required"] is True
    assert safety["note"] == POST_PHASE_NOTE


def test_build_report_carries_the_first_key_conclusion():
    evidence = {"first_key_probe": {"conclusion": "first_key_lossy",
                                    "first_key_loss_rate": 0.25}}
    report = build_report(evidence, [])
    assert report["first_key_probe"]["conclusion"] == "first_key_lossy"


def test_build_report_tolerates_missing_evidence():
    report = build_report(None, [])
    assert report["first_key_probe"] is None
    assert report["steps"] == []
