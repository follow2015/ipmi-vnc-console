"""Guards for the scripted keystroke support in tools/passthrough_check.py."""
import json

import pytest

from tools.passthrough_check import (
    CLIENT_MODIFIERS,
    PROBE_TEXT,
    SECRET_PLACEHOLDER,
    apply_probe,
    describe_steps,
    liveness_series,
    liveness_verdict,
    not_changed_steps,
    parse_type_script,
    probe_steps,
    probe_verdict,
    script_env,
)


def test_script_keeps_the_secret_as_a_placeholder():
    steps = parse_type_script(json.dumps([
        {"label": "username", "text": "root"},
        {"label": "password", "text": SECRET_PLACEHOLDER},
    ]))
    assert [s["text"] for s in steps] == ["root", SECRET_PLACEHOLDER]
    assert steps[1]["text"] != "root"


def test_serialised_job_never_carries_the_secret_value(monkeypatch):
    monkeypatch.setenv("KVM_SECRET", "s3cr3t-value")
    steps = parse_type_script('[{"label":"password","text":"@secret"}]')
    env = script_env(steps)
    assert "s3cr3t-value" not in env["KVM_SCRIPT"]
    assert SECRET_PLACEHOLDER in env["KVM_SCRIPT"]


def test_describe_steps_redacts_secret_text():
    steps = parse_type_script(json.dumps([
        {"label": "username", "text": "root"},
        {"label": "password", "text": "@secret"},
    ]))
    described = describe_steps(steps)
    assert described[0]["chars"] == 4
    assert described[1]["secret"] is True
    assert "text" not in described[1]
    assert "s3cr3t" not in json.dumps(described)


def test_script_rejects_a_step_without_a_label():
    with pytest.raises(ValueError, match="label"):
        parse_type_script('[{"text":"root"}]')


def test_script_rejects_a_step_without_text():
    with pytest.raises(ValueError, match="text"):
        parse_type_script('[{"label":"a"}]')


def test_script_rejects_unknown_fields():
    with pytest.raises(ValueError, match="unknown"):
        parse_type_script('[{"label":"a","text":"b","cmd":"rm -rf /"}]')


def test_script_rejects_malformed_json():
    with pytest.raises(ValueError, match="JSON"):
        parse_type_script("not json")


def test_script_rejects_a_non_list_payload():
    with pytest.raises(ValueError, match="list"):
        parse_type_script('{"label":"a","text":"b"}')


def test_script_is_empty_when_not_supplied():
    assert parse_type_script("") == []


def test_script_accepts_an_explicit_key_chord():
    steps = parse_type_script('[{"label":"cad","keys":"Control+Alt+Delete"}]')
    assert steps[0]["keys"] == "Control+Alt+Delete"
    assert steps[0]["text"] == ""


def test_script_rejects_a_step_with_both_text_and_keys():
    with pytest.raises(ValueError, match="one of"):
        parse_type_script('[{"label":"a","text":"x","keys":"Enter"}]')


def test_describe_key_chord_keeps_the_chord_visible():
    steps = parse_type_script('[{"label":"cad","keys":"Control+Alt+Delete"}]')
    assert describe_steps(steps) == [{"label": "cad", "keys": "Control+Alt+Delete"}]


def test_probe_types_a_readable_marker_and_clears_it_again():
    steps = probe_steps()
    assert [s["label"] for s in steps] == ["probe_echo", "probe_clear"]
    assert steps[0]["text"] == PROBE_TEXT
    assert steps[1]["keys"] == "Control+U"


def test_probe_never_presses_enter():
    steps = probe_steps()
    assert steps[0]["enter"] is False
    assert steps[1]["enter"] is False


def test_probe_text_proves_both_letter_cases_travel():
    assert any(c.isupper() for c in PROBE_TEXT)
    assert any(c.islower() for c in PROBE_TEXT)


def test_probe_rejects_a_marker_without_an_uppercase_letter():
    with pytest.raises(ValueError, match="uppercase"):
        probe_steps("abc1")


def test_probe_rejects_a_marker_without_a_lowercase_letter():
    with pytest.raises(ValueError, match="lowercase"):
        probe_steps("ABC1")


def test_probe_rejects_anything_that_is_not_ascii_alphanumeric():
    for marker in ("Ab 1", "Ab;reboot", "Ab\n", "Ab-1", "Aa中文"):
        with pytest.raises(ValueError, match="alphanumeric"):
            probe_steps(marker)


def test_probe_rejects_an_empty_or_overlong_marker():
    with pytest.raises(ValueError, match="length"):
        probe_steps("")
    with pytest.raises(ValueError, match="length"):
        probe_steps("Aa" + "b" * 15)


def test_probe_steps_survive_the_script_parser():
    reparsed = parse_type_script(json.dumps(probe_steps()))
    assert [s["label"] for s in reparsed] == ["probe_echo", "probe_clear"]
    assert reparsed[0]["text"] == PROBE_TEXT


def test_probe_marks_its_screenshots_for_the_operator():
    steps = probe_steps()
    assert steps[0]["shot_before"] == "probe-before"
    assert steps[0]["shot"] == "probe-echo"


def test_describe_steps_keeps_probe_text_out_of_the_evidence():
    described = describe_steps(probe_steps())
    assert described[0] == {"label": "probe_echo", "chars": len(PROBE_TEXT)}


def test_probe_is_prepended_only_when_requested():
    steps = parse_type_script('[{"label":"login","text":"root"}]')
    assert apply_probe(steps, False) == steps
    assert apply_probe(steps, True)[0]["label"] == "probe_echo"


def test_probe_runs_before_the_operators_own_steps():
    steps = parse_type_script('[{"label":"login","text":"root"}]')
    merged = apply_probe(steps, True)
    assert [s["label"] for s in merged] == ["probe_echo", "probe_clear", "login"]


def test_probe_is_not_added_twice():
    once = apply_probe(parse_type_script('[{"label":"login","text":"root"}]'), True)
    twice = apply_probe(once, True)
    assert [s["label"] for s in twice].count("probe_echo") == 1


def test_probe_verdict_separates_not_run_from_a_silent_console():
    assert probe_verdict(None) == "not_run"
    assert probe_verdict({}) == "not_run"
    assert probe_verdict({"before": 1, "after": 2, "changed": True}) == "echoed"
    assert probe_verdict({"before": 7, "after": 7, "changed": False}) == "silent"


def test_liveness_calls_a_changing_screen_moving():
    assert liveness_verdict([11, 12, 13]) == "moving"


def test_liveness_calls_a_frozen_screen_stalled():
    assert liveness_verdict([7, 7, 7, 7]) == "stalled"


def test_liveness_refuses_to_judge_without_enough_samples():
    assert liveness_verdict(None) == "unknown"
    assert liveness_verdict([]) == "unknown"
    assert liveness_verdict([7]) == "unknown"
    assert liveness_verdict([7, 7]) == "unknown"


def test_liveness_counts_a_single_change_in_a_long_flat_run():
    assert liveness_verdict([9, 9, 9, 9, 9, 8]) == "moving"


def test_liveness_series_reads_the_run_in_observation_order():
    payload = {
        "canvas_initial": {"fingerprint": 1},
        "step_samples": [{"canvas": {"fingerprint": 2}}, {"canvas": {"fingerprint": 3}}],
        "canvas_after_input": {"fingerprint": 4},
    }
    assert liveness_series(payload) == [1, 2, 3, 4]


def test_liveness_series_skips_missing_observations():
    payload = {"canvas_initial": {}, "step_samples": [{"canvas": {}}],
               "canvas_after_input": None}
    assert liveness_series(payload) == []


def test_liveness_series_tolerates_older_evidence_without_fingerprints():
    assert liveness_series({"canvas_initial": {"non_black": 90000}}) == []


def test_liveness_series_ignores_the_probe_it_typed_itself():
    payload = {
        "canvas_initial": {"fingerprint": 1},
        "step_samples": [
            {"label": "probe_echo", "canvas": {"fingerprint": 9}},
            {"label": "probe_clear", "canvas": {"fingerprint": 9}},
            {"label": "look", "canvas": {"fingerprint": 1}},
        ],
        "canvas_after_input": {"fingerprint": 1},
    }
    assert liveness_series(payload) == [1, 1, 1]


def test_client_modifiers_cover_every_modifier():
    assert set(CLIENT_MODIFIERS) == {"Shift", "Control", "Alt", "Meta"}


def test_client_modifiers_start_with_shift():
    assert CLIENT_MODIFIERS[0] == "Shift"


def test_client_modifiers_never_include_a_key_that_types_something():
    typable = {"Enter", "Tab", "Space", "Escape", "Backspace", "Delete",
               "ArrowLeft", "ArrowRight", "ArrowUp", "ArrowDown"}
    for name in CLIENT_MODIFIERS:
        assert name not in typable
        assert name.isalpha()


def test_script_env_always_carries_the_modifier_plan():
    env = script_env([])
    assert json.loads(env["KVM_MODIFIERS"]) == list(CLIENT_MODIFIERS)


def test_a_step_can_demand_that_the_screen_change():
    steps = parse_type_script('[{"label":"run","text":"uname -a","expect_change":true}]')
    assert steps[0]["expect_change"] is True


def test_a_step_expects_no_change_unless_it_says_so():
    steps = parse_type_script('[{"label":"look","text":"","enter":false}]')
    assert steps[0]["expect_change"] is False


def test_change_assertions_name_the_steps_that_did_not_move():
    samples = [
        {"label": "run", "fingerprint_before": 1, "canvas": {"fingerprint": 1}},
        {"label": "idle", "fingerprint_before": 2, "canvas": {"fingerprint": 2}},
    ]
    steps = [{"label": "run", "expect_change": True},
             {"label": "idle", "expect_change": False}]
    assert not_changed_steps(samples, steps) == ["run"]


def test_change_assertions_ignore_steps_the_run_never_reached():
    samples = [{"label": "run", "fingerprint_before": 1, "canvas": {"fingerprint": 2}}]
    steps = [{"label": "run", "expect_change": True},
             {"label": "later", "expect_change": True}]
    assert not_changed_steps(samples, steps) == []


def test_change_assertions_skip_observations_without_a_baseline():
    samples = [{"label": "run", "canvas": {"fingerprint": 2}}]
    assert not_changed_steps(samples, [{"label": "run", "expect_change": True}]) == []


def test_reload_step_needs_no_text_and_carries_no_enter():
    steps = parse_type_script(json.dumps([{"label": "reload", "reload": True, "wait": 5000}]))
    assert steps == [{"label": "reload", "text": "", "keys": "", "reload": True,
                      "enter": False, "wait": 5000, "delay": 55, "shot": "",
                      "shot_before": "", "expect_change": False}]
    assert describe_steps(steps) == [{"label": "reload", "reload": True}]


def test_reload_cannot_be_combined_with_typing():
    for bad in ({"label": "x", "reload": True, "text": "a"},
                {"label": "x", "reload": True, "keys": "Enter"},
                {"label": "x", "reload": "yes"}):
        with pytest.raises(ValueError, match="reload"):
            parse_type_script(json.dumps([bad]))
