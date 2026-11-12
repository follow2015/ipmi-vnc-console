"""The keyboard probe's verdict logic and its safety limits."""
import re
from pathlib import Path

import pytest

from tools.keyboard_proof import judge

ROOT = Path(__file__).resolve().parents[1]
PROBE = ROOT / "tools" / "keyboard_proof.cjs"


def payload(**overrides):
    base = {
        "canvas_size_stable": True,
        "canvas_idle": {"pixels": 0},
        "canvas_typed": {"pixels": 419, "bbox": [112, 48, 72, 16]},
        "canvas_restored": {"pixels": 0},
        "state_after_input": "normal",
        "errors": [],
    }
    base.update(overrides)
    return base


CONFIRMED = {"cleanup": "confirmed"}


def test_reversible_echo_proves_the_claim():
    ok, verdict = judge(payload(), CONFIRMED)
    assert ok is True
    assert verdict["keystroke_reached_host"] and verdict["echo_removed"]
    assert verdict["session_lifecycle"] and verdict["framebuffer_settled"]


def test_idle_churn_is_not_mistaken_for_input():
    ok, verdict = judge(payload(canvas_idle={"pixels": 500}, canvas_typed={"pixels": 419,
                                                                         "bbox": [0, 0, 1, 1]}), CONFIRMED)
    assert ok is False
    assert verdict["keystroke_reached_host"] is False


def test_typing_without_a_visible_change_fails():
    ok, verdict = judge(payload(canvas_typed={"pixels": 0, "bbox": None}), CONFIRMED)
    assert ok is False
    assert verdict["keystroke_reached_host"] is False


def test_change_without_a_region_fails():
    ok, verdict = judge(payload(canvas_typed={"pixels": 900, "bbox": None}), CONFIRMED)
    assert ok is False


def test_erase_that_leaves_the_text_behind_fails():
    ok, verdict = judge(payload(canvas_restored={"pixels": 419}), CONFIRMED)
    assert ok is False
    assert verdict["echo_removed"] is False


def test_erase_cannot_be_judged_without_the_preinput_frame():
    ok, verdict = judge(payload(canvas_restored={"resized": True, "pixels": -1}), CONFIRMED)
    assert ok is False
    assert verdict["echo_removed"] is False


def test_unsettled_framebuffer_invalidates_the_control_group():
    ok, verdict = judge(payload(canvas_size_stable=False), CONFIRMED)
    assert ok is False
    assert verdict["framebuffer_settled"] is False


def test_session_must_survive_the_input_and_clean_up():
    ok, verdict = judge(payload(), {"cleanup": "pending"})
    assert ok is False
    assert verdict["session_lifecycle"] is False
    ok, verdict = judge(payload(state_after_input="disconnected"), CONFIRMED)
    assert ok is False


def test_browser_errors_always_fail_the_run():
    ok, _ = judge(payload(errors=["boom"]), CONFIRMED)
    assert ok is False


def test_probe_refuses_keys_that_could_submit_input():
    source = PROBE.read_text(encoding="utf-8")
    forbidden = re.search(r"const FORBIDDEN = new Set\(\[(.*?)\]\)", source, re.S).group(1)
    for name in ("Enter", "NumpadEnter", "Tab", "Escape", "Space"):
        assert f"'{name}'" in forbidden, f"{name} must be rejected before dispatch"
    assert "keyboard.press('Enter')" not in source


def test_probe_only_types_lowercase_letters():
    source = PROBE.read_text(encoding="utf-8")
    text = re.search(r"const TEXT = '([^']*)'", source).group(1)
    assert text and text.islower() and text.isalpha()
    guard = re.search(r"function guardKey\(name\) \{(.*?)\n\}", source, re.S).group(1)
    assert r"/^[a-z]$/" in guard
    assert "'Backspace'" in guard


def test_probe_sends_no_combination_other_than_clear_line():
    source = PROBE.read_text(encoding="utf-8")
    combos = set(re.findall(r"guardCombo\('([^']+)'\)", source)) - {"combo"}
    assert combos == {"Control+u"}
    pressed = set(re.findall(r"keyboard\.press\('([^']+)'\)", source))
    assert pressed <= {"Backspace", "Control+u"}


def test_probe_has_a_bounded_key_budget():
    source = PROBE.read_text(encoding="utf-8")
    budget = int(re.search(r"const MAX_KEYS = (\d+)", source).group(1))
    assert 0 < budget <= 32


@pytest.mark.parametrize("field", ["canvas_idle", "canvas_typed", "canvas_restored"])
def test_judge_tolerates_missing_sections(field):
    data = payload()
    data.pop(field)
    ok, _ = judge(data, CONFIRMED)
    assert ok is False


def test_control_group_that_never_measured_cannot_pass():
    ok, verdict = judge(payload(canvas_idle={"resized": True, "pixels": -1}), CONFIRMED)
    assert ok is False
    assert verdict["keystroke_reached_host"] is False
