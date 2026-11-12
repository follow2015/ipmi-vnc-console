"""The click probe's verdict logic and its safety limits."""
import re
from pathlib import Path

import pytest

from tools.click_proof import judge

ROOT = Path(__file__).resolve().parents[1]
PROBE = ROOT / "tools" / "click_proof.cjs"


def payload(**overrides):
    base = {
        "canvas_size_stable": True,
        "canvas_lit": {"lit": 449000},
        "canvas_idle": {"pixels": 0},
        "clicked": {"pixels": 265733, "bbox": [360, 0, 664, 768]},
        "restored": {"pixels": 2538, "bbox": [360, 448, 600, 288]},
        "change_at_target": True,
        "restored_by": "escape",
        "state_after_input": "normal",
        "errors": [],
    }
    base.update(overrides)
    return base


CONFIRMED = {"cleanup": "confirmed"}


def test_panel_opening_at_the_target_proves_the_claim():
    ok, verdict = judge(payload(), CONFIRMED)
    assert ok is True
    assert verdict["click_reached_host"] is True
    assert verdict["session_lifecycle"] is True


def test_a_small_residual_does_not_fail_a_correct_run():
    ok, verdict = judge(payload(clicked={"pixels": 265733, "bbox": [360, 0, 664, 768]},
                                restored={"pixels": 2538, "bbox": [360, 448, 600, 288]}), CONFIRMED)
    assert ok is True
    assert verdict["change_reverted_when_dismissed"] is True


def test_a_panel_that_stays_open_is_not_proof():
    ok, verdict = judge(payload(restored={"pixels": 265000, "bbox": [360, 0, 664, 768]}), CONFIRMED)
    assert ok is False
    assert verdict["change_reverted_when_dismissed"] is False


def test_residual_must_be_under_half_even_for_a_small_change():
    ok, verdict = judge(payload(clicked={"pixels": 2000, "bbox": [900, 700, 60, 60]},
                                restored={"pixels": 1200, "bbox": [900, 700, 60, 60]}), CONFIRMED)
    assert ok is False
    assert verdict["change_reverted_when_dismissed"] is False


def test_small_change_is_not_a_click_consequence():
    ok, verdict = judge(payload(clicked={"pixels": 300, "bbox": [900, 740, 20, 20]}), CONFIRMED)
    assert ok is False
    assert verdict["click_changed_the_host_screen"] is False


def test_change_must_land_where_the_click_was():
    ok, verdict = judge(payload(change_at_target=False), CONFIRMED)
    assert ok is False
    assert verdict["change_landed_at_the_target"] is False


def test_blank_framebuffer_means_no_signal():
    ok, verdict = judge(payload(canvas_lit={"lit": 0}), CONFIRMED)
    assert ok is False
    assert verdict["framebuffer_has_signal"] is False


def test_control_group_must_be_measured():
    ok, verdict = judge(payload(canvas_idle={"resized": True, "pixels": -1}), CONFIRMED)
    assert ok is False
    assert verdict["control_frame_quiet"] is False


def test_unsettled_framebuffer_invalidates_the_control_group():
    ok, verdict = judge(payload(canvas_size_stable=False), CONFIRMED)
    assert ok is False
    assert verdict["control_frame_quiet"] is False


def test_session_must_survive_and_clean_up():
    ok, verdict = judge(payload(), {"cleanup": "pending"})
    assert ok is False
    assert verdict["session_lifecycle"] is False


def test_browser_errors_always_fail_the_run():
    ok, _ = judge(payload(errors=["blank framebuffer"]), CONFIRMED)
    assert ok is False


def test_probe_only_presses_the_left_button():
    source = PROBE.read_text(encoding="utf-8")
    buttons = set(re.findall(r"button:\s*'([a-z]+)'", source))
    assert buttons == {"left"}, f"only the left button may be pressed, got {buttons}"


def test_probe_types_nothing_and_only_uses_the_documented_keys():
    source = PROBE.read_text(encoding="utf-8")
    assert "keyboard.type" not in source
    assert "insertText" not in source
    pressed = set(re.findall(r"keyboard\.press\('([^']+)'\)", source))
    assert pressed == {"Escape", "Control+Alt+Delete"}, pressed


def test_probe_click_budget_is_bounded():
    source = PROBE.read_text(encoding="utf-8")
    assert int(re.search(r"const MAX_CLICKS = (\d+)", source).group(1)) <= 2
    assert "clicks < MAX_CLICKS" in source, "every extra click must be gated"


def test_fallback_dismissal_only_fires_while_the_panel_is_still_open():
    source = PROBE.read_text(encoding="utf-8")
    assert "stillOpen" in source
    assert "result.clicked.pixels" in source


def test_probe_avoids_the_minute_boundary():
    source = PROBE.read_text(encoding="utf-8")
    assert "MIN_SECONDS_BEFORE_BOUNDARY" in source
    assert "getSeconds()" in source


@pytest.mark.parametrize("field", ["clicked", "restored"])
def test_judge_tolerates_missing_sections(field):
    data = payload()
    data.pop(field)
    ok, _ = judge(data, CONFIRMED)
    assert ok is False
