"""The pointer probe's verdict logic and its safety limits."""
import re
from pathlib import Path

import pytest

from tools.pointer_proof import CURSOR_MAX_PIXELS, judge

ROOT = Path(__file__).resolve().parents[1]
PROBE = ROOT / "tools" / "pointer_proof.cjs"


def step(target, pixels, bbox, hit):
    return {"target": target, "pixels": pixels, "bbox": bbox, "hit": hit}


def payload(**overrides):
    base = {
        "canvas_size_stable": True,
        "canvas_lit": {"lit": 448000},
        "canvas_idle": {"pixels": 0},
        "cursor_steps": [
            step([82, 61], 267, [8, 8, 88, 72], True),
            step([922, 676], 338, [80, 56, 856, 536], True),
            step([512, 384], 460, [512, 296, 424, 256], True),
        ],
        "hover": [],
        "canvas_menu": {"pixels": 0, "bbox": None},
        "canvas_menu_dismissed": {"pixels": 0, "bbox": None},
        "state_after_input": "normal",
        "errors": [],
    }
    base.update(overrides)
    return base


CONFIRMED = {"cleanup": "confirmed"}


def test_cursor_following_the_pointer_proves_the_claim():
    ok, verdict = judge(payload(), CONFIRMED)
    assert ok is True
    assert verdict["cursor_followed_the_pointer"] is True
    assert verdict["session_lifecycle"] is True


def test_one_hit_is_not_enough():
    data = payload(cursor_steps=[step([82, 61], 267, [8, 8, 88, 72], True),
                                 step([922, 676], 338, [0, 0, 999, 999], False),
                                 step([512, 384], 460, [0, 0, 999, 999], False)])
    ok, verdict = judge(data, CONFIRMED)
    assert ok is False
    assert verdict["cursor_followed_the_pointer"] is False


def test_full_repaint_is_not_a_cursor_move():
    data = payload(cursor_steps=[
        step([82, 61], CURSOR_MAX_PIXELS + 1, [8, 8, 88, 72], True),
        step([922, 676], CURSOR_MAX_PIXELS + 1, [80, 56, 856, 536], True),
        step([512, 384], CURSOR_MAX_PIXELS + 1, [512, 296, 424, 256], True),
    ])
    ok, verdict = judge(data, CONFIRMED)
    assert ok is False
    assert verdict["cursor_followed_the_pointer"] is False


def test_blank_framebuffer_means_no_signal():
    ok, verdict = judge(payload(canvas_lit={"lit": 0}), CONFIRMED)
    assert ok is False
    assert verdict["framebuffer_has_signal"] is False


def test_control_group_must_be_measured():
    ok, verdict = judge(payload(canvas_idle={"resized": True, "pixels": -1}), CONFIRMED)
    assert ok is False
    assert verdict["cursor_followed_the_pointer"] is False


def test_unsettled_framebuffer_invalidates_the_control_group():
    ok, verdict = judge(payload(canvas_size_stable=False), CONFIRMED)
    assert ok is False


def test_hover_only_counts_when_it_is_local():
    data = payload(cursor_steps=[], hover=[
        {"spot": "left_edge", "pixels": 2549, "bbox": [16, 16, 992, 568]},
    ])
    ok, verdict = judge(data, CONFIRMED)
    assert ok is False
    assert verdict["hover_reached_host"] is False


def test_local_hover_counts():
    data = payload(cursor_steps=[], hover=[
        {"spot": "top_center", "pixels": 240, "bbox": [500, 8, 40, 24]},
    ])
    ok, verdict = judge(data, CONFIRMED)
    assert ok is True
    assert verdict["hover_reached_host"] is True


def test_context_menu_must_open_and_close():
    opens = {"pixels": 24000, "bbox": [300, 400, 300, 200]}
    closes = {"pixels": 0, "bbox": None}
    ok, verdict = judge(payload(cursor_steps=[], canvas_menu=opens,
                                canvas_menu_dismissed=closes), CONFIRMED)
    assert ok is True
    assert verdict["context_menu_reached_host"] is True
    ok, verdict = judge(payload(cursor_steps=[], canvas_menu=opens,
                                canvas_menu_dismissed=opens), CONFIRMED)
    assert ok is False


def test_session_must_survive_and_clean_up():
    ok, verdict = judge(payload(), {"cleanup": "pending"})
    assert ok is False
    assert verdict["session_lifecycle"] is False


def test_browser_errors_always_fail_the_run():
    ok, _ = judge(payload(errors=["blank framebuffer"]), CONFIRMED)
    assert ok is False


def test_probe_never_presses_the_left_button():
    source = PROBE.read_text(encoding="utf-8")
    buttons = set(re.findall(r"button:\s*'([a-z]+)'", source))
    assert buttons == {"right"}, "only the right button may be pressed"


@pytest.mark.parametrize("constant,limit", [("MAX_RIGHT_CLICKS", 3), ("MAX_MOVES", 16)])
def test_probe_budgets_are_bounded(constant, limit):
    source = PROBE.read_text(encoding="utf-8")
    value = int(re.search(rf"const {constant} = (\d+)", source).group(1))
    assert 0 < value <= limit


def test_probe_stops_on_a_blank_framebuffer():
    source = PROBE.read_text(encoding="utf-8")
    assert "MIN_LIT_PIXELS" in source
    assert "no_signal_detected" in source
