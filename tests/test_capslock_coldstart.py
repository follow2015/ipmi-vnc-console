"""Experiment D's stop criterion, and the geometry that makes ``unknown`` auditable."""
from __future__ import annotations

import pytest

from tools.capslock_coldstart import geometry, stability, text_landed


@pytest.mark.parametrize("readback", [
    {"verdict": "echoed_correct", "visible_groups": 4},
    {"verdict": "unknown", "visible_groups": 2},
    {"verdict": "partial", "visible_groups": 3},
])
def test_a_measured_glyph_group_counts_as_text_landing(readback):
    assert text_landed(readback) is True


@pytest.mark.parametrize("readback", [
    None,
    {},
    {"verdict": None, "visible_groups": None},
    {"verdict": "not_run", "visible_groups": None},
    {"verdict": "silent", "visible_groups": 0},
    {"verdict": "echoed", "visible_groups": None},
])
def test_no_measured_glyph_is_not_a_landing(readback):
    assert text_landed(readback) is False


def test_a_bright_boot_splash_is_not_mistaken_for_a_prompt():
    splash = {"verdict": "silent", "caps_lock": "unknown", "visible_groups": 0}
    assert text_landed(splash) is False


def test_geometry_reports_the_heights_a_verdict_was_computed_from():
    case = {"lower": {"cells": [{"top": 51, "bottom": 63, "ink": 70}]},
            "upper": {"cells": [{"top": 49, "bottom": 63, "ink": 52}]}}
    measured = geometry(case)
    assert measured["lower"]["height"] == 13
    assert measured["upper"]["height"] == 15


def test_geometry_says_none_when_a_calibration_glyph_never_appeared():
    measured = geometry({"lower": {"cells": [{"top": 728, "bottom": 751, "ink": 274}]},
                         "upper": {"cells": []}})
    assert measured["lower"]["height"] == 24
    assert measured["upper"] is None


def test_geometry_tolerates_a_missing_case_block():
    assert geometry(None) == {"lower": None, "upper": None}


@pytest.mark.parametrize("known,expected", [
    ([], False),
    (["off"], False),
    (["off", "off"], True),
    (["off", "on"], False),
    (["off", "off", "on"], False),
])
def test_stability_needs_at_least_two_agreeing_measurements(known, expected):
    assert stability(known) is expected
