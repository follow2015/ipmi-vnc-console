"""The operator driver's argument parsing."""
from __future__ import annotations

import pytest

from tools.console_ops import parse_versions


def test_no_declaration_keeps_the_measured_default():
    assert parse_versions("") == ()
    assert parse_versions("  ") == ()


def test_a_single_greeting_is_taken_verbatim():
    assert parse_versions("RFB 003.008") == ("RFB 003.008",)


def test_several_firmwares_can_be_declared_for_one_run():
    assert parse_versions("RFB 003.008, RFB 055.008") == ("RFB 003.008", "RFB 055.008")


@pytest.mark.parametrize("bad", ["003.008", "RFB003.008", "RFB 3.8", "RFB 003.0080", "rfb 003.008"])
def test_anything_that_is_not_a_greeting_is_refused(bad):
    with pytest.raises(SystemExit):
        parse_versions(bad)
