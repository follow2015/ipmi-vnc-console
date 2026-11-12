"""Codes stay the contract; the sentence next to them is for the operator."""
from __future__ import annotations

from kvmhub.common import ERROR_STATUS, USER_MESSAGES, user_message


def test_a_busy_asset_says_what_to_do():
    assert "稍后重试" in user_message("asset_busy")


def test_every_message_belongs_to_a_real_code():
    assert set(USER_MESSAGES) <= set(ERROR_STATUS)


def test_unknown_codes_get_no_sentence_rather_than_a_made_up_one():
    assert user_message("some_future_code") is None
