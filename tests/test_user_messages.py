"""Codes stay the contract; the sentence next to them is for the operator."""
from __future__ import annotations

import re
from pathlib import Path

from kvmhub import store
from kvmhub.common import (END_REASON_MESSAGES, ERROR_STATUS, USER_MESSAGES,
                           end_reason_message, user_message)


def test_a_busy_asset_says_what_to_do():
    assert "稍后重试" in user_message("asset_busy")


def test_every_message_belongs_to_a_real_code():
    assert set(USER_MESSAGES) <= set(ERROR_STATUS)


def test_unknown_codes_get_no_sentence_rather_than_a_made_up_one():
    assert user_message("some_future_code") is None



def test_every_session_end_reason_has_a_sentence():
    missing = [reason for reason in store.END_REASONS if end_reason_message(reason) is None]
    assert missing == []


def test_every_reason_the_store_writes_has_a_sentence():
    source = Path(store.__file__).read_text(encoding="utf-8")
    written = set(re.findall(r"reason='([a-z_]+)'", source))
    assert {"manual_release", "deadline"} <= written, "the scan must still find reasons"
    assert sorted(reason for reason in written if end_reason_message(reason) is None) == []


def test_unknown_reasons_get_no_sentence_rather_than_a_made_up_one():
    assert end_reason_message("some_future_reason") is None
    assert "some_future_reason" not in END_REASON_MESSAGES
