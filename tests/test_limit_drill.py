"""The admission drill must prove clean refusal, not just the right error code."""
from __future__ import annotations

import asyncio
import json

from tools.limit_drill import run


def test_all_three_limits_refuse_cleanly_and_recover(tmp_path):
    report = asyncio.run(run(tmp_path))
    assert report["all_green"], report["assertions"]
    scenarios = report["scenarios"]
    assert scenarios["asset_exclusivity"]["second_code"] == "asset_busy"
    assert scenarios["tenant_quota"]["second_code"] == "quota_exceeded"
    assert scenarios["worker_capacity"]["second_code"] == "worker_capacity_exhausted"
    for scenario in scenarios.values():
        assert scenario["after_refusal"] == {"pending_sessions": 1, "asset_slots": 1}
        assert scenario["recovered_after_close"] is True


def test_report_carries_no_ticket_sid_address_or_credential(tmp_path):
    report = asyncio.run(run(tmp_path))
    text = json.dumps(report, ensure_ascii=False)
    for forbidden in ("ticket", "sid", "127.0.0.1:5900", "synthetic-password", "drill.sqlite"):
        assert forbidden not in text, forbidden
