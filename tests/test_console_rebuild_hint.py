"""M3 stage 1, page half: during a rebuild the operator must be told what it is."""
from __future__ import annotations

import time
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from kvmhub.recovery import RecoveryPolicy, RecoveryState
from kvmhub.session_state import Phase
from kvmhub.worker import REAL_CONSOLE_JS, Gateway, Runtime, wire_recovery


@pytest.fixture(scope="module")
def cfg(tmp_path_factory):
    directory = tmp_path_factory.mktemp("gateway")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    path = directory / "public.pem"
    path.write_bytes(key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    return {"public_key": str(path)}


class RebuildingAdapter:

    supports_upstream_recovery = True

    def __init__(self, attempts: int = 1, recoveries: int = 0) -> None:
        self.recovery = RecoveryPolicy()
        state = RecoveryState(self.recovery)
        state.state = "recovering"
        state.attempts = attempts
        state.recoveries = recoveries
        self.session = SimpleNamespace(recovery=state)


def live_session(cfg, adapter, sid="a" * 32):
    gateway = Gateway(cfg)
    sess = Runtime(sid, "hash", adapter, time.monotonic() + 30)
    sess.machine.to(Phase.LIVE, "activated")
    sess.telemetry.note_connection(adapter)
    gateway.sessions[sid] = sess
    return gateway, sess


def test_stats_describes_the_rebuild_with_its_budget(cfg):
    gateway, sess = live_session(cfg, RebuildingAdapter())

    body = gateway.stats(sess)

    assert body["recovery"] == {"state": "recovering", "attempts": 1, "recoveries": 0,
                                "limit": 2, "max_total": 3}
    assert body["session"]["state"] == "recovering"
    assert body["machine"]["phase"] == "reconnecting"
    assert set(body["recovery"]) == {"state", "attempts", "recoveries", "limit", "max_total"}


def test_the_rebuild_block_carries_no_text_a_scrape_could_use(cfg):
    adapter = RebuildingAdapter()
    adapter.session.recovery.last_error = "upstream_unresponsive"
    gateway, sess = live_session(cfg, adapter, sid="b" * 32)

    body = gateway.stats(sess)

    assert "upstream_unresponsive" not in repr(body["recovery"])
    assert all(not isinstance(value, str) or value == "recovering"
               for value in body["recovery"].values())


def test_the_budget_comes_from_the_wired_policy(cfg):
    adapter = RebuildingAdapter()
    policy = RecoveryPolicy(attempts=4, max_total=9)
    wire_recovery(adapter, policy)
    adapter.session.recovery = RecoveryState(policy)
    adapter.session.recovery.state = "recovering"
    adapter.session.recovery.attempts = 1
    gateway, sess = live_session(cfg, adapter, sid="d" * 32)

    body = gateway.stats(sess)

    assert body["recovery"] == {"state": "recovering", "attempts": 1, "recoveries": 0,
                                "limit": 4, "max_total": 9}


def test_an_unwired_adapter_recovers_nothing(cfg):
    adapter = RebuildingAdapter()
    adapter.recovery = None
    adapter.session.recovery = None
    gateway, sess = live_session(cfg, adapter, sid="e" * 32)

    assert gateway.stats(sess)["recovery"] is None


def test_a_session_without_recovery_reports_none_instead_of_zeroes(cfg):
    gateway, sess = live_session(cfg, None, sid="c" * 32)

    body = gateway.stats(sess)

    assert body["recovery"] is None
    assert body["session"]["state"] == "live"


def test_the_page_says_the_gateway_is_rebuilding_and_names_the_attempt():
    assert "网关正在重建上游控制台" in REAL_CONSOLE_JS
    assert "recovery.limit" in REAL_CONSOLE_JS
    assert "recovery.attempts" in REAL_CONSOLE_JS


def test_the_page_only_polls_while_it_is_retrying_and_stops_when_the_picture_returns():
    start = REAL_CONSOLE_JS.index("if (rec.attempts > 0) {")
    assert "watchGateway();" in REAL_CONSOLE_JS[start:start + 400], \
        "the retry page load is the only place the watcher starts"
    assert "askThenConnect();" in REAL_CONSOLE_JS[start:], \
        "a first page load still probes limits instead of polling stats"
    assert "GATEWAY_POLLS_MAX" in REAL_CONSOLE_JS
    assert "GATEWAY_POLL_MS" in REAL_CONSOLE_JS
    assert "if (health.state === 'normal') return;" in REAL_CONSOLE_JS
    assert REAL_CONSOLE_JS.count("stopGatewayWatch();") >= 4


def test_the_page_keeps_its_own_retry_counters_when_the_gateway_is_silent():
    assert "正在重连 '" in REAL_CONSOLE_JS
    assert "catch(function () {})" in REAL_CONSOLE_JS
