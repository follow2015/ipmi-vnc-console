"""M3 invariants I1–I5, driven by deterministic calls instead of luck."""
import asyncio
import time

import aiohttp
import pytest

from kvmhub.session_state import ALLOWED, Phase, SessionMachine
from kvmhub.worker import Gateway, Runtime
from tools.bootstrap import generate


@pytest.fixture
def cfg(tmp_path):
    directory = generate(tmp_path / "identity")
    import json
    return json.loads((directory / "worker.json").read_text())


class Adapter:
    def __init__(self, cleaned=True):
        self.closed = 0
        self.cleaned = cleaned

    async def close(self):
        self.closed += 1
        return self.cleaned


def gateway_with(cfg, sess):
    gateway = Gateway(cfg)
    gateway.sessions[sess.sid] = sess
    return gateway


def captured(gateway):
    sent = []

    async def call(sid, operation, data=None):
        sent.append((operation, data))
        return {"ok": True}

    gateway.call = call
    return sent



async def test_i1_and_i2_finish_and_adapter_close_happen_exactly_once(cfg):
    adapter = Adapter()
    sess = Runtime("sid-i1", "hash", adapter, time.monotonic() + 30)
    gateway = gateway_with(cfg, sess)
    sent = captured(gateway)

    await asyncio.gather(gateway.finish(sess, "client_closed"),
                         gateway.finish(sess, "lease_expired"))
    await gateway.finish(sess, "client_closed")

    assert adapter.closed == 1
    assert [op for op, _ in sent] == ["finish"]
    assert sess.machine.phase is Phase.ENDED



async def test_i3_an_ended_session_is_not_reachable_or_revivable(cfg):
    sess = Runtime("sid-i3", "hash", Adapter(), time.monotonic() + 30)
    gateway = gateway_with(cfg, sess)
    captured(gateway)
    await gateway.finish(sess, "revoked")

    assert sess.sid not in gateway.sessions
    assert sess.machine.to(Phase.LIVE, "zombie") is False
    assert sess.machine.to(Phase.RECONNECTING, "zombie") is False
    assert sess.machine.phase is Phase.ENDED



async def test_i4_a_failed_report_stays_pending_instead_of_vanishing(cfg):
    sess = Runtime("sid-i4", "hash", Adapter(), time.monotonic() + 30)
    gateway = gateway_with(cfg, sess)
    gateway.traces[sess.sid] = "trace"

    async def unavailable(*args, **kwargs):
        raise aiohttp.ClientConnectionError()

    gateway.call = unavailable
    await gateway.finish(sess, "upstream_error")

    assert sess.sid in gateway.pending_reports
    assert gateway.pending_reports[sess.sid]["reason"] == "upstream_error"
    assert gateway.pending_reports[sess.sid]["cleanup"] == "confirmed"


async def test_i5_an_unconfirmed_cleanup_is_reported_as_pending(cfg):
    sess = Runtime("sid-i5", "hash", Adapter(cleaned=False), time.monotonic() + 30)
    gateway = gateway_with(cfg, sess)
    sent = captured(gateway)

    await gateway.finish(sess, "client_closed")
    assert sent[0][1]["cleanup"] == "pending"



def test_the_happy_path_counts_rebuild_cycles_not_attempts():
    machine = SessionMachine()
    assert machine.phase is Phase.CONNECTING
    assert machine.to(Phase.LIVE, "activated")
    assert machine.to(Phase.RECONNECTING, "upstream_lost")
    assert machine.to(Phase.RECONNECTING, "still_lost")
    assert machine.to(Phase.LIVE, "upstream_rebuilt")
    assert machine.reconnects == 1
    assert [step["to"] for step in machine.history] == ["live", "reconnecting", "live"]


@pytest.mark.parametrize("source,target", [
    (Phase.CONNECTING, Phase.RECONNECTING),
    (Phase.LIVE, Phase.CONNECTING),
    (Phase.ENDED, Phase.LIVE),
    (Phase.ENDED, Phase.RECONNECTING),
])
def test_an_edge_nobody_modelled_is_refused_and_leaves_the_phase_alone(source, target):
    machine = SessionMachine()
    for step in _path(source):
        assert machine.to(step)
    assert target not in ALLOWED[source]
    assert machine.to(target, "surprise") is False
    assert machine.phase is source


def _path(phase):
    return {Phase.CONNECTING: [],
            Phase.LIVE: [Phase.LIVE],
            Phase.RECONNECTING: [Phase.LIVE, Phase.RECONNECTING],
            Phase.ENDED: [Phase.ENDED]}[phase]


def test_ended_is_terminal_for_every_phase():
    assert ALLOWED[Phase.ENDED] == frozenset()


def test_the_history_is_bounded():
    machine = SessionMachine()
    machine.to(Phase.LIVE)
    for _ in range(60):
        machine.to(Phase.RECONNECTING)
        machine.to(Phase.LIVE)
    assert len(machine.history) <= 24


def test_stats_reports_the_machine_phase_alongside_the_old_state(cfg):
    class Recovering:
        state = "recovering"

    adapter = Adapter()
    adapter.recovery = Recovering()
    sess = Runtime("sid-stats", "hash", adapter, time.monotonic() + 30)
    gateway = gateway_with(cfg, sess)
    sess.machine.to(Phase.LIVE)

    stats = gateway.stats(sess)
    assert stats["machine"]["phase"] == "reconnecting"
    assert stats["session"]["state"] in ("live", "recovering", "closing")

    adapter.recovery.state = "relaying"
    assert gateway.stats(sess)["machine"]["phase"] == "live"
    assert sess.machine.reconnects == 1
