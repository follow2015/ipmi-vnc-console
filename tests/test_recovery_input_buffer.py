"""M3 stage 2: during a rebuild keep the releases, drop the presses, stay bounded."""
import asyncio
from types import SimpleNamespace

import pytest

from kvmhub.common import Problem
from kvmhub.insyde_messages import build_key_event
from kvmhub.passthrough import RfbPassthroughSession
from kvmhub.recovery import RecoveryPolicy


class Sink:
    def __init__(self, fail=False):
        self.sent = []
        self.fail = fail
        self.upstream_close_code = None

    async def send_raw(self, data):
        if self.fail:
            raise Problem("upstream_unavailable", 502)
        self.sent.append(bytes(data))


def session(sink=None, *, policy=True):
    sink = sink or Sink()
    return RfbPassthroughSession(
        sink, SimpleNamespace(completed=True, shared=False),
        recovery=RecoveryPolicy() if policy else None), sink


def rebuild(sess):
    sess.recovery.begin()
    assert sess.recovery.state == "recovering"


def test_a_release_is_kept_and_a_press_is_not():
    sess, _ = session()
    rebuild(sess)
    down = build_key_event(0x61, True)
    up = build_key_event(0x61, False)
    sess._hold_during_recovery(down)
    sess._hold_during_recovery(up)
    assert sess._recovery_input == [up]
    assert sess.recovery_input_dropped == 1
    assert sess.recovery.dropped_input == 1


def test_a_pointer_move_is_dropped_not_replayed():
    sess, _ = session()
    rebuild(sess)
    sess._hold_during_recovery(b"\x05" + b"\x00" * 17)
    assert sess._recovery_input == []
    assert sess.recovery_input_dropped == 1


def test_the_buffer_is_bounded_at_64_events():
    sess, _ = session()
    rebuild(sess)
    for key in range(200):
        sess._hold_during_recovery(build_key_event(key, False))
    assert len(sess._recovery_input) == RfbPassthroughSession.RECOVERY_INPUT_LIMIT == 64
    assert sess.recovery_input_dropped == 136


def test_replaying_sends_every_held_release_once():
    sess, sink = session()
    rebuild(sess)
    held = [build_key_event(k, False) for k in (0x61, 0xE1, 0xE2)]
    for item in held:
        sess._hold_during_recovery(item)

    asyncio.run(sess._replay_recovery_input())
    assert sink.sent == held
    assert sess.recovery_input_replayed == 3
    assert sess._recovery_input == []
    asyncio.run(sess._replay_recovery_input())
    assert sink.sent == held


def test_a_failed_replay_is_counted_not_raised():
    sess, _ = session(Sink(fail=True))
    rebuild(sess)
    sess._hold_during_recovery(build_key_event(0x61, False))
    asyncio.run(sess._replay_recovery_input())
    assert sess.recovery_input_replayed == 0
    assert sess.recovery_input_dropped == 1
    assert sess.recovery.dropped_input == 1


def test_the_counters_reach_the_session_shape():
    sess, _ = session()
    rebuild(sess)
    sess._hold_during_recovery(build_key_event(0x61, False))
    asyncio.run(sess._replay_recovery_input())
    shape = sess.as_dict()
    assert shape["recovery_input_replayed"] == 1
    assert shape["recovery_input_dropped"] == 0


def test_without_a_policy_a_press_is_still_dropped_and_counted():
    sess, _ = session(policy=False)
    sess._hold_during_recovery(build_key_event(0x61, True))
    assert sess._recovery_input == []
    assert sess.recovery_input_dropped == 1
