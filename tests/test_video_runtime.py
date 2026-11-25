"""V1 runtime offline invariants: strict IPC, budgets and process lifecycle."""
import asyncio
import os
import time
import struct

import pytest

from kvmhub.video.runtime import (MAX_INPUT_BYTES, MAX_UPDATE_BYTES,
                                  BudgetLedger, ManagedDecoder, Message,
                                  OutputQueue, READY, SIGNAL, VideoBudget,
                                  VideoBudgetError, VideoProtocolError,
                                  VideoResyncRequired, VideoUnsupported,
                                  decode_message, encode_message,
                                  hard_cpu_limit_supported)
from kvmhub.video.synthetic import jpeg_block
from kvmhub.video.wire import unpack_update

NONCE = b'0123456789abcdef'


@pytest.mark.parametrize('kind,rect,tail', [
    (1, (64, 0, 1, 1), struct.pack('>I', 4) + b'\0' * 4),
    (1, (0, 0, 0, 1), struct.pack('>I', 0)),
    (3, (0, 0, 1, 1), struct.pack('>II', 64, 0)),
])
def test_invalid_wire_geometry_requires_new_recovery_permit(monkeypatch, kind, rect, tail):
    decoder = ManagedDecoder(
        budget=VideoBudget(max_width=64, max_height=64),
        require_hard_cpu_limit=False, require_resync_permit=True)
    decoder.epoch = 1
    decoder.needs_resync = False
    payload = struct.pack('>III', 1, 1, 1) + struct.pack('>IIIIB', *rect, kind) + tail
    monkeypatch.setattr(decoder, 'decode', lambda _: Message(1, 1, SIGNAL, payload))
    with pytest.raises(VideoProtocolError, match='video_rect_invalid'):
        decoder.decode_update(b'')
    assert decoder.epoch == 0 and decoder.needs_resync and decoder.permit_pending
    with pytest.raises(VideoResyncRequired, match='video_resync_permit_missing'):
        asyncio.run(decoder.resync(64, 64))


def test_v9_ipc_header_identity_and_kind_mutations_are_rejected():
    raw = encode_message(NONCE, Message(3, 7, SIGNAL, b'abc'))
    assert decode_message(raw, NONCE) == Message(3, 7, SIGNAL, b'abc')
    bad = [
        (raw[:0] + b'X' + raw[1:], 'version_invalid'),
        (raw[:4] + b'\x02' + raw[5:], 'version_invalid'),
        (raw[:5] + b'x' + raw[6:], 'session_invalid'),
        (raw[:29] + b'\x63' + raw[30:], 'header_invalid'),
        (raw[:30] + b'\x64' + raw[31:], 'length_invalid'),
        (raw[:-1], 'payload_truncated'),
    ]
    for payload, reason in bad:
        with pytest.raises(VideoProtocolError, match=reason):
            decode_message(payload, NONCE)
    with pytest.raises(VideoProtocolError, match='session_invalid'):
        decode_message(raw, b'f' * 16)
    with pytest.raises(VideoProtocolError, match='kind_invalid'):
        encode_message(NONCE, Message(1, 1, 99, b''))
    with pytest.raises(VideoProtocolError, match='payload_invalid'):
        encode_message(NONCE, Message(1, 1, SIGNAL, b'x' * (MAX_UPDATE_BYTES + 1)))


def test_v10_geometry_rect_payload_memory_and_cumulative_input_budgets():
    budget = VideoBudget()
    budget.check_geometry(4096, 2160)
    for width, height in ((0, 1), (4097, 1), (4096, 2161)):
        with pytest.raises(ValueError):
            budget.check_geometry(width, height)
    with pytest.raises(VideoBudgetError, match='rects_budget'):
        budget.check_event(4097, 0)
    with pytest.raises(VideoBudgetError, match='payload_budget'):
        budget.check_event(0, MAX_UPDATE_BYTES + 1)
    ledger = BudgetLedger(budget)
    ledger.reserve(budget.max_session_bytes)
    with pytest.raises(VideoBudgetError, match='memory_budget'):
        ledger.reserve(1)
    ledger.release(budget.max_session_bytes)
    with pytest.raises(VideoBudgetError, match='input_budget'):
        ledger.begin_input(MAX_INPUT_BYTES + 1)
    ledger.begin_input(4)
    with pytest.raises(VideoBudgetError, match='decode_in_progress'):
        ledger.begin_input(1)
    ledger.end_input()
    ledger.begin_input(6)
    ledger.end_input()
    assert ledger.input == 10


def test_input_budget_is_enforced_across_updates_not_per_frame():
    budget = VideoBudget(max_total_input_bytes=10 * 1024 * 1024)
    ledger = BudgetLedger(budget)
    for _ in range(4):
        ledger.begin_input(2 * 1024 * 1024)
        ledger.end_input()
    with pytest.raises(VideoBudgetError, match='input_budget'):
        ledger.begin_input(3 * 1024 * 1024)


def test_slow_client_budget_and_age_are_per_client():
    now = [100.0]
    budget = VideoBudget()
    fast, slow = OutputQueue(budget, clock=lambda: now[0]), OutputQueue(budget, clock=lambda: now[0])
    slow.enqueue(b'a' * budget.max_output_bytes)
    with pytest.raises(VideoBudgetError, match='output_queue_budget'):
        slow.enqueue(b'b')
    fast.enqueue(b'ok')
    assert fast.drain() == b'ok'
    now[0] += budget.output_age + 0.01
    with pytest.raises(VideoBudgetError, match='output_age'):
        slow.check()


def test_managed_decoder_roundtrip_with_scrubbed_environment():
    decoder = ManagedDecoder(nonce=NONCE, budget=VideoBudget(decode_cpu=5.0),
                             require_hard_cpu_limit=False)
    try:
        ready = decoder.start()
        assert ready.kind == READY and ready.payload.startswith(b'KVIDEO1|')
        assert b'CODEBUDDY' not in ready.payload and b'KVMHUB' not in ready.payload
        header, stream = jpeg_block()
        assert decoder.reset(64, 64, header) == 1
        answer = decoder.decode(stream)
        assert answer.kind == SIGNAL and answer.epoch == 1
        update = unpack_update(answer.payload, limit=(64, 64))
        assert (update.epoch, update.seq) == (1, 1)
        assert len(update.operations) == 1
    finally:
        decoder.close()
    assert not decoder.running


def test_child_error_code_survives_into_last_error_and_invalidates_the_epoch():
    decoder = ManagedDecoder(nonce=NONCE, budget=VideoBudget(decode_cpu=5.0),
                             require_hard_cpu_limit=False)
    try:
        decoder.start()
        decoder.reset(64, 64)
        with pytest.raises(VideoProtocolError,
                           match='video_decode_rejected: video_block_kind_unknown'):
            decoder.decode(b'\xff')
        assert 'video_block_kind_unknown' in decoder.last_error
        assert decoder.needs_resync and decoder.epoch == 0
        with pytest.raises(VideoResyncRequired):
            decoder.decode(b'\xff')
    finally:
        decoder.close()


def test_unparsable_child_output_invalidates_the_epoch_and_asks_for_a_permit(monkeypatch):
    calls = []

    async def hook():
        calls.append('recover')

    def boom(*args, **kwargs):
        raise VideoProtocolError('video_wire_count_invalid')

    monkeypatch.setattr('kvmhub.video.wire.unpack_update', boom)

    async def run():
        decoder = ManagedDecoder(nonce=NONCE, budget=VideoBudget(decode_cpu=5.0),
                                 require_hard_cpu_limit=False,
                                 before_resync=hook, require_resync_permit=True)
        try:
            decoder.start()
            header, stream = jpeg_block()
            decoder.reset(64, 64, header)
            with pytest.raises(VideoProtocolError, match='video_wire_count_invalid'):
                decoder.decode_update(stream)
            assert decoder.epoch == 0 and decoder.permit_pending
            with pytest.raises(VideoResyncRequired):
                decoder.decode_update(stream)
            assert calls == []
            assert await decoder.resync(64, 64, header) == 1
            assert calls == ['recover']
        finally:
            decoder.close()

    asyncio.run(run())


def test_crashed_decoder_requires_full_resync_before_another_decode():
    decoder = ManagedDecoder(nonce=NONCE, require_hard_cpu_limit=False)
    decoder.start()
    decoder.reset(64, 64)
    decoder._kill()
    assert decoder.needs_resync and decoder.epoch == 0
    with pytest.raises(VideoResyncRequired, match='resync_required'):
        decoder.decode(b'')
    decoder.close()


def test_a_child_killed_from_outside_is_reaped_and_can_be_restarted():
    decoder = ManagedDecoder(nonce=NONCE, require_hard_cpu_limit=False)
    decoder.start()
    assert decoder.reset(64, 64) == 1
    decoder.proc.kill()
    deadline = time.time() + 5
    while decoder.proc is not None and decoder.proc.is_alive() and time.time() < deadline:
        time.sleep(0.02)
    assert not decoder.running
    decoder.start()
    assert decoder.reset(64, 64) == 1
    decoder.close()


def test_managed_resync_requires_a_fresh_permit_before_a_new_epoch():
    calls = []

    async def hook():
        calls.append('recover')

    async def run():
        decoder = ManagedDecoder(nonce=NONCE, require_hard_cpu_limit=False,
                                 before_resync=hook, require_resync_permit=True)
        decoder.start()
        decoder.reset(64, 64)
        decoder._failed('synthetic_crash')
        assert decoder.permit_pending
        with pytest.raises(VideoResyncRequired, match='video_resync_permit_missing'):
            decoder.reset(64, 64)
        with pytest.raises(VideoResyncRequired, match='resync_required'):
            decoder.decode(b'')
        assert calls == []
        decoder.close()
        decoder = ManagedDecoder(nonce=NONCE, require_hard_cpu_limit=False,
                                 before_resync=hook, require_resync_permit=True)
        decoder.start()
        decoder.permit_pending = True
        assert await decoder.resync(64, 64) == 1
        assert calls == ['recover']
        decoder._failed('synthetic_second_crash')
        assert decoder.permit_pending
        decoder.close()

    asyncio.run(run())


def test_managed_resync_without_a_hook_is_fail_closed():
    async def run():
        decoder = ManagedDecoder(nonce=NONCE, require_hard_cpu_limit=False,
                                 require_resync_permit=True)
        decoder.start()
        decoder._kill()
        with pytest.raises(VideoResyncRequired, match='video_resync_permit_missing'):
            await decoder.resync(64, 64)
        assert decoder.epoch == 0 and decoder.needs_resync
        decoder.close()
    asyncio.run(run())


def test_hard_cpu_limit_fail_closed_on_unsupported_platform():
    if hard_cpu_limit_supported():
        assert True
    else:
        decoder = ManagedDecoder()
        with pytest.raises(VideoUnsupported, match='hard_cpu_limit_unavailable'):
            decoder.start()
        assert os.name == 'nt'


def test_session_cpu_limit_is_a_lifetime_budget_not_a_frame_budget():
    budget = VideoBudget()
    assert budget.decode_session_cpu > budget.decode_cpu * 10
    with pytest.raises(VideoBudgetError, match='video_budget_invalid'):
        VideoBudget(decode_cpu=10.0, decode_session_cpu=10.0)
