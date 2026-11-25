"""V1 session coordinator: decoded ops, request-driven output and G1 resync."""
from __future__ import annotations

import asyncio

import pytest

from kvmhub.video.framebuffer import Rect
from kvmhub.video.runtime import (ManagedDecoder, VideoBudget, VideoBudgetError,
                                  VideoProtocolError, VideoResyncRequired)
from kvmhub.video.session import VideoSession
from kvmhub.video.synthetic import jpeg_block

NONCE = b'0123456789abcdef'


def test_source_updates_only_reach_clients_that_requested_them():
    header, source = jpeg_block()

    async def run():
        session = VideoSession(decoder=ManagedDecoder(
            nonce=NONCE, require_hard_cpu_limit=False))
        await session.open(64, 64, header)
        session.attach('browser-1')
        try:
            session.request('browser-1', Rect(0, 0, 64, 64), incremental=False)
            assert session.prepare('browser-1') is None

            update = await session.feed(source)
            assert (update.epoch, update.seq) == (1, 1)
            assert session.framebuffer.snapshot(Rect(0, 0, 64, 64)) is not None
            batch = session.prepare('browser-1')
            assert batch is not None and len(batch.snapshots) == 1
            messages = list(session.messages('browser-1', batch))
            assert messages and all(len(message) <= 65536 for message in messages)
            session.sent('browser-1', batch)

            session.request('browser-1', Rect(0, 0, 64, 64), incremental=True)
            assert session.prepare('browser-1') is None

            await session.feed(source)
            session.request('browser-1', Rect(0, 0, 64, 64), incremental=True)
            batch = session.prepare('browser-1')
            assert batch is not None
            session.sent('browser-1', batch)
        finally:
            session.close()

    asyncio.run(run())


def test_shadow_framebuffer_and_staged_bytes_are_accounted():
    header, source = jpeg_block()

    async def run():
        session = VideoSession(decoder=ManagedDecoder(
            nonce=NONCE, require_hard_cpu_limit=False))
        await session.open(64, 64, header)
        ledger = session.decoder.ledger
        assert ledger.memory == 64 * 64 * 5
        session.attach('browser-1')
        session.request('browser-1', Rect(0, 0, 64, 64), incremental=False)
        await session.feed(source)
        batch = session.prepare('browser-1')
        staged = list(session.messages('browser-1', batch))
        staged_bytes = sum(len(message) for message in staged)
        assert staged_bytes > 0
        assert ledger.memory == 64 * 64 * 9 + staged_bytes
        session.sent('browser-1', batch)
        assert ledger.memory == 64 * 64 * 5
        session.detach('browser-1')
        session.close()
        assert ledger.memory == 0

    asyncio.run(run())


def test_a_client_that_stops_reading_is_refused_without_hurting_others():
    header, source = jpeg_block()

    async def run():
        session = VideoSession(decoder=ManagedDecoder(
            nonce=NONCE, require_hard_cpu_limit=False))
        await session.open(64, 64, header)
        session.decoder.budget = VideoBudget(max_output_bytes=1)
        session.attach('slow')
        session.attach('fast')
        session.request('slow', Rect(0, 0, 64, 64), incremental=False)
        await session.feed(source)
        batch = session.prepare('slow')
        with pytest.raises(VideoBudgetError, match='output_queue_budget'):
            list(session.messages('slow', batch))
        assert session.queued['slow'] == 0
        assert session.queued['fast'] == 0
        session.close()

    asyncio.run(run())


def test_a_rejected_update_invalidates_the_epoch_and_requires_a_permit():
    header, source = jpeg_block()
    calls = []

    async def hook():
        calls.append('recover')

    async def run():
        decoder = ManagedDecoder(nonce=NONCE, require_hard_cpu_limit=False,
                                 before_resync=hook, require_resync_permit=True)
        session = VideoSession(decoder=decoder)
        await session.open(64, 64, header)
        session.framebuffer.seq = 5
        with pytest.raises(VideoProtocolError, match='video_update_rejected'):
            await session.feed(source)
        assert decoder.epoch == 0 and decoder.permit_pending
        with pytest.raises(VideoResyncRequired):
            await session.feed(source)
        assert calls == []
        assert await session.resync(64, 64, header) == 1
        assert calls == ['recover']
        assert (await session.feed(source)).epoch == 1
        session.close()

    asyncio.run(run())


def test_crashed_decoder_cannot_resync_without_a_managed_permit():
    header, source = jpeg_block()
    calls = []

    async def hook():
        calls.append('recover')

    async def run():
        decoder = ManagedDecoder(nonce=NONCE, require_hard_cpu_limit=False,
                                 before_resync=hook, require_resync_permit=True)
        session = VideoSession(decoder=decoder)
        await session.open(64, 64, header)
        session.attach('browser-1')
        decoder.invalidate('synthetic_crash')
        with pytest.raises(VideoResyncRequired):
            await session.feed(source)
        assert calls == []

        assert await session.resync(64, 64, header) == 1
        assert calls == ['recover']
        assert session.streams['browser-1'].epoch == 1
        assert (await session.feed(source)).epoch == 1
        session.close()

    asyncio.run(run())


def test_resync_drops_bytes_staged_for_the_dead_epoch():
    header, source = jpeg_block()

    async def run():
        session = VideoSession(decoder=ManagedDecoder(
            nonce=NONCE, require_hard_cpu_limit=False))
        await session.open(64, 64, header)
        session.attach('browser-1')
        session.request('browser-1', Rect(0, 0, 64, 64), incremental=False)
        await session.feed(source)
        batch = session.prepare('browser-1')
        list(session.messages('browser-1', batch))
        assert session.queued['browser-1'] > 0

        await session.resync(64, 64, header)
        assert session.queued['browser-1'] == 0
        assert session.decoder.ledger.memory == 64 * 64 * 5
        await session.feed(source)
        session.request('browser-1', Rect(0, 0, 64, 64), incremental=False)
        fresh = session.prepare('browser-1')
        assert list(session.messages('browser-1', fresh))
        session.sent('browser-1', fresh)
        session.close()

    asyncio.run(run())


@pytest.mark.parametrize('cleanup', ['sent', 'abort', 'detach', 'resync', 'close'])
def test_snapshot_budget_is_shared_and_released(cleanup):
    async def run():
        header, source = jpeg_block()
        base, snapshot_size = 64 * 64 * 5, 64 * 64 * 4
        budget = VideoBudget(max_session_bytes=base * 2)
        session = VideoSession(decoder=ManagedDecoder(
            budget=budget, require_hard_cpu_limit=False))
        try:
            await session.open(64, 64, header)
            await session.feed(source)
            for client in ('a', 'b'):
                session.attach(client)
                session.request(client, Rect(0, 0, 64, 64), incremental=False)
            batch = session.prepare('a')
            assert session.decoder.ledger.memory == base + snapshot_size
            with pytest.raises(VideoBudgetError, match='memory_budget'):
                session.prepare('b')
            assert session.streams['b'].inflight is None
            assert session.decoder.ledger.memory == base + snapshot_size
            if cleanup == 'sent':
                session.sent('a', batch)
            elif cleanup == 'abort':
                session.streams['a'].abort(batch)
            elif cleanup == 'detach':
                session.detach('a')
            elif cleanup == 'resync':
                await session.resync(64, 64, header)
            else:
                session.close()
            assert session.decoder.ledger.memory == (0 if cleanup == 'close' else base)
        finally:
            session.close()
        assert session.decoder.ledger.memory == 0
    asyncio.run(run())


def test_partial_prepare_failure_rolls_back_all_snapshot_reservations(monkeypatch):
    async def run():
        header, source = jpeg_block()
        base = 64 * 64 * 5
        session = VideoSession(decoder=ManagedDecoder(
            budget=VideoBudget(max_session_bytes=base + 64 * 64 * 4),
            require_hard_cpu_limit=False))
        try:
            await session.open(64, 64, header)
            session.attach('client')
            session.request('client', Rect(0, 0, 64, 64), incremental=False)
            assert session.prepare('client') is None
            assert session.decoder.ledger.memory == base
            await session.feed(source)
            session.request('client', Rect(0, 0, 1, 1), incremental=False)
            original = session.framebuffer.snapshot
            allocations = []
            def snapshot(rect):
                allocations.append(rect)
                return original(rect)
            monkeypatch.setattr(session.framebuffer, 'snapshot', snapshot)
            with pytest.raises(VideoBudgetError, match='memory_budget'):
                session.prepare('client')
            assert len(allocations) == 1
            assert session.decoder.ledger.memory == base
            assert session.streams['client'].inflight is None
        finally:
            session.close()
    asyncio.run(run())
