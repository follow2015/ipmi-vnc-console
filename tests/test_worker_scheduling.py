"""Scheduling races must be resolved when claiming, not when listing workers."""
import asyncio
import os
import uuid

import pytest

from kvmhub.platform.bus import AssemblyBus
from kvmhub.platform.redis_state import MemoryState, RedisState, WORKER_PREFIX


def test_concurrent_claims_never_exceed_worker_capacity():
    async def run():
        bus = AssemblyBus(MemoryState())
        await bus.register_worker('w1', instance_id='i1', capacity=3)
        results = await asyncio.gather(*(bus.claim_session('w1', f's{i}', 60) for i in range(40)))
        assert sum(results) == 3
        assert await bus.worker_load('w1') == 3
    asyncio.run(run())


def test_drain_survives_heartbeats_and_does_not_remove_existing_claims():
    async def run():
        bus = AssemblyBus(MemoryState())
        await bus.register_worker('w1', instance_id='i1', capacity=3)
        await bus.register_worker('w2', instance_id='i2', capacity=3)
        assert await bus.claim_session('w1', 'existing', 60)
        await bus.set_draining('w1', True, actor='operator')
        await bus.register_worker('w1', instance_id='i1', capacity=3)
        assert (await bus.workers())['w1']['draining']
        assert not await bus.claim_session('w1', 'new', 60)
        assert await bus.claims('w1') == ['existing']
        assert (await bus.choose_worker())['worker_id'] == 'w2'
        await bus.set_draining('w1', False, actor='operator')
        assert await bus.claim_session('w1', 'new', 60)
    asyncio.run(run())


def test_concurrent_assembly_consumers_have_one_winner():
    async def run():
        bus = AssemblyBus(MemoryState())
        await bus.put_assembly('sid', {'plan': {}})
        results = await asyncio.gather(*(bus.take_assembly('sid') for _ in range(40)))
        assert sum(result is not None for result in results) == 1
    asyncio.run(run())


@pytest.mark.skipif(not os.environ.get('KVMHUB_TEST_REDIS_URL'),
                    reason='set KVMHUB_TEST_REDIS_URL to run real Redis concurrency checks')
def test_real_redis_claim_consumption_and_drain_are_atomic():
    async def run():
        state = RedisState(os.environ['KVMHUB_TEST_REDIS_URL'])
        bus = AssemblyBus(state)
        suffix = uuid.uuid4().hex[:12]
        worker_id, assembly_sid = 'w' + suffix, 'assembly-' + suffix
        session_ids = [f'{suffix}-{i}' for i in range(100)]
        try:
            await bus.register_worker(worker_id, instance_id=suffix, capacity=3)
            claims = await asyncio.gather(*(bus.claim_session(worker_id, sid, 60) for sid in session_ids))
            assert sum(claims) == 3
            assert await bus.worker_load(worker_id) == 3
            await bus.put_assembly(assembly_sid, {'plan': {'probe': True}})
            deliveries = await asyncio.gather(*(bus.take_assembly(assembly_sid) for _ in range(100)))
            assert sum(item is not None for item in deliveries) == 1
            await bus.set_draining(worker_id, True, actor='test')
            await bus.release_session(worker_id, session_ids[claims.index(True)])
            assert not await bus.claim_session(worker_id, 'new-' + suffix, 60)
            await bus.register_worker(worker_id, instance_id=suffix, capacity=3)
            assert (await bus.workers())[worker_id]['draining']
            await bus.set_draining(worker_id, False, actor='test')
            assert await bus.claim_session(worker_id, 'new-' + suffix, 60)
        finally:
            for sid in session_ids + ['new-' + suffix]:
                await bus.release_session(worker_id, sid)
            await bus.delete_assembly(assembly_sid)
            await state.delete('kvmhub:drain:' + worker_id)
            await state.delete(WORKER_PREFIX + worker_id)
            await state.close()
    asyncio.run(run())
