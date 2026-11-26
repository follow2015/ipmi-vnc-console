"""Design §8.1/V12: transcode capacity is reserved atomically and fully undone."""
from __future__ import annotations

import asyncio
import os
import time
import uuid

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from kvmhub.common import Problem
from kvmhub.operation_permit import issue_operation_permit, verify_operation_permit
from kvmhub.platform import services
from kvmhub.platform.bus import TRANSCODE_LANE, AssemblyBus, BusError
from kvmhub.platform.console import ConsolePlane
from kvmhub.platform.redis_state import RESOURCE_PREFIX, MemoryState, RedisState
from kvmhub.store import Store
from kvmhub.video import client_v2
from kvmhub.worker import Gateway

KEY = b"0123456789abcdef0123456789abcdef"
TARGET = "https://192.0.2.11"


def budgets(**overrides):
    values = {"transcode_capacity": 1, "cpu_budget": 2.0, "mem_budget": 2048.0,
              "session_cpu": 1.0, "session_mem": 512.0}
    values.update(overrides)
    return values


def test_memory_reservation_never_yields_between_check_and_write():
    import inspect
    source = inspect.getsource(MemoryState.reserve_worker_resources)
    body = source.split('"""')[-1]
    assert 'await' not in body
    assert body.index('rows[sid] =') > body.index('if sid in rows')


def test_one_budget_per_sid_in_memory_state():
    async def run():
        state = MemoryState()
        result = await asyncio.gather(*(
            state.reserve_worker_resources("w1", f"s{i}", ttl=60, capacity=1,
                                           cpu_budget=2.0, mem_budget=2048.0,
                                           cpu_need=1.0, mem_need=512.0)
            for i in range(40)))
        assert sum(result) == 1
        used = await state.worker_resources("w1")
        assert used["count"] == 1
        assert used["cpu"] == 1.0 and used["mem"] == 512.0
        winner = used["sids"][0]
        assert not await state.reserve_worker_resources(
            "w1", winner, ttl=60, capacity=1, cpu_budget=2.0,
            mem_budget=2048.0, cpu_need=1.0, mem_need=512.0)
        await state.release_worker_resources("w1", winner)
        assert (await state.worker_resources("w1"))["count"] == 0
    asyncio.run(run())


@pytest.mark.skipif(not os.environ.get('KVMHUB_TEST_REDIS_URL'),
                    reason='set KVMHUB_TEST_REDIS_URL to exercise the Lua reservation')
def test_real_redis_decode_budget_is_atomic():
    async def run():
        state = RedisState(os.environ['KVMHUB_TEST_REDIS_URL'])
        worker_id = 'w' + uuid.uuid4().hex[:10]
        try:
            result = await asyncio.gather(*(
                state.reserve_worker_resources(worker_id, f's{i}', ttl=60, capacity=1,
                                               cpu_budget=2.0, mem_budget=2048.0,
                                               cpu_need=1.0, mem_need=512.0)
                for i in range(40)))
            assert sum(result) == 1
            assert (await state.worker_resources(worker_id))['count'] == 1
        finally:
            zkey, hkey = state._resource_keys(worker_id)
            await state.delete(zkey)
            await state.delete(hkey)
            await state.close()
    asyncio.run(run())


def test_cpu_budget_rejects_a_second_session_before_slot_count():
    async def run():
        state = MemoryState()
        assert await state.reserve_worker_resources(
            "w1", "s1", ttl=60, capacity=4, cpu_budget=1.5, mem_budget=4096.0,
            cpu_need=1.0, mem_need=512.0)
        assert not await state.reserve_worker_resources(
            "w1", "s2", ttl=60, capacity=4, cpu_budget=1.5, mem_budget=4096.0,
            cpu_need=1.0, mem_need=512.0)
        assert (await state.worker_resources("w1"))["sids"] == ["s1"]
    asyncio.run(run())


IDENTITY = {"recipe_id": "r1", "recipe_revision": "2",
            "protocol_contract": "console-rfb/1", "schema_version": "v1"}


def test_lane_version_and_heartbeat_freshness_filter_workers():
    async def run():
        clock = [1000.0]
        state = MemoryState(clock=lambda: clock[0])
        bus = AssemblyBus(state, clock=lambda: clock[0])
        meta = {"address": "127.0.0.1", "port": 9443, "lane": TRANSCODE_LANE,
                **IDENTITY, **budgets()}
        await bus.register_worker("decoder", instance_id="i1", capacity=4, metadata=meta)
        await bus.register_worker("plain", instance_id="i2", capacity=4,
                                  metadata={"address": "127.0.0.1", "port": 9443})
        requirements = {"lane": TRANSCODE_LANE, "versions": dict(IDENTITY)}
        assert (await bus.choose_worker(requirements))["worker_id"] == "decoder"
        with pytest.raises(BusError) as wrong:
            await bus.choose_worker({**requirements,
                                     "versions": {**IDENTITY, "recipe_id": "r2"}})
        assert wrong.value.code == "pipeline_version_unavailable"
        assert await bus.claim_session("decoder", "already-live", 60)
        clock[0] += 20
        with pytest.raises(BusError) as stale:
            await bus.choose_worker({**requirements, "max_worker_age": 10})
        assert stale.value.code == "worker_capacity_exhausted"
        assert await bus.claims("decoder") == ["already-live"]
    asyncio.run(run())


def test_a_lane_worker_without_budgets_is_a_version_fault_not_capacity():
    async def run():
        bus = AssemblyBus(MemoryState())
        await bus.register_worker("half", instance_id="i1", capacity=4,
                                  metadata={"address": "127.0.0.1", "port": 9443,
                                            "lane": TRANSCODE_LANE, **IDENTITY})
        with pytest.raises(BusError) as exc:
            await bus.choose_worker({"lane": TRANSCODE_LANE, "versions": dict(IDENTITY)})
        assert exc.value.code == "pipeline_version_unavailable"
    asyncio.run(run())


class _Authority:

    def __init__(self, key):
        self.key = key

    async def authorize(self, *, operation, host, **fields):
        stamp = time.time()
        token = issue_operation_permit(
            self.key, operation=operation, sid=fields["sid"], asset_id=fields["asset_id"],
            tenant_id=fields["tenant_id"], user_id=fields["user_id"],
            domain_id=fields["domain_id"], worker_id=fields["worker_id"],
            instance_id=fields["instance_id"],
            connection_revision=fields["connection_revision"],
            admission_revision=fields["admission_revision"],
            digest=fields["digest"], generation=fields["generation"],
            lease_not_after=stamp + 60, now=stamp)
        return {"permit": token,
                "claims": verify_operation_permit(self.key.public_key(), token, now=stamp)}


def _plane(tmp_path, bus):
    key = Ed25519PrivateKey.generate()
    store = Store(str(tmp_path / "capacity.db"), KEY, passthrough_targets=(TARGET,))
    store.seed_mock("192.0.2.11:5900", "0" * 64, "synthetic", "synthetic")
    plane = ConsolePlane(store=store, private_key=Ed25519PrivateKey.generate(), bus=bus,
                         authority=_Authority(key), authority_host="authority.internal",
                         permit_public_key=key.public_key(), managed_domains=("dom-1",))
    return store, plane


def _assembly():
    return {"ready": True, "asset_id": "mock-1", "tenant_id": "capacity-tenant",
            "worker_requirements": {"lane": TRANSCODE_LANE, "versions": dict(IDENTITY)},
            "client_contract": client_v2.protocol_contract(),
            "client_bundle": client_v2.client_build(),
            "g0": {"ready": True, "domain_id": "dom-1", "connection_revision": 1,
                   "admission_revision": 1, "digest": "d" * 64, "generation": "g1"}}


async def _assert_no_residue(store, bus):
    assert store.db.execute(
        "SELECT 1 FROM asset_slot WHERE asset_id='mock-1'").fetchone() is None
    assert len(await bus.claims("w1")) == 0
    assert await bus.tenant_quota_usage("capacity-tenant") == 0
    assert (await bus.worker_resources("w1"))["count"] == 0


def test_an_authority_refusal_becomes_a_platform_error_not_a_bare_problem(tmp_path):
    bus = AssemblyBus(MemoryState())
    store, plane = _plane(tmp_path, bus)

    class _Refusing:
        async def authorize(self, *, host, **fields):
            raise Problem("device_not_admitted", 403)

    async def run():
        await bus.register_worker("w1", instance_id="i1", capacity=4,
                                  metadata={"address": "127.0.0.1", "port": 9443,
                                            "lane": TRANSCODE_LANE, **IDENTITY,
                                            **budgets()})
        plane.authority = _Refusing()
        with pytest.raises(services.PlatformError) as caught:
            await plane.open(_assembly(), user_id="local-admin", concurrent_limit=1)
        assert caught.value.code == "device_not_admitted"
        assert caught.value.status == 403
        assert caught.value.message != "device_not_admitted"
        await _assert_no_residue(store, bus)

    asyncio.run(run())
    store.close()


def test_refused_transcode_reservation_compensates_everything(tmp_path):
    bus = AssemblyBus(MemoryState())
    store, plane = _plane(tmp_path, bus)

    async def run():
        await bus.register_worker("w1", instance_id="i1", capacity=4,
                                  metadata={"address": "127.0.0.1", "port": 9443,
                                            "lane": TRANSCODE_LANE, **IDENTITY,
                                            **budgets()})
        original = bus.reserve_worker_resources

        async def refused(*args, **kwargs):
            return False

        bus.reserve_worker_resources = refused
        try:
            with pytest.raises(services.PlatformError) as exc:
                await plane.open(_assembly(), user_id="local-admin", concurrent_limit=1)
        finally:
            bus.reserve_worker_resources = original
        assert exc.value.code == "transcode_capacity_exhausted"
        assert exc.value.status == 429
        await _assert_no_residue(store, bus)

    asyncio.run(run())
    store.close()


def test_publish_failure_after_reservation_releases_the_decode_slot(tmp_path):
    bus = AssemblyBus(MemoryState())
    store, plane = _plane(tmp_path, bus)

    async def run():
        await bus.register_worker("w1", instance_id="i1", capacity=4,
                                  metadata={"address": "127.0.0.1", "port": 9443,
                                            "lane": TRANSCODE_LANE, **IDENTITY,
                                            **budgets()})
        original = bus.put_assembly

        async def failing(*args, **kwargs):
            raise RuntimeError("synthetic Redis failure")

        bus.put_assembly = failing
        try:
            with pytest.raises(RuntimeError):
                await plane.open(_assembly(), user_id="local-admin", concurrent_limit=1)
        finally:
            bus.put_assembly = original
        await _assert_no_residue(store, bus)

    asyncio.run(run())
    store.close()


def test_managed_open_reserves_one_decode_slot_and_publishes_the_lane(tmp_path):
    bus = AssemblyBus(MemoryState())
    store, plane = _plane(tmp_path, bus)

    async def run():
        await bus.register_worker("w1", instance_id="i1", capacity=4,
                                  metadata={"address": "127.0.0.1", "port": 9443,
                                            "lane": TRANSCODE_LANE, **IDENTITY,
                                            **budgets()})
        result = await plane.open(_assembly(), user_id="local-admin", concurrent_limit=1)
        used = await bus.worker_resources("w1")
        assert used["count"] == 1 and used["sids"] == [result["sid"]]
        document = await bus.peek_assembly(result["sid"])
        assert document["lane"] == TRANSCODE_LANE
        assert document["pipeline_versions"] == IDENTITY
        assert document["client_contract"] == client_v2.protocol_contract()
        assert document["client_bundle"] == client_v2.client_build()
        assert len(document["binding"]) == 64

    asyncio.run(run())
    store.close()


def test_lane_outside_a_managed_domain_is_refused_before_routing(tmp_path):
    bus = AssemblyBus(MemoryState())
    store, plane = _plane(tmp_path, bus)
    plane.managed_domains = ()

    async def run():
        with pytest.raises(services.PlatformError) as exc:
            await plane.open(_assembly(), user_id="local-admin", concurrent_limit=1)
        assert exc.value.code == "pipeline_version_unavailable"
        assert exc.value.status == 503
        await _assert_no_residue(store, bus)

    asyncio.run(run())
    store.close()


def test_worker_accept_rechecks_lane_versions_binding_and_local_capacity():
    gateway = object.__new__(Gateway)
    gateway.transcode_lane = TRANSCODE_LANE
    gateway.transcode_capacity = 1
    gateway.transcode_reserved = set()
    gateway.lane_identity = dict(IDENTITY)
    binding = "b" * 64

    gateway._admit_transcode_lane("s1", TRANSCODE_LANE, dict(IDENTITY), binding=binding)
    assert gateway.transcode_reserved == {"s1"}
    with pytest.raises(Problem) as full:
        gateway._admit_transcode_lane("s2", TRANSCODE_LANE, dict(IDENTITY), binding=binding)
    assert full.value.code == "transcode_capacity_exhausted"
    with pytest.raises(Problem) as wrong:
        gateway._admit_transcode_lane("s2", TRANSCODE_LANE,
                                      {**IDENTITY, "protocol_contract": "console-rfb/2"},
                                      binding=binding)
    assert wrong.value.code == "pipeline_version_unavailable"
    with pytest.raises(Problem) as extra:
        gateway._admit_transcode_lane("s2", TRANSCODE_LANE,
                                      {**IDENTITY, "recipe_flags": "x"}, binding=binding)
    assert extra.value.code == "pipeline_version_unavailable"
    with pytest.raises(Problem) as unbound:
        gateway._admit_transcode_lane("s2", TRANSCODE_LANE, dict(IDENTITY))
    assert unbound.value.code == "pipeline_version_unavailable"
    gateway.transcode_reserved.discard("s1")
    gateway._admit_transcode_lane("s3", TRANSCODE_LANE, dict(IDENTITY), binding=binding)
    assert gateway.transcode_reserved == {"s3"}
