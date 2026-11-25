"""Cross-process hand-off between the control plane and the PoC data plane."""
from __future__ import annotations

import os
import time
import uuid
from collections.abc import AsyncIterator

from .redis_state import QUOTA_PREFIX, State, quota_key

ASSEMBLY_PREFIX = "kvmhub:assembly:"
LOAD_PREFIX = "kvmhub:load:"
DRAIN_PREFIX = "kvmhub:drain:"
ROUTE_PREFIX = "kvmhub:route:"
DEFAULT_CAPACITY = 4
DEFAULT_WORKER_TTL = 45
ASSEMBLY_TTL = 120
TRANSCODE_LANE = 'transcode-v1'
LANE_VERSION_KEYS = ('recipe_id', 'recipe_revision', 'protocol_contract', 'schema_version')
DEFAULT_PIPELINE_SCHEMA = 'v1'


def pipeline_identity(environ=None) -> dict:
    env = os.environ if environ is None else environ

    def read(name):
        return str(env.get(name) or '').strip()

    from ..video.client_v2 import client_build, protocol_contract

    return {'lane': read('KVMHUB_WORKER_LANE'),
            'recipe_id': read('KVMHUB_RECIPE_ID'),
            'recipe_revision': read('KVMHUB_RECIPE_REVISION'),
            'protocol_contract': protocol_contract(),
            'schema_version': read('KVMHUB_PIPELINE_SCHEMA') or DEFAULT_PIPELINE_SCHEMA,
            'bundle_revision': read('KVMHUB_BUNDLE_REVISION') or client_build()}


class BusError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code, self.message = code, message


class AssemblyBus:
    def __init__(self, state: State, *, clock=time.time):
        self.state = state
        self._clock = clock

    async def put_assembly(self, sid: str, payload: dict,
                           ttl: int = ASSEMBLY_TTL) -> str:
        if not sid:
            raise BusError("invalid_session", "装配包缺少会话 id")
        document = dict(payload)
        assembly_id = uuid.uuid4().hex
        document["assembly_id"] = assembly_id
        document["issued_at"] = self._clock()
        document.setdefault("credential_id", None)
        for banned in ("password", "username", "credential", "ticket", "cookie"):
            document.pop(banned, None)
        await self.state.put(ASSEMBLY_PREFIX + sid, document, ttl)
        return assembly_id

    async def peek_assembly(self, sid: str) -> dict | None:
        return await self.state.get(ASSEMBLY_PREFIX + sid)

    async def take_assembly(self, sid: str) -> dict | None:
        return await self.state.take(ASSEMBLY_PREFIX + sid)

    async def delete_assembly(self, sid: str) -> None:
        await self.state.delete(ASSEMBLY_PREFIX + sid)


    async def put_route(self, sid: str, payload: dict, ttl: int) -> None:
        await self.state.put(ROUTE_PREFIX + sid, payload, max(1, int(ttl)))

    async def get_route(self, sid: str) -> dict | None:
        return await self.state.get(ROUTE_PREFIX + sid)

    async def delete_route(self, sid: str) -> None:
        await self.state.delete(ROUTE_PREFIX + sid)

    async def publish_revoke(self, sid: str) -> None:
        await self.state.publish_revoke(sid)

    async def revocations(self) -> AsyncIterator[str]:
        async for sid in self.state.subscribe_revocations():
            yield sid


    async def reserve_tenant_quota(self, tenant_id: str, sid: str,
                                   limit: int | None, ttl: int) -> bool:
        if not tenant_id:
            return True
        return await self.state.reserve_quota(quota_key(tenant_id), sid, limit, ttl)

    async def release_tenant_quota(self, tenant_id: str, sid: str) -> None:
        if not tenant_id:
            return
        await self.state.release_quota(quota_key(tenant_id), sid)

    async def tenant_quota_usage(self, tenant_id: str) -> int:
        if not tenant_id:
            return 0
        return await self.state.quota_usage(quota_key(tenant_id))

    async def quota_members(self, tenant_id: str) -> list[str]:
        if not tenant_id:
            return []
        return await self.state.quota_members(quota_key(tenant_id))

    async def reclaim_quota(self, sids: set[str]) -> int:
        if not sids:
            return 0
        dropped = 0
        for key in await self.state.keys(QUOTA_PREFIX):
            before = await self.state.quota_usage(key)
            for sid in sids:
                await self.state.release_quota(key, sid)
            dropped += max(0, before - await self.state.quota_usage(key))
        return dropped

    async def register_worker(self, worker_id: str, *, instance_id: str,
                              capacity: int = DEFAULT_CAPACITY,
                              ttl: int = DEFAULT_WORKER_TTL,
                              metadata: dict | None = None) -> dict:
        if not worker_id or not instance_id or capacity < 1:
            raise BusError("invalid_worker", "Worker id / instance / capacity 不合法")
        payload = {"worker_id": worker_id, "instance_id": instance_id,
                   "capacity": int(capacity), "registered_at": self._clock(),
                   "metadata": metadata or {}}
        await self.state.register_worker(worker_id, payload, ttl)
        return payload

    async def workers(self) -> dict[str, dict]:
        roster = await self.state.workers()
        for worker_id, row in roster.items():
            row["draining"] = await self.state.get(DRAIN_PREFIX + worker_id) is not None
        return roster

    async def set_draining(self, worker_id: str, draining: bool, *, actor: str) -> None:
        if worker_id not in await self.state.workers():
            raise BusError("invalid_worker", "Worker 未注册或已失联")
        if draining:
            await self.state.put(DRAIN_PREFIX + worker_id, {"actor": actor, "since": self._clock()}, 86400 * 30)
        else:
            await self.state.delete(DRAIN_PREFIX + worker_id)

    async def claim_session(self, worker_id: str, sid: str, ttl: int) -> bool:
        key = f"{LOAD_PREFIX}{worker_id}:{sid}"
        worker = (await self.workers()).get(worker_id)
        if not worker or worker["draining"]:
            return False
        return await self.state.claim_worker(key, DRAIN_PREFIX + worker_id,
                                            f"{LOAD_PREFIX}{worker_id}:",
                                            {"sid": sid, "at": self._clock()}, ttl, int(worker["capacity"]))

    async def release_session(self, worker_id: str, sid: str) -> None:
        await self.state.delete(f"{LOAD_PREFIX}{worker_id}:{sid}")

    async def worker_load(self, worker_id: str) -> int:
        return len(await self.state.keys(f"{LOAD_PREFIX}{worker_id}:"))

    async def claims(self, worker_id: str) -> list[str]:
        prefix = f"{LOAD_PREFIX}{worker_id}:"
        return [key[len(prefix):] for key in await self.state.keys(prefix)]


    @staticmethod
    def _worker_transcode_budgets(row: dict) -> dict | None:
        metadata = row.get("metadata") or {}
        if metadata.get("lane") != TRANSCODE_LANE:
            return None
        try:
            result = {"capacity": int(metadata["transcode_capacity"]),
                      "cpu_budget": float(metadata["cpu_budget"]),
                      "mem_budget": float(metadata["mem_budget"]),
                      "cpu_need": float(metadata["session_cpu"]),
                      "mem_need": float(metadata["session_mem"])}
        except (KeyError, TypeError, ValueError):
            return None
        if min(result.values()) <= 0:
            return None
        return result

    async def reserve_worker_resources(self, worker_id: str, sid: str, *, ttl: int,
                                       row: dict | None = None) -> bool:
        if row is None:
            row = (await self.workers()).get(worker_id)
        budgets = self._worker_transcode_budgets(row) if row else None
        if budgets is None:
            return False
        return await self.state.reserve_worker_resources(
            worker_id, sid, ttl=ttl, **budgets)

    async def release_worker_resources(self, worker_id: str, sid: str) -> None:
        await self.state.release_worker_resources(worker_id, sid)

    async def worker_resources(self, worker_id: str) -> dict:
        return await self.state.worker_resources(worker_id)

    async def choose_worker(self, requirements: dict | None = None) -> dict:
        req = requirements or {}
        lane = req.get("lane") or None
        versions = req.get("versions") or {}
        if not isinstance(versions, dict):
            raise BusError("invalid_request", "Worker 版本需求不合法")
        max_age = req.get("max_worker_age")
        roster = await self.workers()
        if not roster:
            raise BusError("no_worker_available", "没有已注册的 Worker，控制台未下发")
        candidates = []
        version_gap = False
        capacity_gap = False
        for worker_id, row in roster.items():
            if row.get("draining"):
                continue
            metadata = row.get("metadata") or {}
            if lane and metadata.get("lane") != lane:
                version_gap = True
                continue
            if any(metadata.get(key) != value for key, value in versions.items()):
                version_gap = True
                continue
            if max_age is not None:
                try:
                    if self._clock() - float(row.get("registered_at", 0)) > float(max_age):
                        capacity_gap = True
                        continue
                except (TypeError, ValueError):
                    capacity_gap = True
                    continue
            try:
                capacity = int(row.get("capacity", DEFAULT_CAPACITY))
            except (TypeError, ValueError):
                capacity_gap = True
                continue
            if capacity < 1:
                capacity_gap = True
                continue
            load = await self.worker_load(worker_id)
            if load >= capacity:
                capacity_gap = True
                continue
            score = load / capacity
            if lane == TRANSCODE_LANE:
                budgets = self._worker_transcode_budgets(row)
                if budgets is None:
                    version_gap = True
                    continue
                used = await self.worker_resources(worker_id)
                if (used["count"] >= budgets["capacity"]
                        or used["cpu"] + budgets["cpu_need"] > budgets["cpu_budget"]
                        or used["mem"] + budgets["mem_need"] > budgets["mem_budget"]):
                    capacity_gap = True
                    continue
                score = max(score, used["count"] / budgets["capacity"],
                            used["cpu"] / budgets["cpu_budget"],
                            used["mem"] / budgets["mem_budget"])
            candidates.append((score, load, worker_id, row))
        if not candidates:
            code = ("pipeline_version_unavailable"
                    if version_gap and not capacity_gap else "worker_capacity_exhausted")
            raise BusError(code, "没有匹配版本或容量的 Worker，控制台未下发")
        _, _, worker_id, row = min(candidates, key=lambda item: (item[0], item[1], item[2]))
        return {**row, "worker_id": worker_id, "load": await self.worker_load(worker_id)}
