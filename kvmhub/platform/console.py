"""Console ticket issuance from the production control plane."""
from __future__ import annotations

import time
import uuid
import ipaddress
import re
from typing import Callable

from .. import common
from ..common import Problem, issue
from ..store import Store
from . import services
from .bus import AssemblyBus, BusError

DEFAULT_ACCEPT_TEMPLATE = "https://{worker_id}-{sid}.kvm.localhost:{port}/_platform/accept"


class ConsolePlane:
    def __init__(self, *, private_key, bus: AssemblyBus,
                 store: Store | None = None,
                 store_factory: Callable[[], Store] | None = None,
                 accept_template: str | None = None, port: int = 9443,
                 clock=time.time):
        if (store is None) == (store_factory is None):
            raise ValueError("provide exactly one of store / store_factory")
        self.private_key = private_key
        self.bus = bus
        self._store_factory = store_factory
        self._store_instance = store
        self._owns_store = store_factory is not None
        self.accept_template = accept_template or DEFAULT_ACCEPT_TEMPLATE
        self.port = port
        self._clock = clock

    def _connect(self) -> tuple[Store, bool]:
        if self._owns_store:
            return self._store_factory(), True
        return self._store_instance, False

    def close(self) -> None:
        if self._store_instance is not None:
            self._store_instance.close()
            self._store_instance = None

    def accept_url(self, *, worker_id: str, sid: str) -> str:
        return self.accept_template.format(worker_id=worker_id, sid=sid, port=self.port)

    @staticmethod
    def _worker_upstream(worker: dict) -> str:
        metadata = worker.get("metadata") or {}
        try:
            address = ipaddress.ip_address(metadata["address"])
            port = int(metadata["port"])
            if address.version != 4 or not (address.is_private or address.is_loopback) \
                    or not 1 <= port <= 65535:
                raise ValueError("invalid upstream")
        except (KeyError, TypeError, ValueError) as exc:
            raise services.PlatformError("invalid_worker", "Worker 路由未配置", 403) from exc
        return f"{address}:{port}"

    async def open(self, assembly: dict, *, user_id: str, trace: str = "",
                   concurrent_limit: int | None = None,
                   session_limit_minutes: int | None = None) -> dict:
        asset_id = str(assembly.get("asset_id") or "")
        if not asset_id or not assembly.get("ready"):
            raise services.PlatformError("assembly_not_ready", "装配包未通过全部闸门", 409)
        tenant_id = str(assembly.get("tenant_id") or "")
        await self.reconcile_claims()
        await self.reconcile_quota(tenant_id)
        try:
            worker = await self.bus.choose_worker()
        except BusError as exc:
            raise services.PlatformError(exc.code, exc.message, 503) from exc
        worker_id = str(worker["worker_id"])
        instance_id = str(worker["instance_id"])
        correlation = trace if len(trace) == 32 else uuid.uuid4().hex
        now = self._clock()
        hard_cap = now + int(session_limit_minutes) * 60 if session_limit_minutes else None
        store, dispose = self._connect()
        try:
            try:
                row = store.allocate(asset_id, user_id, worker_id, instance_id, correlation,
                                     hard_cap=hard_cap)
            except Problem as exc:
                raise services.PlatformError(exc.code, f"会话分配被拒绝：{exc.code}",
                                             exc.status) from exc
            sid = row["id"]
            hard_ttl = max(60, int(row["hard_until"] - now))
            if not await self.bus.reserve_tenant_quota(tenant_id, sid, concurrent_limit, hard_ttl):
                store.revoke(sid, user_id, correlation)
                raise services.PlatformError(
                    "quota_exceeded",
                    f"租户并发会话已达上限（{concurrent_limit}），请关闭其它控制台后重试", 429)
            if not await self.bus.claim_session(worker_id, sid, hard_ttl):
                store.revoke(sid, user_id, correlation)
                await self.bus.release_tenant_quota(tenant_id, sid)
                raise services.PlatformError("worker_capacity_exhausted",
                                             "Worker 容量已满，请重试", 503)
            document = {
                "asset_id": asset_id,
                "tenant_id": tenant_id,
                "profile": assembly.get("profile"),
                "plan": assembly.get("plan"),
                "data_plane": assembly.get("data_plane"),
                "checks": assembly.get("checks"),
                "credential_id": assembly.get("credential_id"),
            }
            assembly_id = await self.bus.put_assembly(sid, document)
            if common.SESSION_MODE == "path":
                await self.bus.put_route(sid, {
                    "worker_id": worker_id,
                    "instance_id": instance_id,
                    "upstream": self._worker_upstream(worker),
                    "asset_id": asset_id,
                    "tenant_id": tenant_id,
                }, hard_ttl)
            ticket = issue(self.private_key, row, now, trace=correlation,
                           tenant_id=tenant_id)
            return {"sid": sid, "ticket": ticket,
                    "tenant_id": assembly.get("tenant_id"),
                    "accept_url": self.accept_url(worker_id=worker_id, sid=sid),
                    "worker_id": worker_id, "instance_id": instance_id,
                    "assembly_id": assembly_id, "delivery": "worker_bridge",
                    "hard_until": row["hard_until"],
                    "session_limit_minutes": session_limit_minutes, "asset_id": asset_id,
                    "note": "票据不含 BMC 凭据；装配包由 Worker 一次性取用，凭据由 Store.exchange 在内部套接字解密。"}
        finally:
            if dispose:
                store.close()

    async def reconcile_claims(self) -> int:
        released = 0
        dead: set[str] = set()
        store, dispose = self._connect()
        try:
            for worker_id in await self.bus.workers():
                for sid in await self.bus.claims(worker_id):
                    try:
                        row = store.get(sid)
                    except Problem:
                        row = None
                    if row is None or row["status"] not in store.LIVE_STATES:
                        await self.bus.release_session(worker_id, sid)
                        dead.add(sid)
                        released += 1
        finally:
            if dispose:
                store.close()
        if dead:
            await self.bus.reclaim_quota(dead)
        return released

    async def reconcile_quota(self, tenant_id: str) -> int:
        if not tenant_id:
            return 0
        members = await self.bus.quota_members(tenant_id)
        if not members:
            return 0
        dead: set[str] = set()
        store, dispose = self._connect()
        try:
            for sid in members:
                try:
                    row = store.get(sid)
                except Problem:
                    dead.add(sid)
                    continue
                if row["status"] not in store.LIVE_STATES:
                    dead.add(sid)
        finally:
            if dispose:
                store.close()
        if dead:
            await self.bus.reclaim_quota(dead)
        return len(dead)

    async def close_session(self, sid: str, *, user_id: str, trace: str = "",
                            tenant_id: str = "") -> dict:
        correlation = trace if len(trace) == 32 else uuid.uuid4().hex
        store, dispose = self._connect()
        try:
            try:
                row = store.owned(sid, user_id)
            except Problem as exc:
                raise services.PlatformError(exc.code, exc.code, exc.status) from exc
            store.revoke(sid, user_id, correlation)
        finally:
            if dispose:
                store.close()
        await self.bus.release_session(str(row["worker_id"]), sid)
        tenant = tenant_id or await self._route_tenant(sid)
        await self.bus.release_tenant_quota(tenant, sid)
        await self.bus.delete_assembly(sid)
        await self.bus.delete_route(sid)
        await self.bus.publish_revoke(sid)
        return {"ok": True, "sid": sid}

    async def _route_tenant(self, sid: str) -> str:
        route = await self.bus.get_route(sid)
        return str((route or {}).get("tenant_id") or "")

    async def active_sessions(self, *, now: float | None = None) -> list[dict]:
        stamp = self._clock() if now is None else now
        store, dispose = self._connect()
        try:
            rows = store.db.execute(
                "SELECT id,user_id,asset_id,worker_id,instance_id,status,cleanup,"
                "created,hard_until FROM session WHERE status IN (?,?,?,?) "
                "ORDER BY created DESC", store.LIVE_STATES).fetchall()
            out = []
            for raw in rows:
                row = dict(raw)
                route = await self.bus.get_route(row["id"])
                row["tenant_id"] = str((route or {}).get("tenant_id") or "") or None
                row["route_active"] = route is not None
                row["lease_active"] = await self.bus.state.lease_alive(row["id"])
                row["duration_seconds"] = max(0, int(stamp - float(row["created"])))
                row["remaining_seconds"] = max(0, int(float(row["hard_until"]) - stamp))
                out.append(row)
            return out
        finally:
            if dispose:
                store.close()

    def session_asset(self, sid: str) -> str:
        store, dispose = self._connect()
        try:
            try:
                return str(store.get(sid)["asset_id"])
            except Problem as exc:
                raise services.PlatformError("session_not_found", "会话不存在", 404) from exc
        finally:
            if dispose:
                store.close()

    async def force_revoke(self, sid: str, *, tenant_id: str = "",
                           trace: str = "") -> dict:
        store, dispose = self._connect()
        try:
            try:
                row = store.get(sid)
            except Problem as exc:
                raise services.PlatformError("session_not_found", "会话不存在", 404) from exc
        finally:
            if dispose:
                store.close()
        route = await self.bus.get_route(sid)
        route_tenant = str((route or {}).get("tenant_id") or "") or None
        live = row["status"] in ("pending", "connecting", "active", "closing")
        await self.bus.publish_revoke(sid)
        await self.bus.delete_route(sid)
        await self.bus.delete_assembly(sid)
        await self.bus.release_session(str(row["worker_id"]), sid)
        await self.bus.release_tenant_quota(tenant_id or route_tenant or "", sid)
        return {"ok": True, "sid": sid, "status": row["status"],
                "asset_id": row["asset_id"], "was_live": live,
                "tenant_id": tenant_id or route_tenant, "trace_id": trace}

    def confirm_cleanup(self, sid: str, *, user_id: str, manage: bool = False,
                        trace: str = "") -> dict:
        correlation = trace if len(trace) == 32 else uuid.uuid4().hex
        store, dispose = self._connect()
        try:
            try:
                store.confirm_cleanup(sid, user_id, correlation, manage=manage)
            except Problem as exc:
                raise services.PlatformError(exc.code, exc.code, exc.status) from exc
        finally:
            if dispose:
                store.close()
        return {"ok": True, "sid": sid, "cleanup": "confirmed"}

    def status(self, sid: str, user_id: str) -> dict:
        store, dispose = self._connect()
        try:
            try:
                return store.public(sid, user_id)
            except Problem as exc:
                raise services.PlatformError(exc.code, exc.code, exc.status) from exc
        finally:
            if dispose:
                store.close()

    async def route(self, host: str) -> str:
        label = host.split('.', 1)[0]
        match = re.fullmatch(r'(w[0-9a-z-]{1,32})-([0-9a-f]{32})', label)
        if not match:
            raise services.PlatformError('invalid_session', '会话域名不合法', 403)
        worker_id, sid = match.groups()
        store, dispose = self._connect()
        try:
            try:
                session = store.get(sid)
            except Problem as exc:
                raise services.PlatformError(exc.code, exc.code, 403) from exc
        finally:
            if dispose:
                store.close()
        if session['status'] not in ('pending', 'connecting', 'active') or session['hard_until'] <= self._clock():
            raise services.PlatformError('invalid_session', '会话已结束或到期', 403)
        worker = (await self.bus.workers()).get(worker_id)
        if (session['worker_id'] != worker_id or not worker
                or worker['instance_id'] != session['instance_id']):
            raise services.PlatformError('invalid_worker', '会话 Worker 已失联或不匹配', 403)
        return self._worker_upstream(worker)

    def asset_occupancy(self, asset_ids: list[str], user_id: str, *, manage: bool = False) -> dict:
        if not asset_ids:
            return {}
        store, dispose = self._connect()
        try:
            result = {}
            for aid in asset_ids:
                row = store.db.execute(
                    "SELECT s.id,s.user_id,s.status,s.cleanup,s.hard_until "
                    "FROM asset_slot a JOIN session s ON s.id=a.session_id WHERE a.asset_id=?",
                    (aid,)).fetchone()
                if row is not None:
                    own = row["user_id"] == user_id
                    result[aid] = {"busy": True, "owned": own,
                                   "user_id": row["user_id"] if own or manage else None,
                                   "session_id": row["id"] if (own or manage) else None,
                                   "status": row["status"], "cleanup": row["cleanup"],
                                   "hard_until": row["hard_until"],
                                   "remaining_seconds": max(0, int(row["hard_until"] - self._clock())),
                                   "queue": "not_supported"}
            return result
        finally:
            if dispose:
                store.close()
