"""Console ticket issuance from the production control plane."""
from __future__ import annotations

import contextlib
import time
import uuid
import ipaddress
import re
from typing import Callable

from .. import common
from ..admission_runtime import (authority_request, binding_digest, binding_payload)
from ..common import Problem, issue
from ..store import Store
from . import services
from .bus import TRANSCODE_LANE, AssemblyBus, BusError

DEFAULT_ACCEPT_TEMPLATE = "https://{worker_id}-{sid}.kvm.localhost:{port}/_platform/accept"


def managed_operation_required(assembly: dict, managed_domains, authority) -> tuple[bool, dict]:
    g0 = assembly.get("g0") or {}
    domain_id = str(g0.get("domain_id") or "")
    if not (managed_domains and domain_id in managed_domains):
        return False, g0
    if authority is None:
        raise services.PlatformError(
            "admission_service_unavailable", "管理域未配置准入服务，连接被拒绝", 503)
    if not g0.get("ready"):
        raise services.PlatformError(
            "connection_config_pending", "管理域连接配置尚未确认，连接被拒绝", 409)
    return True, g0


class ConsolePlane:
    def __init__(self, *, private_key, bus: AssemblyBus,
                 store: Store | None = None,
                 store_factory: Callable[[], Store] | None = None,
                 accept_template: str | None = None, port: int = 9443,
                 clock=time.time, authority=None, authority_host: str = "",
                 permit_public_key=None, managed_domains: tuple[str, ...] = ()):
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
        self.authority = authority
        self.authority_host = authority_host
        self.permit_public_key = permit_public_key
        self.managed_domains = frozenset(managed_domains)

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


    def write_grant(self, user_id: str, asset_id: str, expires: float, *, trace: str = "") -> None:
        store, dispose = self._connect()
        try:
            with store.tx():
                store.put_grant(user_id, asset_id, expires)
                store.event("platform", "grant_written", detail={"user": user_id, "asset": asset_id},
                            trace=trace or None)
        finally:
            if dispose:
                store.close()

    def delete_grant(self, user_id: str, asset_id: str, *, trace: str = "") -> None:
        store, dispose = self._connect()
        try:
            with store.tx():
                store.delete_grant(user_id, asset_id)
                store.event("platform", "grant_removed", detail={"user": user_id, "asset": asset_id},
                            trace=trace or None)
        finally:
            if dispose:
                store.close()

    def delete_grants_for_asset(self, asset_id: str, *, trace: str = "") -> None:
        store, dispose = self._connect()
        try:
            with store.tx():
                store.delete_grants_for_asset(asset_id)
                store.event("platform", "asset_grants_cleared", detail={"asset": asset_id},
                            trace=trace or None)
        finally:
            if dispose:
                store.close()

    def set_subject_authz(self, user_id: str, console_allowed: int, epoch: int,
                          *, trace: str = "") -> None:
        store, dispose = self._connect()
        try:
            with store.tx():
                store.set_subject_authz(user_id, console_allowed, epoch)
                store.event("platform", "subject_authz_set",
                            detail={"user": user_id, "allowed": console_allowed, "epoch": epoch},
                            trace=trace or None)
        finally:
            if dispose:
                store.close()

    def bump_subject_epoch(self, user_id: str, *, console_allowed: int | None = None,
                           trace: str = "") -> int:
        store, dispose = self._connect()
        try:
            with store.tx():
                new_epoch = store.bump_subject_epoch(user_id, console_allowed=console_allowed)
                store.event("platform", "subject_epoch_bumped",
                            detail={"user": user_id, "epoch": new_epoch}, trace=trace or None)
            return new_epoch
        finally:
            if dispose:
                store.close()

    def revoke_subject(self, user_id: str, *, trace: str = "") -> None:
        self.bump_subject_epoch(user_id, console_allowed=0, trace=trace)

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
        managed, g0 = managed_operation_required(assembly, self.managed_domains, self.authority)
        if assembly.get('overlay') and not managed:
            raise services.PlatformError('overlay_requires_managed', '覆盖层需要受管准入域', 409)
        await self.reconcile_claims()
        await self.reconcile_quota(tenant_id)
        requirements = dict(assembly.get("worker_requirements") or {})
        if requirements.get("lane") and not managed:
            raise services.PlatformError(
                "pipeline_version_unavailable",
                "转码通道只对管理域开放", 503)
        try:
            worker = await self.bus.choose_worker(requirements or None)
        except BusError as exc:
            status = 429 if exc.code == "transcode_capacity_exhausted" else 503
            raise services.PlatformError(exc.code, exc.message, status) from exc
        worker_id = str(worker["worker_id"])
        instance_id = str(worker["instance_id"])
        correlation = trace if len(trace) == 32 else uuid.uuid4().hex
        now = self._clock()
        hard_cap = now + int(session_limit_minutes) * 60 if session_limit_minutes else None
        store, dispose = self._connect()
        try:
            permit = None
            permit_claims = None
            candidate = None
            binding = ""
            resources_reserved = False
            if managed:
                candidate = uuid.uuid4().hex
                binding = binding_digest(binding_payload(
                    sid=candidate, asset_id=asset_id, tenant_id=tenant_id,
                    user_id=user_id, domain_id=g0["domain_id"], worker_id=worker_id,
                    instance_id=instance_id,
                    connection_revision=int(g0["connection_revision"]),
                    admission_revision=int(g0["admission_revision"]),
                    digest=g0["digest"], generation=g0["generation"]))
                request = authority_request(
                    operation="allocate", sid=candidate, asset_id=asset_id,
                    user_id=user_id, tenant_id=tenant_id, domain_id=g0["domain_id"],
                    worker_id=worker_id, instance_id=instance_id,
                    connection_revision=int(g0["connection_revision"]),
                    admission_revision=int(g0["admission_revision"]),
                    digest=g0["digest"], generation=g0["generation"],
                    session_started_at=now,
                    hard_until=now + (hard_cap or 4 * 3600))
                try:
                    answer = await self.authority.authorize(
                        host=self.authority_host, **request)
                except Problem as exc:
                    raise services.PlatformError(
                        exc.code,
                        common.user_message(exc.code) or f"准入被拒绝：{exc.code}",
                        exc.status) from exc
                permit, permit_claims = answer["permit"], answer["claims"]
            try:
                row = store.allocate(
                    asset_id, user_id, worker_id, instance_id, correlation,
                    hard_cap=hard_cap, sid=candidate, permit=permit,
                    public_key=self.permit_public_key, binding=binding,
                    expected=({"dom": g0["domain_id"], "wid": worker_id,
                               "iid": instance_id, "cr": int(g0["connection_revision"]),
                               "ar": int(g0["admission_revision"]), "aid": asset_id,
                               "usr": user_id, "tid": tenant_id,
                               "dgs": g0["digest"], "gen": g0["generation"]}
                              if permit_claims else None))
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
            if requirements.get("lane") == TRANSCODE_LANE:
                if not await self.bus.reserve_worker_resources(worker_id, sid,
                                                               ttl=hard_ttl, row=worker):
                    store.revoke(sid, user_id, correlation)
                    await self.bus.release_session(worker_id, sid)
                    await self.bus.release_tenant_quota(tenant_id, sid)
                    raise services.PlatformError(
                        "transcode_capacity_exhausted",
                        "转码容量已满或预算不足，请重试", 429)
                resources_reserved = True
            try:
                document = {
                    "asset_id": asset_id,
                    "tenant_id": tenant_id,
                    "display_address": assembly.get("display_address"),
                    "profile": assembly.get("profile"),
                    "plan": assembly.get("plan"),
                    "data_plane": assembly.get("data_plane"),
                    "checks": assembly.get("checks"),
                    "credential_id": assembly.get("credential_id"),
                    "binding": binding, "g0": g0,
                    "lane": requirements.get("lane"),
                    "pipeline_versions": requirements.get("versions"),
                    "client_contract": assembly.get("client_contract") or "",
                    "client_bundle": assembly.get("client_bundle") or "",
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
                               tenant_id=tenant_id, binding=binding)
            except BaseException:
                with contextlib.suppress(Exception):
                    store.revoke(sid, user_id, correlation)
                with contextlib.suppress(Exception):
                    await self.bus.release_session(worker_id, sid)
                with contextlib.suppress(Exception):
                    await self.bus.release_tenant_quota(tenant_id, sid)
                if resources_reserved:
                    with contextlib.suppress(Exception):
                        await self.bus.release_worker_resources(worker_id, sid)
                with contextlib.suppress(Exception):
                    await self.bus.delete_assembly(sid)
                with contextlib.suppress(Exception):
                    await self.bus.delete_route(sid)
                raise
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
                        await self.bus.release_worker_resources(worker_id, sid)
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
        await self.bus.release_worker_resources(str(row["worker_id"]), sid)
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
                           trace: str = "", actor: str = "platform") -> dict:
        correlation = trace if len(trace) == 32 else uuid.uuid4().hex
        store, dispose = self._connect()
        try:
            try:
                outcome = store.force_revoke(sid, actor, correlation)
            except Problem as exc:
                raise services.PlatformError("session_not_found", "会话不存在", 404) from exc
        finally:
            if dispose:
                store.close()
        route = await self.bus.get_route(sid)
        route_tenant = str((route or {}).get("tenant_id") or "") or None
        await self.bus.publish_revoke(sid)
        await self.bus.delete_route(sid)
        await self.bus.delete_assembly(sid)
        await self.bus.release_session(str(outcome["worker_id"]), sid)
        await self.bus.release_worker_resources(str(outcome["worker_id"]), sid)
        await self.bus.release_tenant_quota(tenant_id or route_tenant or "", sid)
        return {"ok": True, "sid": sid, "status": outcome["status"],
                "asset_id": outcome["asset_id"], "was_live": outcome["was_live"],
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
