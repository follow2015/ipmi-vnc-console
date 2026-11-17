"""Production control-plane HTTP API (FastAPI)."""
from __future__ import annotations

import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from urllib.parse import urlsplit

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from sqlalchemy import func, select

from .config import Settings, settings as load_settings
from .db import init_schema, make_engine, seed_roles, session_factory, transaction
from .models import Asset, Capability, Tenant, User, VendorProfile, parse_json
from .redis_state import SESSION_PREFIX, State, create_state
from .security import (CredentialCipher, constant_time_equal, new_session_token,
                       token_digest)
from . import connection, governance, services, text_input, vendor_registry
from .bus import AssemblyBus, BusError
from .contracts import CONTRACT_RESPONSES, contract_components, response_schema

MAX_BODY = 65536


def _build_plane(cfg: Settings, state: State):
    if not cfg.data_plane_store or not cfg.signing_key_path:
        return None
    from pathlib import Path

    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    from ..common import WORKER_PORT
    from ..store import Store
    from .bus import AssemblyBus
    from .console import ConsolePlane

    private = load_pem_private_key(Path(cfg.signing_key_path).read_bytes(), password=None)
    targets = tuple(item.strip() for item in cfg.passthrough_targets.split(",") if item.strip())

    def connect() -> Store:
        return Store(cfg.data_plane_store, cfg.data_plane_key,
                     passthrough_targets=targets)

    return ConsolePlane(store_factory=connect, private_key=private,
                        bus=AssemblyBus(state),
                        accept_template=cfg.worker_url_template or None, port=WORKER_PORT)


class Platform:
    def __init__(self, cfg: Settings, *, state: State | None = None, plane=None):
        self.cfg = cfg
        self.engine = make_engine(cfg.db_url)
        self.factory = session_factory(self.engine)
        self.cipher = CredentialCipher(cfg.credential_key)
        self.state = state if state is not None else create_state(cfg.redis_url)
        self.bus = AssemblyBus(self.state)
        self.owns_plane = plane is None
        self.plane = plane if plane is not None else _build_plane(cfg, self.state)
        if cfg.db_url.startswith("sqlite"):
            init_schema(self.engine)
        with transaction(self.factory) as db:
            seed_roles(db)

    @property
    def tenant_cookie_name(self) -> str:
        return "__Host-kvmhub_sid" if self.cfg.is_prod else "kvmhub_sid"

    @property
    def admin_cookie_name(self) -> str:
        return "__Host-kvmhub_admin_sid" if self.cfg.is_prod else "kvmhub_admin_sid"

    async def ready(self) -> dict:
        checks: dict[str, bool] = {"database": False, "state": False, "credential_key": bool(self.cipher.available)}
        try:
            with transaction(self.factory) as db:
                db.execute(select(User.id).limit(1))
            checks["database"] = True
        except Exception:
            pass
        try:
            await self.state.touch_lease("__healthcheck__", 5)
            checks["state"] = await self.state.lease_alive("__healthcheck__")
            await self.state.drop_lease("__healthcheck__")
        except Exception:
            pass
        return checks

    async def close(self) -> None:
        if self.owns_plane and self.plane is not None:
            self.plane.close()
        await self.state.close()
        self.engine.dispose()


async def _json(request: Request) -> dict:
    length = request.headers.get("content-length", "0")
    if length.isdigit() and int(length) > MAX_BODY:
        raise services.PlatformError("request_too_large", "请求体过大", 413)
    raw = await request.body()
    if len(raw) > MAX_BODY:
        raise services.PlatformError("request_too_large", "请求体过大", 413)
    import json
    try:
        value = json.loads(raw or b"{}")
    except ValueError as exc:
        raise services.PlatformError("invalid_request", "请求体不是合法 JSON") from exc
    if not isinstance(value, dict):
        raise services.PlatformError("invalid_request", "请求体必须是 JSON 对象")
    return value


def create_app(cfg: Settings | None = None, *, state: State | None = None,
               plane=None) -> FastAPI:
    platform = Platform(cfg or load_settings(), state=state, plane=plane)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        yield
        await platform.close()

    app = FastAPI(title="KVM Hub 控制面", version="2.0.0", lifespan=lifespan)
    app.state.platform = platform

    @app.exception_handler(services.PlatformError)
    async def on_error(request: Request, exc: services.PlatformError):
        return JSONResponse({"error": exc.code, "message": exc.message,
                             "trace_id": request.state.trace}, status_code=exc.status)

    @app.middleware("http")
    async def guards(request: Request, call_next):
        incoming = request.headers.get("X-Trace-ID", "")
        request.state.trace = incoming if len(incoming) == 32 and all(c in "0123456789abcdef" for c in incoming) else uuid.uuid4().hex
        response = await call_next(request)
        response.headers.update({
            "Cache-Control": "no-store", "Referrer-Policy": "strict-origin",
            "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY",
            "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
            "X-Trace-ID": request.state.trace})
        return response

    async def current(request: Request, *, mutate: bool = False, permission: str | None = None,
                      tenant_required: bool = True, platform_only: bool = False,
                      admin: bool = False) -> dict:
        cookie = platform.admin_cookie_name if admin else platform.tenant_cookie_name
        token = request.cookies.get(cookie, "")
        if not token:
            other = request.cookies.get(
                platform.tenant_cookie_name if admin else platform.admin_cookie_name, "")
            if admin and other:
                raise services.PlatformError("platform_access_denied", "该入口仅限平台管理员", 403)
            if not admin and other:
                raise services.PlatformError(
                    "platform_account_requires_platform_api",
                    "平台账号请使用 /api/v2/platform 管理接口", 403)
        auth = await platform.state.get_session(token_digest(token)) if token else None
        if not auth or float(auth.get("expires", 0)) <= time.time():
            raise services.PlatformError("authentication_required", "请先登录", 401)
        with transaction(platform.factory) as db:
            row = db.execute(select(User.is_active, User.tenant_id)
                             .where(User.id == auth["user_id"])).first()
        if row is None or row[0] is not True:
            raise services.PlatformError("authentication_required", "账号已停用，请重新登录", 401)
        auth = dict(auth)
        auth["tenant_id"] = row[1]
        if platform_only:
            if auth["tenant_id"] is not None:
                raise services.PlatformError("platform_access_denied", "该入口仅限平台管理员", 403)
        elif tenant_required and auth["tenant_id"] is None:
            raise services.PlatformError(
                "platform_account_requires_platform_api",
                "平台账号请使用 /api/v2/platform 管理接口", 403)
        if mutate:
            origin = request.headers.get("origin", "")
            host = request.headers.get("host", "")
            if not origin or not host or urlsplit(origin).netloc != host:
                raise services.PlatformError("csrf_rejected", "请求来源与主机不一致", 403)
            if not constant_time_equal(request.headers.get("x-csrf-token", ""), auth.get("csrf", "")):
                raise services.PlatformError("csrf_rejected", "CSRF 校验失败", 403)
        if permission:
            with transaction(platform.factory) as db:
                services.require(db, auth["user_id"], permission)
        return auth

    async def current_platform(request: Request, *, mutate: bool = False,
                               permission: str | None = None) -> dict:
        auth = await current(request, mutate=mutate, tenant_required=False,
                             platform_only=True, admin=True)
        code = permission or "platform.tenant.read"
        with transaction(platform.factory) as db:
            services.require(db, auth["user_id"], code)
        return auth

    async def current_integration(request: Request) -> dict:
        parts = request.headers.get("authorization", "").split()
        if len(parts) != 2 or parts[0].lower() != "bearer":
            raise services.PlatformError("authentication_required", "需要 Bearer 服务凭据", 401)
        with transaction(platform.factory) as db:
            auth = services.authenticate_service_token(
                db, parts[1], request.client.host if request.client else "",
                request.headers.get("x-forwarded-for", ""),
                trusted_proxies=platform.cfg.integration_trusted_proxies)
            services.require(db, auth["user_id"], "console.open")
        return auth

    @app.get("/api/v2/integration/ping")
    async def integration_ping(request: Request):
        auth = await current_integration(request)
        return {"ok": True, "tenant_code": auth["tenant_code"],
                "service_account": auth["username"], "token_label": auth["token_label"],
                "token_prefix": auth["token_prefix"]}

    @app.get("/api/v2/integration/assets")
    async def integration_assets(request: Request):
        auth = await current_integration(request)
        with transaction(platform.factory) as db:
            assets = db.scalars(select(Asset).where(Asset.tenant_id == auth["tenant_id"])
                                .order_by(Asset.address)).all()
            return {"assets": [a.public() for a in assets]}

    @app.post("/api/v2/integration/console/open")
    async def integration_console_open(request: Request):
        auth = await current_integration(request)
        plane = require_plane()
        body = await _json(request)
        asset_id = str(body.get("asset_id", "") or "")
        address = str(body.get("address", "") or "")
        operator = str(body.get("operator", "") or "")[:128]
        with transaction(platform.factory) as db:
            if not asset_id and address:
                row = db.scalar(select(Asset.id).where(Asset.address == address,
                                                      Asset.tenant_id == auth["tenant_id"]))
                asset_id = str(row or "")
            try:
                assembly = connection.assembly(
                    db, asset_id=asset_id, user_id=auth["user_id"],
                    actor=auth["username"], tenant_id=auth["tenant_id"])
                quotas = services.tenant_quotas(db, auth["tenant_id"])
            except connection.ConnectionRefused as exc:
                raise _refused(exc) from exc
        result = await plane.open(assembly, user_id=auth["user_id"], trace=request.state.trace,
                                  concurrent_limit=services.quota_limit(
                                      quotas, "max_concurrent_sessions"),
                                  session_limit_minutes=services.quota_limit(
                                      quotas, "max_session_minutes"))
        with transaction(platform.factory) as db:
            services.audit(db, auth["username"], "console_ticket_issued", asset_id=asset_id,
                           tenant_id=auth["tenant_id"], actor_type="dcim_system",
                           detail={"sid": result["sid"], "worker_id": result["worker_id"],
                                   "assembly_id": result["assembly_id"],
                                   "hard_until": result["hard_until"],
                                   "session_limit_minutes": result["session_limit_minutes"],
                                   "operator": operator, "token_id": auth["token_id"]},
                           trace=request.state.trace)
        return result

    @app.post("/api/v2/integration/consoles/{sid}/close")
    async def integration_console_close(sid: str, request: Request):
        auth = await current_integration(request)
        result = await require_plane().close_session(
            sid, user_id=auth["user_id"], trace=request.state.trace,
            tenant_id=auth["tenant_id"])
        with transaction(platform.factory) as db:
            services.audit(db, auth["username"], "console_ticket_revoked",
                           tenant_id=auth["tenant_id"], actor_type="dcim_system",
                           detail={"sid": sid, "token_id": auth["token_id"]},
                           trace=request.state.trace)
        return result

    @app.get("/healthz")
    async def healthz():
        return {"status": "ok", "env": platform.cfg.env}

    @app.get("/readyz")
    async def readyz():
        checks = await platform.ready()
        ok = checks["database"] and checks["state"] and (checks["credential_key"] or not platform.cfg.is_prod)
        return JSONResponse({"status": "ok" if ok else "degraded", "checks": checks},
                            status_code=200 if ok else 503)

    @app.post("/api/v2/login")
    async def login(request: Request):
        body = await _json(request)
        with transaction(platform.factory) as db:
            user = services.authenticate(db, str(body.get("username", "")),
                                         str(body.get("password", "")),
                                         tenant_code=str(body.get("tenant_code", "") or ""))
            if user.tenant_id is None:
                raise services.PlatformError(
                    "platform_account_requires_platform_login", "平台账号请从独立后台登录", 403)
            roles = services.roles_of(db, user.id)
        token, csrf = new_session_token(), new_session_token()
        await platform.state.put_session(
            token_digest(token),
            {"user_id": user.id, "username": user.username, "roles": roles, "csrf": csrf,
             "tenant_id": user.tenant_id,
             "expires": time.time() + platform.cfg.session_ttl}, platform.cfg.session_ttl)
        response = JSONResponse({"user": user.public(), "roles": roles, "csrf": csrf,
                                 "tenant_id": user.tenant_id})
        response.set_cookie(platform.tenant_cookie_name, token,
                            max_age=platform.cfg.session_ttl, secure=platform.cfg.is_prod,
                            httponly=True, samesite="strict", path="/")
        return response

    @app.post("/api/v2/platform/login")
    async def platform_login(request: Request):
        body = await _json(request)
        with transaction(platform.factory) as db:
            user = services.authenticate(db, str(body.get("username", "")),
                                         str(body.get("password", "")))
            if user.tenant_id is not None:
                raise services.PlatformError("platform_access_denied", "该入口仅限平台管理员", 403)
            services.require(db, user.id, "platform.tenant.read")
            roles = services.roles_of(db, user.id)
        token, csrf = new_session_token(), new_session_token()
        await platform.state.put_session(
            token_digest(token),
            {"user_id": user.id, "username": user.username, "roles": roles, "csrf": csrf,
             "tenant_id": None,
             "expires": time.time() + platform.cfg.session_ttl}, platform.cfg.session_ttl)
        response = JSONResponse({"user": user.public(), "roles": roles, "csrf": csrf,
                                 "tenant_id": None})
        response.set_cookie(platform.admin_cookie_name, token,
                            max_age=platform.cfg.session_ttl, secure=platform.cfg.is_prod,
                            httponly=True, samesite="strict", path="/")
        return response

    @app.post("/api/v2/logout")
    async def logout(request: Request):
        token = request.cookies.get(platform.tenant_cookie_name, "")
        auth = None
        if token:
            session_data = await platform.state.get_session(token_digest(token))
            is_tenant = False
            if session_data:
                user_id = session_data.get("user_id")
                with transaction(platform.factory) as db:
                    row = (db.execute(select(User.tenant_id).where(User.id == user_id)).first()
                           if user_id else None)
                is_tenant = row is not None and row[0] is not None
            if is_tenant:
                auth = await current(request, mutate=True)
        if token:
            await platform.state.drop_session(token_digest(token))
        if auth:
            with transaction(platform.factory) as db:
                services.audit(db, auth["username"], "logout", tenant_id=auth["tenant_id"])
        response = JSONResponse({"ok": True})
        response.delete_cookie(platform.tenant_cookie_name, path="/")
        return response

    @app.post("/api/v2/platform/logout")
    async def platform_logout(request: Request):
        auth = await current(request, mutate=True, tenant_required=False,
                             platform_only=True, admin=True)
        token = request.cookies.get(platform.admin_cookie_name, "")
        await platform.state.drop_session(token_digest(token))
        with transaction(platform.factory) as db:
            services.audit(db, auth["username"], "logout", tenant_id=None,
                           actor_type="platform")
        response = JSONResponse({"ok": True})
        response.delete_cookie(platform.admin_cookie_name, path="/")
        return response

    @app.get("/api/v2/me")
    async def me(request: Request):
        auth = await current(request, tenant_required=False)
        if auth["tenant_id"] is None:
            token = request.cookies.get(platform.tenant_cookie_name, "")
            if token:
                await platform.state.drop_session(token_digest(token))
            response = JSONResponse(
                {"error": "authentication_required", "message": "请使用对应入口登录",
                 "trace_id": request.state.trace}, status_code=401)
            response.delete_cookie(platform.tenant_cookie_name, path="/")
            return response
        with transaction(platform.factory) as db:
            perms = sorted(services.permissions_of(db, auth["user_id"]))
        return {"user_id": auth["user_id"], "username": auth["username"],
                "tenant_id": auth["tenant_id"], "roles": auth["roles"],
                "permissions": perms, "csrf": auth["csrf"]}

    @app.get("/api/v2/platform/me")
    async def platform_me(request: Request):
        auth = await current(request, tenant_required=False, platform_only=True, admin=True)
        with transaction(platform.factory) as db:
            perms = sorted(services.permissions_of(db, auth["user_id"]))
        return {"user_id": auth["user_id"], "username": auth["username"],
                "tenant_id": None, "roles": auth["roles"],
                "permissions": perms, "csrf": auth["csrf"]}

    @app.get("/api/v2/users")
    async def users(request: Request):
        auth = await current(request, permission="user.read")
        with transaction(platform.factory) as db:
            return services.list_users(db, tenant_id=auth["tenant_id"])

    @app.post("/api/v2/users")
    async def create_user(request: Request):
        auth = await current(request, mutate=True, permission="user.write")
        body = await _json(request)
        with transaction(platform.factory) as db:
            user = services.create_user(db, str(body.get("username", "")),
                                        str(body.get("password", "")), str(body.get("role", "viewer")),
                                        actor=auth["username"], display_name=str(body.get("display_name", "")),
                                        tenant_id=auth["tenant_id"])
            return user.public()

    @app.post("/api/v2/users/{user_id}/active")
    async def set_active(user_id: str, request: Request):
        auth = await current(request, mutate=True, permission="user.write")
        body = await _json(request)
        with transaction(platform.factory) as db:
            services.set_user_active(db, user_id, bool(body.get("active", False)),
                                     actor=auth["username"], tenant_id=auth["tenant_id"])
        if not bool(body.get("active", False)):
            for key in await platform.state.keys(SESSION_PREFIX):
                session = await platform.state.get(key)
                if session and session.get("user_id") == user_id:
                    await platform.state.delete(key)
        return {"ok": True}

    @app.get("/api/v2/assets")
    async def assets(request: Request, scope: str = "tenant"):
        if scope not in ("tenant", "granted", "all"):
            raise services.PlatformError("scope_invalid", "scope 只能是 tenant、granted 或 all", 400)
        if scope == "granted":
            auth = await current(request, permission="asset.read")
            with transaction(platform.factory) as db:
                rows = services.assets_for_user(db, auth["user_id"], tenant_id=auth["tenant_id"])
        else:
            auth = await current(request, permission="asset.write" if scope == "all" else "asset.read")
            with transaction(platform.factory) as db:
                rows = services.all_assets(db, auth["user_id"], tenant_id=auth["tenant_id"])
        occupancy = platform.plane.asset_occupancy(
            [row["id"] for row in rows], auth["user_id"], manage=scope == "all") if platform.plane else {}
        with transaction(platform.factory) as db:
            names = {uid: db.scalar(select(User.username).where(User.id == uid))
                     for uid in {value["user_id"] for value in occupancy.values() if value["user_id"]}}
        for row in rows:
            value = occupancy.get(row["id"])
            if value:
                value["username"] = names.get(value["user_id"])
            row["occupancy"] = value
            row["occupancy_available"] = platform.plane is not None
        return rows

    @app.post("/api/v2/assets")
    async def upsert_asset(request: Request):
        auth = await current(request, mutate=True, permission="asset.write")
        body = await _json(request)
        with transaction(platform.factory) as db:
            existing = db.scalar(select(Asset).where(Asset.address == str(body.get("address", "")),
                                                      Asset.tenant_id == auth["tenant_id"]))
            optional = {key: body[key] if key in body else getattr(existing, key, None)
                        for key in ("vendor", "model", "firmware", "fingerprint",
                                    "credential_id", "profile_id", "capability_id", "licence", "notes")}
            if existing is not None and "capability_id" not in body:
                if any(optional[key] != getattr(existing, key)
                       for key in ("vendor", "model", "firmware", "profile_id")):
                    optional["capability_id"] = None
            asset = services.upsert_asset(
                db, name=str(body.get("name", "")), address=str(body.get("address", "")),
                vendor=str(optional["vendor"] or ""), model=str(optional["model"] or ""),
                firmware=str(optional["firmware"] or ""), fingerprint=str(optional["fingerprint"] or ""),
                credential_id=optional["credential_id"], profile_id=optional["profile_id"],
                capability_id=optional["capability_id"], licence=str(optional["licence"] or ""),
                notes=str(optional["notes"] or ""), actor=auth["username"],
                tenant_id=auth["tenant_id"])
            return asset.public()

    @app.post("/api/v2/credentials")
    async def create_credential(request: Request):
        auth = await current(request, mutate=True, permission="credential.write")
        body = await _json(request)
        with transaction(platform.factory) as db:
            cred = services.save_credential(
                db, platform.cipher, label=str(body.get("label", "")),
                username=str(body.get("username", "")), password=str(body.get("password", "")),
                actor=auth["username"], tenant_id=auth["tenant_id"])
            return cred.public()

    @app.post("/api/v2/grants")
    async def grant(request: Request):
        auth = await current(request, mutate=True, permission="grant.write")
        body = await _json(request)
        with transaction(platform.factory) as db:
            services.grant_asset(db, user_id=str(body.get("user_id", "")),
                                 asset_id=str(body.get("asset_id", "")), actor=auth["username"],
                                 ttl_seconds=int(body.get("ttl_seconds", 86400 * 30)),
                                 tenant_id=auth["tenant_id"])
        return {"ok": True}

    @app.get("/api/v2/vendor-profiles")
    async def profiles(request: Request):
        auth = await current(request, permission="vendor.read")
        with transaction(platform.factory) as db:
            rows = db.scalars(select(VendorProfile)
                              .where((VendorProfile.tenant_id.is_(None))
                                     | (VendorProfile.tenant_id == auth["tenant_id"]))
                              .order_by(VendorProfile.priority)).all()
            return [row.public() for row in rows]

    @app.post("/api/v2/detect")
    async def detect(request: Request):
        auth = await current(request, mutate=True, permission="asset.write")
        body = await _json(request)
        detection = vendor_registry.detect_from_redfish(body.get("inventory") or {})
        with transaction(platform.factory) as db:
            match = vendor_registry.identify(db, detection, tenant_id=auth["tenant_id"])
            draft_id = None
            connection = None
            if match.profile is not None and match.usable:
                draft = services.capability_draft(db, match.profile, detection=detection,
                                                  actor=auth["username"],
                                                  tenant_id=auth["tenant_id"])
                draft_id = draft.id
                connection = vendor_registry.connection_plan(match.profile)
            services.audit(db, auth["username"], "vendor_detected", tenant_id=auth["tenant_id"],
                           detail={"detection": detection, "match": match.as_dict(),
                                   "draft_id": draft_id}, trace=request.state.trace)
            result = match.as_dict()
            result.update({"detection": detection, "capability_draft_id": draft_id,
                           "connection_plan": connection})
            return result

    @app.post("/api/v2/consoles/assembly")
    async def console_assembly(request: Request):
        auth = await current(request, mutate=True, permission="console.open")
        body = await _json(request)
        try:
            with transaction(platform.factory) as db:
                return connection.assembly(
                    db, asset_id=str(body.get("asset_id", "")),
                    user_id=auth["user_id"], actor=auth["username"],
                    tenant_id=auth["tenant_id"])
        except connection.ConnectionRefused as exc:
            raise _refused(exc) from exc

    def require_plane():
        if platform.plane is None:
            raise services.PlatformError(
                "data_plane_not_configured",
                "控制台数据面未配置（需要 KVMHUB_DATA_PLANE_STORE / KVMHUB_SIGNING_KEY / KVMHUB_DATA_PLANE_KEY）", 503)
        return platform.plane

    def _refused(exc: connection.ConnectionRefused) -> services.PlatformError:
        return services.PlatformError(exc.code, exc.message,
                                      403 if exc.code == "tenant_suspended" else 409)

    async def session_view(*, tenant_id: str | None = None) -> list[dict]:
        plane = require_plane()
        rows = await plane.active_sessions()
        with transaction(platform.factory) as db:
            asset_ids = {row["asset_id"] for row in rows}
            user_ids = {row["user_id"] for row in rows}
            assets = {asset.id: asset for asset in
                      db.scalars(select(Asset).where(Asset.id.in_(asset_ids)))} if asset_ids else {}
            users = {user.id: user for user in
                     db.scalars(select(User).where(User.id.in_(user_ids)))} if user_ids else {}
            codes = {tenant.id: tenant.code for tenant in db.scalars(select(Tenant))}
        out = []
        for row in rows:
            asset = assets.get(row["asset_id"])
            owner = users.get(row["user_id"])
            tid = (asset.tenant_id if asset is not None else None) or row.get("tenant_id")
            if tenant_id is not None and tid != tenant_id:
                continue
            out.append({
                "sid": row["id"], "tenant_id": tid, "tenant_code": codes.get(tid),
                "user_id": row["user_id"], "username": owner.username if owner else None,
                "asset_id": row["asset_id"], "asset_name": asset.name if asset else None,
                "asset_address": asset.address if asset else None,
                "worker_id": row["worker_id"], "status": row["status"],
                "cleanup": row["cleanup"], "created": row["created"],
                "duration_seconds": row["duration_seconds"],
                "remaining_seconds": row["remaining_seconds"],
                "route_active": row["route_active"], "lease_active": row["lease_active"],
            })
        return out

    @app.get('/_internal/worker-route', include_in_schema=False)
    async def worker_route(request: Request):
        upstream = await require_plane().route(request.headers.get('x-console-host', ''))
        return JSONResponse({'ok': True}, headers={'X-Worker-Upstream': upstream})

    @app.post("/api/v2/consoles/open")
    async def console_open(request: Request):
        auth = await current(request, mutate=True, permission="console.open")
        plane = require_plane()
        body = await _json(request)
        asset_id = str(body.get("asset_id", ""))
        try:
            with transaction(platform.factory) as db:
                assembly = connection.assembly(
                    db, asset_id=asset_id, user_id=auth["user_id"], actor=auth["username"],
                    tenant_id=auth["tenant_id"])
                quotas = services.tenant_quotas(db, auth["tenant_id"])
        except connection.ConnectionRefused as exc:
            raise _refused(exc) from exc
        result = await plane.open(assembly, user_id=auth["user_id"], trace=request.state.trace,
                                  concurrent_limit=services.quota_limit(
                                      quotas, "max_concurrent_sessions"),
                                  session_limit_minutes=services.quota_limit(
                                      quotas, "max_session_minutes"))
        with transaction(platform.factory) as db:
            services.audit(db, auth["username"], "console_ticket_issued", asset_id=asset_id,
                           tenant_id=auth["tenant_id"],
                           detail={"sid": result["sid"], "worker_id": result["worker_id"],
                                   "assembly_id": result["assembly_id"],
                                   "hard_until": result["hard_until"],
                                   "session_limit_minutes": result["session_limit_minutes"]},
                           trace=request.state.trace)
        return result

    @app.get("/api/v2/consoles/{sid}")
    async def console_status(sid: str, request: Request):
        auth = await current(request, permission="console.open")
        return require_plane().status(sid, auth["user_id"])

    @app.post("/api/v2/consoles/{sid}/close")
    async def console_close(sid: str, request: Request):
        auth = await current(request, mutate=True, permission="console.close")
        result = await require_plane().close_session(sid, user_id=auth["user_id"],
                                                     trace=request.state.trace,
                                                     tenant_id=auth["tenant_id"])
        with transaction(platform.factory) as db:
            services.audit(db, auth["username"], "console_ticket_revoked",
                           tenant_id=auth["tenant_id"],
                           detail={"sid": sid}, trace=request.state.trace)
        return result

    @app.post("/api/v2/consoles/{sid}/cleanup")
    async def console_cleanup(sid: str, request: Request):
        auth = await current(request, mutate=True, permission="console.close")
        plane = require_plane()
        asset_id = plane.session_asset(sid)
        manage = False
        with transaction(platform.factory) as db:
            asset = db.get(Asset, asset_id)
            if asset is None or asset.tenant_id != auth["tenant_id"]:
                raise services.PlatformError("session_not_found", "会话不存在", 404)
            try:
                services.require(db, auth["user_id"], "asset.write")
                manage = True
            except services.PlatformError:
                manage = False
        result = plane.confirm_cleanup(
            sid, user_id=auth["user_id"], manage=manage, trace=request.state.trace)
        with transaction(platform.factory) as db:
            services.audit(db, auth["username"], "console_slot_released",
                           tenant_id=auth["tenant_id"],
                           detail={"sid": sid, "scope": "manage" if manage else "owner"},
                           trace=request.state.trace)
        return result

    @app.get("/api/v2/sessions")
    async def sessions(request: Request):
        auth = await current(request, permission="session.read")
        return await session_view(tenant_id=auth["tenant_id"])

    @app.post("/api/v2/sessions/{sid}/revoke")
    async def revoke_session(sid: str, request: Request):
        auth = await current(request, mutate=True, permission="session.revoke")
        plane = require_plane()
        asset_id = plane.session_asset(sid)
        with transaction(platform.factory) as db:
            asset = db.get(Asset, asset_id)
            if asset is None or asset.tenant_id != auth["tenant_id"]:
                raise services.PlatformError("session_not_found", "会话不存在", 404)
        result = await plane.force_revoke(sid, tenant_id=auth["tenant_id"],
                                          trace=request.state.trace)
        with transaction(platform.factory) as db:
            services.audit(db, auth["username"], "session.force_revoked",
                           tenant_id=auth["tenant_id"],
                           detail={"sid": sid, "status": result["status"],
                                   "was_live": result["was_live"], "scope": "tenant"},
                           trace=request.state.trace)
        return result

    @app.get("/api/v2/text-input/matrix")
    async def matrix(request: Request):
        await current(request, permission="asset.read")
        sample = "".join(chr(c) for c in range(32, 127)) + "\n\t"
        rows = {level: [] for level in (text_input.VERIFIED, text_input.UNVERIFIED,
                                       text_input.KNOWN_BROKEN, text_input.UNSUPPORTED)}
        for ch in sample:
            rows[text_input.reliability(ch)].append(ch if ch.isprintable() else repr(ch))
        return {"levels": rows, "known_broken_notes": text_input._KNOWN_BROKEN,
                "max_chars": text_input._MAX_CHARS,
                "note": "verified 来自真机回读（阶段 28 与 2026-11-16 的长命令输入框）；"
                        "unverified 是未核对，不是可用。"}

    @app.post("/api/v2/text-plan")
    async def text_plan(request: Request):
        auth = await current(request, mutate=True, permission="console.open")
        body = await _json(request)
        text = body.get("text")
        if not isinstance(text, str):
            raise services.PlatformError("invalid_request", "text 必须是字符串")
        plan = text_input.plan_text(text)
        with transaction(platform.factory) as db:
            services.audit(db, auth["username"], "text_plan_previewed",
                           tenant_id=auth["tenant_id"],
                           detail={"chars": len(text), "counts": plan.counts,
                                   "has_broken": plan.has_broken}, trace=request.state.trace)
        return plan.as_dict()

    @app.get("/api/v2/workers")
    async def workers(request: Request):
        await current(request, permission="asset.read")
        roster = await platform.bus.workers()
        for worker_id in roster:
            roster[worker_id]["load"] = await platform.bus.worker_load(worker_id)
        return roster

    @app.get("/api/v2/audit")
    async def audit_log(request: Request):
        auth = await current(request, permission="audit.read")
        with transaction(platform.factory) as db:
            return services.recent_audit(db, tenant_id=auth["tenant_id"])


    @app.get("/api/v2/platform/tenants")
    async def platform_tenants(request: Request):
        await current_platform(request, permission="platform.tenant.read")
        with transaction(platform.factory) as db:
            rows = services.list_tenants(db)
            counts = {tenant["id"]: {"assets": 0, "users": 0} for tenant in rows}
            for tenant_id in counts:
                counts[tenant_id]["assets"] = db.scalar(
                    select(func.count()).select_from(Asset).where(Asset.tenant_id == tenant_id))
                counts[tenant_id]["users"] = db.scalar(
                    select(func.count()).select_from(User).where(User.tenant_id == tenant_id))
        for tenant in rows:
            tenant.update(counts.get(tenant["id"], {}))
            tenant["active_sessions"] = await platform.bus.tenant_quota_usage(tenant["id"])
        return rows

    @app.post("/api/v2/platform/tenants")
    async def platform_create_tenant(request: Request):
        auth = await current_platform(request, mutate=True, permission="platform.tenant.write")
        body = await _json(request)
        with transaction(platform.factory) as db:
            row = services.create_tenant(
                db, code=str(body.get("code", "")), name=str(body.get("name", "")),
                plan=str(body.get("plan", "standard")),
                quotas=body.get("quotas") if isinstance(body.get("quotas"), dict) else None,
                actor=auth["username"])
            return row.public()

    @app.post("/api/v2/platform/tenants/{tenant_id}/status")
    async def platform_tenant_status(tenant_id: str, request: Request):
        auth = await current_platform(request, mutate=True, permission="platform.tenant.write")
        body = await _json(request)
        with transaction(platform.factory) as db:
            row = services.set_tenant_status(db, tenant_id, str(body.get("status", "")),
                                             actor=auth["username"])
            return row.public()

    @app.patch("/api/v2/platform/tenants/{tenant_id}")
    async def platform_update_tenant(tenant_id: str, request: Request):
        auth = await current_platform(request, mutate=True, permission="platform.tenant.write")
        body = await _json(request)
        name = body.get("name")
        plan = body.get("plan")
        quotas = body.get("quotas")
        with transaction(platform.factory) as db:
            row = services.update_tenant(
                db, tenant_id,
                name=name if isinstance(name, str) else None,
                plan=plan if isinstance(plan, str) else None,
                quotas=quotas if isinstance(quotas, dict) else None,
                actor=auth["username"], now=time.time())
            return row.public()

    @app.get("/api/v2/platform/workers")
    async def platform_workers(request: Request):
        await current_platform(request, permission="platform.worker.read")
        roster = await platform.bus.workers()
        for worker_id in roster:
            roster[worker_id]["load"] = await platform.bus.worker_load(worker_id)
        return roster

    @app.post("/api/v2/platform/workers/{worker_id}/drain")
    async def platform_drain_worker(worker_id: str, request: Request):
        auth = await current_platform(request, mutate=True,
                                      permission="platform.worker.manage")
        body = await _json(request)
        draining = body.get("draining")
        if not isinstance(draining, bool):
            raise services.PlatformError("invalid_request", "draining 必须是布尔值")
        try:
            await platform.bus.set_draining(worker_id, draining, actor=auth["username"])
        except BusError as exc:
            raise services.PlatformError(exc.code, exc.message, 404) from exc
        with transaction(platform.factory) as db:
            services.audit(db, auth["username"], "worker_drain_changed", tenant_id=None,
                           actor_type="platform",
                           detail={"worker_id": worker_id, "draining": draining},
                           trace=request.state.trace)
        roster = await platform.bus.workers()
        row = dict(roster.get(worker_id) or {"worker_id": worker_id})
        row["load"] = await platform.bus.worker_load(worker_id)
        return row

    @app.get("/api/v2/platform/assets")
    async def platform_assets(request: Request, tenant_id: str = ""):
        await current_platform(request, permission="platform.asset.read")
        query = select(Asset).order_by(Asset.tenant_id, Asset.name)
        if tenant_id:
            query = query.where(Asset.tenant_id == tenant_id)
        with transaction(platform.factory) as db:
            codes = {row.id: row.code for row in db.scalars(select(Tenant))}
            return [{**{key: value for key, value in asset.public().items()
                        if key != "credential_id"},
                     "tenant_code": codes.get(asset.tenant_id)}
                    for asset in db.scalars(query).all()]

    @app.post("/api/v2/platform/assets/assign")
    async def platform_assign_asset(request: Request):
        auth = await current_platform(request, mutate=True, permission="platform.asset.write")
        body = await _json(request)
        with transaction(platform.factory) as db:
            result = services.assign_asset(
                db, address=str(body.get("address", "")),
                tenant_id=str(body.get("tenant_id", "") or ""),
                name=str(body.get("name", "") or ""), actor=auth["username"],
                reassign=bool(body.get("reassign", False)))
        return result

    @app.get("/api/v2/platform/audit")
    async def platform_audit(request: Request, limit: int = 100, tenant_id: str = ""):
        await current_platform(request, permission="platform.audit.read")
        with transaction(platform.factory) as db:
            rows = services.recent_audit(db, limit, tenant_id=tenant_id or None)
        for row in rows:
            row["detail"].pop("password", None)
            row["detail"].pop("username", None)
        return rows

    @app.get("/api/v2/platform/quota-usage")
    async def platform_quota_usage(request: Request, period: str = ""):
        await current_platform(request, permission="platform.audit.read")
        period = period or datetime.now(timezone.utc).strftime("%Y-%m")
        with transaction(platform.factory) as db:
            return services.quota_usage_view(db, period)

    @app.get("/api/v2/platform/sessions")
    async def platform_sessions(request: Request, tenant_id: str = ""):
        await current_platform(request, permission="platform.session.read")
        return await session_view(tenant_id=tenant_id or None)

    @app.post("/api/v2/platform/sessions/{sid}/revoke")
    async def platform_revoke_session(sid: str, request: Request):
        auth = await current_platform(request, mutate=True,
                                      permission="platform.session.revoke")
        result = await require_plane().force_revoke(sid, trace=request.state.trace)
        tenant_of_record = result.get("tenant_id")
        if tenant_of_record is None and result.get("asset_id"):
            with transaction(platform.factory) as db:
                asset = db.get(Asset, result["asset_id"])
                tenant_of_record = asset.tenant_id if asset is not None else None
        with transaction(platform.factory) as db:
            services.audit(db, auth["username"], "session.force_revoked",
                           tenant_id=tenant_of_record, actor_type="platform",
                           detail={"sid": sid, "status": result["status"],
                                   "was_live": result["was_live"], "scope": "platform"},
                           trace=request.state.trace)
        return result

    @app.get("/api/v2/platform/vendor-profiles")
    async def platform_vendor_profiles(request: Request):
        auth = await current_platform(request, permission="platform.vendor.read")
        stamp = time.time()
        with transaction(platform.factory) as db:
            rows = db.scalars(select(VendorProfile)
                              .order_by(VendorProfile.tenant_id,
                                        VendorProfile.priority)).all()
            return [governance.profile_view(row.public(), now=stamp,
                                            approver=auth["username"])
                    for row in rows]

    @app.get("/api/v2/platform/capabilities")
    async def platform_capabilities(request: Request, tenant_id: str = ""):
        auth = await current_platform(request, permission="platform.vendor.read")
        stamp = time.time()
        query = select(Capability).order_by(Capability.tenant_id, Capability.vendor)
        if tenant_id:
            query = query.where(Capability.tenant_id == tenant_id)
        with transaction(platform.factory) as db:
            rows = db.scalars(query).all()
            return [governance.capability_view(
                        {"id": row.id, "tenant_id": row.tenant_id, "vendor": row.vendor,
                         "model": row.model, "firmware": row.firmware,
                         "adapter": row.adapter, "status": row.status,
                         "profile_id": row.profile_id, "evidence": row.evidence,
                         "approver": row.approver, "expires": row.expires,
                         "review_due": row.review_due,
                         "models": parse_json(row.models, []),
                         "protocol_versions": parse_json(row.protocol_versions, [])},
                        now=stamp, approver=auth["username"])
                    for row in rows]

    def custom_openapi():
        if app.openapi_schema:
            return app.openapi_schema
        from fastapi.openapi.utils import get_openapi

        schema = get_openapi(title=app.title, version=app.version, routes=app.routes)
        schemas = schema.setdefault("components", {}).setdefault("schemas", {})
        schemas.update(contract_components())
        for path, methods in CONTRACT_RESPONSES.items():
            if path not in schema["paths"]:
                raise RuntimeError(f"contract declared for a missing route: {path}")
            for method, model in methods.items():
                operation = schema["paths"][path].get(method)
                if operation is None:
                    raise RuntimeError(f"contract declared for a missing method: {method} {path}")
                content = operation["responses"]["200"].setdefault("content", {})
                content.setdefault("application/json", {})["schema"] = response_schema(model)
        for item in schema["paths"].values():
            for operation in item.values():
                if not isinstance(operation, dict):
                    continue
                for status, response in operation.get("responses", {}).items():
                    if str(status).startswith(("4", "5")):
                        response.setdefault("content", {})["application/json"] = {
                            "schema": {"$ref": "#/components/schemas/ApiError"}}
        app.openapi_schema = schema
        return schema

    app.openapi = custom_openapi
    return app
