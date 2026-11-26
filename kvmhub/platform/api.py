"""Production control-plane HTTP API (FastAPI)."""
from __future__ import annotations

import asyncio
import logging
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from urllib.parse import urlsplit

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from sqlalchemy import func, select, update

from ..common import Problem, user_message
from .config import Settings, settings as load_settings
from .db import init_schema, make_engine, seed_roles, session_factory, transaction
from .models import (Asset, Capability, Credential, ProbeCandidate, ROLE_ADMIN,
                     Tenant, User, VendorProfile, parse_json)
from .redis_state import SESSION_PREFIX, State, create_state
from .security import (CredentialCipher, constant_time_equal, new_session_token,
                       token_digest)
from . import (bmc_probe, bmc_reset, connection, connection_config, governance,
               public_ip, services, text_input, vendor_registry)
from .bus import AssemblyBus, BusError
from .contracts import CONTRACT_RESPONSES, contract_components, response_schema

MAX_BODY = 65536
logger = logging.getLogger("kvmhub.platform.api")


def _tenant_admission_status(status: dict) -> dict:
    return {key: value for key, value in status.items()
            if key not in ("desired", "applied")}


async def _drop_user_sessions(state: State, user_id: str) -> None:
    for key in await state.keys(SESSION_PREFIX):
        session = await state.get(key)
        if session and session.get("user_id") == user_id:
            await state.delete(key)


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
    networks = tuple(item.strip() for item in cfg.bmc_allowed_networks.split(",") if item.strip())

    def connect() -> Store:
        return Store(cfg.data_plane_store, cfg.data_plane_key,
                     passthrough_targets=targets, strict_grants=cfg.strict_grants,
                     bmc_allowed_networks=networks)

    authority = None
    authority_host = ""
    if cfg.authority_url:
        from urllib.parse import urlparse

        from ..admission_runtime import AuthorityClient

        authority_host = urlparse(cfg.authority_url).netloc
        authority = AuthorityClient(
            cfg.authority_url, ca=cfg.authority_ca, cert=cfg.authority_cert,
            key=cfg.authority_key, public_key=private.public_key(),
            principal=cfg.authority_cert_cn or "kvmhub-authority-client")

    return ConsolePlane(store_factory=connect, private_key=private,
                        bus=AssemblyBus(state),
                        accept_template=cfg.worker_url_template or None, port=WORKER_PORT,
                        authority=authority, authority_host=authority_host,
                        permit_public_key=private.public_key(),
                        managed_domains=tuple(
                            item.strip() for item in cfg.managed_domains.split(",")
                            if item.strip()))


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


def _save_asset_from_body(db, body: dict, *, tenant_id: str, actor: str):
    edit_id = str(body.get("id") or "") or None
    existing = None
    if edit_id:
        candidate = db.get(Asset, edit_id)
        if candidate is not None and candidate.tenant_id == tenant_id:
            existing = candidate
    if existing is None:
        existing = db.scalar(select(Asset).where(
            Asset.address == str(body.get("address", "")),
            Asset.tenant_id == tenant_id))
    optional = {key: body[key] if key in body else getattr(existing, key, None)
                for key in ("vendor", "model", "firmware", "fingerprint",
                            "credential_id", "profile_id", "capability_id", "licence", "notes")}
    if existing is not None:
        if any(optional[key] != getattr(existing, key)
               for key in ("vendor", "model", "firmware", "profile_id")):
            optional["capability_id"] = None
    if optional["profile_id"]:
        defaults = services.resolve_asset_defaults(
            db, profile_id=optional["profile_id"], tenant_id=tenant_id)
        if not optional["vendor"]:
            optional["vendor"] = defaults["vendor"]
        if not optional["licence"]:
            optional["licence"] = defaults["licence"]
        if existing is None and defaults["capability_id"]:
            optional["capability_id"] = defaults["capability_id"]
    public_ips = body["public_ips"] if "public_ips" in body else None
    return services.upsert_asset(
        db, name=str(body.get("name", "")), address=str(body.get("address", "")),
        vendor=str(optional["vendor"] or ""), model=str(optional["model"] or ""),
        firmware=str(optional["firmware"] or ""), fingerprint=str(optional["fingerprint"] or ""),
        credential_id=optional["credential_id"], profile_id=optional["profile_id"],
        capability_id=optional["capability_id"], licence=str(optional["licence"] or ""),
        notes=str(optional["notes"] or ""), public_ips=public_ips,
        asset_id=edit_id, actor=actor, tenant_id=tenant_id)


def create_app(cfg: Settings | None = None, *, state: State | None = None,
               plane=None) -> FastAPI:
    platform = Platform(cfg or load_settings(), state=state, plane=plane)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        yield
        await platform.close()

    app = FastAPI(title="KVM Hub 控制面", version="2.0.0", lifespan=lifespan)
    app.state.platform = platform
    app.state.probe_semaphore = asyncio.Semaphore(4)
    app.state.probe_tasks = {}

    @app.exception_handler(services.PlatformError)
    async def on_error(request: Request, exc: services.PlatformError):
        body = {"error": exc.code, "message": exc.message,
                "trace_id": request.state.trace}
        if exc.retryable:
            body["retryable"] = True
        return JSONResponse(body, status_code=exc.status)

    @app.exception_handler(Problem)
    async def on_problem(request: Request, exc: Problem):
        body = {"error": exc.code,
                "message": user_message(exc.code) or exc.code,
                "trace_id": request.state.trace}
        if exc.detail:
            body["detail"] = exc.detail
        return JSONResponse(body, status_code=exc.status)

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
                services.require(db, auth["user_id"], permission,
                                 tenant_id=auth["tenant_id"])
        return auth

    def show_ipmi_for(auth: dict) -> bool:
        with transaction(platform.factory) as db:
            return "asset.write" in services.effective_permissions(
                db, auth["user_id"], auth["tenant_id"])

    async def current_platform(request: Request, *, mutate: bool = False,
                               permission: str | None = None) -> dict:
        auth = await current(request, mutate=mutate, tenant_required=False,
                             platform_only=True, admin=True)
        code = permission or "platform.tenant.read"
        with transaction(platform.factory) as db:
            services.require_platform(db, auth["user_id"], code)
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
            services.require(db, auth["user_id"], "console.open",
                             tenant_id=auth["tenant_id"])
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
            return {"assets": [public_ip.view(a, db, show_ipmi=True) for a in assets]}

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
                resolved = public_ip.asset_by_public_ip(
                    db, auth["tenant_id"], address)
                asset_id = resolved.id if resolved is not None else ""
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
            services.require_platform(db, user.id, "platform.tenant.read")
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
            perms = sorted(services.effective_permissions(
                db, auth["user_id"], auth["tenant_id"]))
            tenant = db.get(Tenant, auth["tenant_id"])
            tenant_mode = tenant.mode if tenant is not None else None
        return {"user_id": auth["user_id"], "username": auth["username"],
                "tenant_id": auth["tenant_id"], "tenant_mode": tenant_mode,
                "roles": auth["roles"], "permissions": perms, "csrf": auth["csrf"]}

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
                                     actor=auth["username"], tenant_id=auth["tenant_id"],
                                     plane=platform.plane)
        if not bool(body.get("active", False)):
            await _drop_user_sessions(platform.state, user_id)
        return {"ok": True}

    @app.post("/api/v2/users/{user_id}/password")
    async def reset_user_password(user_id: str, request: Request):
        auth = await current(request, mutate=True, permission="user.write")
        body = await _json(request)
        with transaction(platform.factory) as db:
            services.set_user_password(db, user_id, str(body.get("password", "")),
                                       actor=auth["username"], tenant_id=auth["tenant_id"])
        await _drop_user_sessions(platform.state, user_id)
        return {"ok": True}

    @app.get("/api/v2/assets")
    async def assets(request: Request, scope: str = "tenant"):
        if scope not in ("tenant", "granted", "all"):
            raise services.PlatformError("scope_invalid", "scope 只能是 tenant、granted 或 all", 400)
        auth = await current(request, mutate=False,
                             permission="asset.write" if scope == "all" else "asset.read")
        is_admin = ROLE_ADMIN in (auth.get("roles") or [])
        narrow = scope == "granted" or (platform.cfg.strict_grants and not is_admin)
        show_ipmi = show_ipmi_for(auth)
        with transaction(platform.factory) as db:
            db_rows = (services.assets_for_user(db, auth["user_id"], tenant_id=auth["tenant_id"])
                       if narrow else
                       services.all_assets(db, auth["user_id"], tenant_id=auth["tenant_id"]))
            by_id = {row["id"]: row for row in db_rows}
            assets = db.scalars(select(Asset).where(Asset.id.in_(by_id))).all() if by_id else []
            rows = [public_ip.view(asset, db, show_ipmi=show_ipmi) for asset in assets]
            for row in rows:
                extra = by_id.get(row["id"])
                if extra and "grant_expires" in extra:
                    row["grant_expires"] = extra["grant_expires"]
                row["admission"] = _tenant_admission_status(
                    connection_config.device_admission_status(db, asset_id=row["id"]))
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

    @app.get("/api/v2/assets/{asset_id}/admission")
    async def asset_admission_status(asset_id: str, request: Request):
        auth = await current(request, permission="asset.read")
        with transaction(platform.factory) as db:
            is_admin = ROLE_ADMIN in (auth.get("roles") or [])
            visible = (services.all_assets(db, auth["user_id"], tenant_id=auth["tenant_id"])
                       if is_admin else
                       services.assets_for_user(db, auth["user_id"], tenant_id=auth["tenant_id"]))
            if asset_id not in {row["id"] for row in visible}:
                raise services.PlatformError("asset_not_found", "资产不存在", 404)
            return _tenant_admission_status(
                connection_config.device_admission_status(db, asset_id=asset_id))

    @app.post("/api/v2/assets")
    async def upsert_asset(request: Request):
        auth = await current(request, mutate=True, permission="asset.write")
        body = await _json(request)
        with transaction(platform.factory) as db:
            asset = _save_asset_from_body(
                db, body, tenant_id=auth["tenant_id"], actor=auth["username"])
            return public_ip.view(asset, db, show_ipmi=True)

    @app.get("/api/v2/public-ips")
    async def list_public_ips(request: Request):
        auth = await current(request, permission="asset.write")
        with transaction(platform.factory) as db:
            rows = db.scalars(select(public_ip.PublicIpMapping).where(
                public_ip.PublicIpMapping.tenant_id == auth["tenant_id"]).order_by(
                    public_ip.PublicIpMapping.primary_ip)).all()
            return [public_ip.mapping_view(row) for row in rows]

    @app.put("/api/v2/public-ips/{asset_id}")
    async def put_public_ip(asset_id: str, request: Request):
        auth = await current(request, mutate=True, permission="asset.write")
        body = await _json(request)
        with transaction(platform.factory) as db:
            mapping = public_ip.upsert_public_ip(
                db, tenant_id=auth["tenant_id"], asset_id=asset_id,
                raw=body.get("public_ips", ""), actor=auth["username"])
            db.commit()
            return public_ip.mapping_view(mapping) if mapping is not None else {
                "id": "", "tenant_id": auth["tenant_id"], "asset_id": asset_id,
                "primary_ip": "", "additional_ips": "", "public_ips": [],
                "created": 0, "updated": 0}

    async def _measure_identity(auth: dict, *, address: str, credential_id: str,
                                port: int, public_ips, trace: str,
                                acquire_timeout: float = 2.0, on_step=None) -> dict:
        with transaction(platform.factory) as db:
            secret = services.read_credential(
                db, platform.cipher, credential_id, tenant_id=auth["tenant_id"])
        semaphore = app.state.probe_semaphore
        try:
            await asyncio.wait_for(semaphore.acquire(), timeout=acquire_timeout)
        except TimeoutError:
            raise services.PlatformError(
                "probe_busy", "探测请求过多，请稍后重试", 429, retryable=True) from None
        try:
            probe_kwargs = {"on_step": on_step} if on_step is not None else {}
            measured = await asyncio.to_thread(
                bmc_probe.probe, address, secret["username"], secret["password"],
                port=port, allowed_networks=platform.cfg.bmc_allowed_networks,
                require_networks=platform.cfg.is_prod, **probe_kwargs)
        except bmc_probe.ProbeError as exc:
            safe_address = address.encode("unicode_escape").decode("ascii")[:256]
            logger.warning("asset_probe_failed address=%s code=%s retryable=%s trace=%s",
                           safe_address, exc.code, exc.retryable, trace)
            with transaction(platform.factory) as db:
                services.audit(
                    db, auth["username"], "asset_probe_failed", tenant_id=auth["tenant_id"],
                    detail={"address": address, "error": exc.code,
                            "retryable": exc.retryable}, trace=trace)
            raise services.PlatformError(
                "asset_probe_failed", "BMC 探测失败，请核对地址、凭据与网络", 502,
                retryable=exc.retryable) from None
        finally:
            semaphore.release()
        detection = vendor_registry.detect_from_redfish(measured["inventory"])
        with transaction(platform.factory) as db:
            match = vendor_registry.identify(db, detection, tenant_id=auth["tenant_id"])
            profile = match.profile if match.usable else None
            services.audit(
                db, auth["username"], "asset_probe", tenant_id=auth["tenant_id"],
                detail={"address": address, "vendor": detection.get("vendor", ""),
                        "model": detection.get("model", ""),
                        "fingerprint_prefix": measured["fingerprint"][:12],
                        "profile_id": profile.id if profile else None,
                        "auth_mode": measured["redfish_auth"]}, trace=trace)
        note = ("已匹配已批准品牌，可自动关联"
                if profile else "未匹配到已批准品牌；未完成适配的型号请走新品牌适配流程")
        return {"address": address, "public_ips": public_ip.normalize_public_ips(public_ips),
                "certificate_sha256": measured["fingerprint"],
                "redfish_auth": measured["redfish_auth"], "detection": detection,
                "matched": match.profile is not None, "usable": match.usable,
                "reason": match.reason, "profile_id": profile.id if profile else None,
                "profile_code": profile.code if profile else "", "note": note}

    @app.post("/api/v2/assets/probe")
    async def probe_asset(request: Request):
        auth = await current(request, mutate=True, permission="asset.write")
        body = await _json(request)
        address = str(body.get("address", "")).strip()
        credential_id = str(body.get("credential_id", "")).strip()
        if not address or not credential_id:
            raise services.PlatformError("invalid_request", "需要 BMC 地址和凭据")
        try:
            port = int(body.get("port", 443) or 443)
        except (TypeError, ValueError):
            raise services.PlatformError("invalid_request", "端口必须是整数") from None
        return await _measure_identity(
            auth, address=address, credential_id=credential_id, port=port,
            public_ips=body.get("public_ips"), trace=request.state.trace)

    @app.post("/api/v2/assets/probe/batch")
    async def probe_assets_batch(request: Request):
        auth = await current(request, mutate=True, permission="asset.write")
        body = await _json(request)
        ids = body.get("asset_ids")
        if not isinstance(ids, list) or not ids:
            raise services.PlatformError("invalid_request", "asset_ids 必须是非空数组", 400)
        wanted = list(dict.fromkeys(str(aid) for aid in ids))
        if len(wanted) > 100:
            raise services.PlatformError("probe_batch_too_large", "单次最多探测 100 台", 400)
        try:
            port = int(body.get("port", 443) or 443)
        except (TypeError, ValueError):
            raise services.PlatformError("invalid_request", "端口必须是整数", 400) from None
        with transaction(platform.factory) as db:
            rows = db.execute(select(Asset.id, Asset.address, Asset.credential_id).where(
                Asset.id.in_(wanted), Asset.tenant_id == auth["tenant_id"])).all()
        by_id = {row[0]: (row[1], row[2]) for row in rows}
        missing = [aid for aid in wanted if aid not in by_id]

        async def measure(asset_id: str) -> dict:
            address, credential_id = by_id[asset_id]
            if not credential_id:
                return {"asset_id": asset_id, "address": address, "ok": False,
                        "error": {"code": "credential_missing",
                                  "message": "该资产未绑定 BMC 凭据", "retryable": False}}
            for attempt in range(2):
                try:
                    result = await _measure_identity(
                        auth, address=address, credential_id=credential_id, port=port,
                        public_ips=[], trace=request.state.trace, acquire_timeout=10.0)
                    return {"asset_id": asset_id, "address": address, "ok": True,
                            "result": result}
                except services.PlatformError as exc:
                    if exc.retryable and attempt == 0:
                        continue
                    return {"asset_id": asset_id, "address": address, "ok": False,
                            "error": {"code": exc.code, "message": exc.message,
                                      "retryable": bool(exc.retryable)}}
                except Exception:
                    return {"asset_id": asset_id, "address": address, "ok": False,
                            "error": {"code": "probe_unexpected",
                                      "message": "探测出现未预期错误", "retryable": True}}
            return {"asset_id": asset_id, "address": address, "ok": False,
                    "error": {"code": "probe_unexpected",
                              "message": "探测出现未预期错误", "retryable": True}}

        items = list(await asyncio.gather(*(measure(aid) for aid in wanted if aid in by_id)))
        with transaction(platform.factory) as db:
            services.audit(
                db, auth["username"], "asset_probe_batch", tenant_id=auth["tenant_id"],
                detail={"total": len(wanted), "ok": sum(1 for item in items if item["ok"]),
                        "missing": missing}, trace=request.state.trace)
        return {"total": len(wanted), "items": items, "missing": missing}

    def _write_probe_candidate(auth: dict, asset_id: str, result: dict,
                               trace: str) -> bool:
        now = time.time()
        with transaction(platform.factory) as db:
            asset = db.get(Asset, asset_id)
            if asset is None or asset.tenant_id != auth["tenant_id"]:
                return False
            detection = result.get("detection") or {}
            profile = (db.get(VendorProfile, result["profile_id"])
                       if result.get("profile_id") else None)
            changed = (detection.get("vendor", "") != asset.vendor
                       or detection.get("model", "") != asset.model
                       or detection.get("firmware", "") != asset.firmware
                       or (result.get("profile_id") or None) != asset.profile_id)
            if not changed:
                return False
            db.execute(update(ProbeCandidate).where(
                ProbeCandidate.asset_id == asset_id,
                ProbeCandidate.state == "pending").values(
                    state="superseded", resolved=now, resolved_by="new-probe"))
            db.add(ProbeCandidate(
                id=uuid.uuid4().hex, asset_id=asset_id, tenant_id=asset.tenant_id,
                state="pending", vendor=detection.get("vendor", ""),
                model=detection.get("model", ""), firmware=detection.get("firmware", ""),
                profile_id=result.get("profile_id") or None,
                capability_id=profile.default_capability_id if profile else None,
                fingerprint=result.get("certificate_sha256", ""),
                reason=result.get("reason", ""), created=now))
            services.audit(db, auth["username"], "probe_candidate_created",
                           tenant_id=auth["tenant_id"], asset_id=asset_id,
                           detail={"profile_id": result.get("profile_id")}, trace=trace)
            return True

    @app.post("/api/v2/assets/probe/batch/async")
    async def probe_assets_batch_async(request: Request):
        auth = await current(request, mutate=True, permission="asset.write")
        body = await _json(request)
        ids = body.get("asset_ids")
        if not isinstance(ids, list) or not ids:
            raise services.PlatformError("invalid_request", "asset_ids 必须是非空数组", 400)
        wanted = list(dict.fromkeys(str(aid) for aid in ids))
        if len(wanted) > 100:
            raise services.PlatformError("probe_batch_too_large", "单次最多探测 100 台", 400)
        try:
            port = int(body.get("port", 443) or 443)
        except (TypeError, ValueError):
            raise services.PlatformError("invalid_request", "端口必须是整数", 400) from None
        with transaction(platform.factory) as db:
            rows = db.execute(select(Asset.id, Asset.address, Asset.credential_id).where(
                Asset.id.in_(wanted), Asset.tenant_id == auth["tenant_id"])).all()
        by_id = {row[0]: (row[1], row[2]) for row in rows}
        trace = request.state.trace
        task_id = uuid.uuid4().hex
        task = {"task_id": task_id, "state": "running", "total": len(wanted),
                "completed": 0, "created": time.time(), "tenant_id": auth["tenant_id"],
                "items": [{"asset_id": aid, "address": by_id.get(aid, (aid, ""))[0],
                           "step": "queued", "ok": None, "error": None, "result": None}
                          for aid in wanted]}
        app.state.probe_tasks[task_id] = task

        async def run():
            async def one(item):
                aid = item["asset_id"]
                if aid not in by_id or not by_id[aid][1]:
                    item["step"] = "failed"
                    item["ok"] = False
                    item["error"] = {"code": "credential_missing",
                                     "message": "资产不存在或未绑定 BMC 凭据",
                                     "retryable": False}
                    task["completed"] += 1
                    return
                address, credential_id = by_id[aid]

                def step(name):
                    item["step"] = name

                for attempt in range(2):
                    try:
                        item["step"] = "connecting"
                        result = await _measure_identity(
                            auth, address=address, credential_id=credential_id,
                            port=port, public_ips=[], trace=trace,
                            acquire_timeout=10.0, on_step=step)
                        item["step"] = "identify"
                        candidates = await asyncio.to_thread(
                            _write_probe_candidate, auth, aid, result, trace)
                        item["candidate_created"] = candidates
                        item["step"] = "done"
                        item["ok"] = True
                        item["result"] = result
                        break
                    except services.PlatformError as exc:
                        if exc.retryable and attempt == 0:
                            continue
                        item["step"] = "failed"
                        item["ok"] = False
                        item["error"] = {"code": exc.code, "message": exc.message,
                                         "retryable": bool(exc.retryable)}
                        break
                    except Exception:
                        item["step"] = "failed"
                        item["ok"] = False
                        item["error"] = {"code": "probe_unexpected",
                                         "message": "探测出现未预期错误", "retryable": True}
                        break
                task["completed"] += 1

            try:
                await asyncio.gather(*(one(item) for item in task["items"]))
                task["state"] = "done"
            except Exception:
                task["state"] = "failed"
            finally:
                cutoff = time.time() - 3600
                for key, value in list(app.state.probe_tasks.items()):
                    if value["created"] < cutoff and value["state"] != "running":
                        app.state.probe_tasks.pop(key, None)

        asyncio.create_task(run())
        return {"task_id": task_id, "total": len(wanted)}

    @app.get("/api/v2/assets/probe/tasks/{task_id}")
    async def probe_task_status(task_id: str, request: Request):
        auth = await current(request, permission="asset.write")
        cutoff = time.time() - 3600
        for key, value in list(app.state.probe_tasks.items()):
            if value["created"] < cutoff and value["state"] != "running":
                app.state.probe_tasks.pop(key, None)
        task = app.state.probe_tasks.get(task_id)
        if task is None or task["tenant_id"] != auth["tenant_id"]:
            raise services.PlatformError(
                "probe_task_not_found",
                "探测任务已结束或控制面重启过；请重新发起批量探测", 404)
        return task

    @app.get("/api/v2/assets/probe/candidates")
    async def probe_candidates(request: Request, asset_id: str = ""):
        auth = await current(request, permission="asset.write")
        with transaction(platform.factory) as db:
            query = (select(ProbeCandidate, Asset.name, Asset.vendor,
                            Asset.model, Asset.firmware)
                     .join(Asset, Asset.id == ProbeCandidate.asset_id)
                     .where(ProbeCandidate.tenant_id == auth["tenant_id"],
                            ProbeCandidate.state == "pending"))
            if asset_id:
                query = query.where(ProbeCandidate.asset_id == asset_id)
            rows = db.execute(query.order_by(ProbeCandidate.created.desc())).all()
            return [{"id": row.id, "asset_id": row.asset_id, "asset_name": name,
                     "state": row.state, "vendor": row.vendor, "model": row.model,
                     "firmware": row.firmware, "profile_id": row.profile_id,
                     "capability_id": row.capability_id, "fingerprint": row.fingerprint,
                     "reason": row.reason, "created": row.created,
                     "current_vendor": current_vendor, "current_model": current_model,
                     "current_firmware": current_firmware}
                    for row, name, current_vendor, current_model, current_firmware in rows]

    @app.post("/api/v2/assets/probe/candidates/approve")
    async def approve_probe_candidates(request: Request):
        auth = await current(request, mutate=True, permission="asset.write")
        body = await _json(request)
        ids = body.get("ids")
        if not isinstance(ids, list) or not ids:
            raise services.PlatformError("invalid_request", "ids 必须是非空数组", 400)
        wanted = list(dict.fromkeys(str(aid) for aid in ids))
        adopt = bool(body.get("adopt_fingerprint"))
        approved, failed = [], []
        trace = request.state.trace
        with transaction(platform.factory) as db:
            rows = db.scalars(select(ProbeCandidate).where(
                ProbeCandidate.id.in_(wanted),
                ProbeCandidate.tenant_id == auth["tenant_id"],
                ProbeCandidate.state == "pending")).all()
            by_id = {row.id: row for row in rows}
            for cid in wanted:
                row = by_id.get(cid)
                if row is None:
                    failed.append({"id": cid, "reason": "candidate_not_found"})
                    continue
                asset = db.get(Asset, row.asset_id)
                if asset is None or asset.tenant_id != auth["tenant_id"]:
                    failed.append({"id": cid, "reason": "asset_not_found"})
                    continue
                stamp = time.time()
                try:
                    services.upsert_asset(
                        db, name=asset.name, address=asset.address,
                        vendor=row.vendor, model=row.model, firmware=row.firmware,
                        fingerprint=row.fingerprint if adopt else (asset.fingerprint or ""),
                        credential_id=asset.credential_id,
                        profile_id=row.profile_id, capability_id=row.capability_id,
                        licence=asset.licence or "", notes=asset.notes or "",
                        public_ips=None, actor=auth["username"], asset_id=asset.id,
                        tenant_id=auth["tenant_id"], now=stamp)
                except services.PlatformError as exc:
                    if exc.code == "clock_regression":
                        raise
                    failed.append({"id": cid, "reason": exc.code})
                    continue
                row.state = "approved"
                row.resolved = stamp
                row.resolved_by = auth["username"]
                db.execute(update(ProbeCandidate).where(
                    ProbeCandidate.asset_id == row.asset_id,
                    ProbeCandidate.state == "pending",
                    ProbeCandidate.id != row.id).values(
                        state="superseded", resolved=stamp, resolved_by=auth["username"]))
                approved.append(row.asset_id)
            services.audit(db, auth["username"], "probe_candidate_approved",
                           tenant_id=auth["tenant_id"],
                           detail={"approved": approved, "failed": failed,
                                   "adopt_fingerprint": adopt}, trace=trace)
        return {"approved": len(approved), "failed": failed,
                "note": "身份变更已提交；设备进入待准入，重新批准后才能连接"}

    @app.post("/api/v2/assets/probe/candidates/{candidate_id}/reject")
    async def reject_probe_candidate(candidate_id: str, request: Request):
        auth = await current(request, mutate=True, permission="asset.write")
        with transaction(platform.factory) as db:
            row = db.get(ProbeCandidate, candidate_id)
            if row is None or row.tenant_id != auth["tenant_id"] or row.state != "pending":
                raise services.PlatformError("candidate_not_found", "候选变更不存在", 404)
            row.state = "rejected"
            row.resolved = time.time()
            row.resolved_by = auth["username"]
            services.audit(db, auth["username"], "probe_candidate_rejected",
                           tenant_id=auth["tenant_id"], asset_id=row.asset_id,
                           trace=request.state.trace)
        return {"ok": True}

    @app.get("/api/v2/asset-onboarding")
    async def asset_onboarding(request: Request):
        auth = await current(request, permission="asset.read")
        with transaction(platform.factory) as db:
            return services.asset_onboarding(db, tenant_id=auth["tenant_id"])

    @app.get("/api/v2/credentials")
    async def list_credentials(request: Request):
        auth = await current(request, permission="credential.write")
        with transaction(platform.factory) as db:
            rows = db.scalars(select(Credential)
                              .where(Credential.tenant_id == auth["tenant_id"])
                              .order_by(Credential.created)).all()
            return [row.public() for row in rows]

    @app.get('/api/v2/profile-overlays')
    async def list_profile_overlays(request: Request):
        auth = await current(request, permission='profile.overlay.write')
        from . import overlays
        from .models import ProfileOverlay, ProfileOverlayRevision
        with transaction(platform.factory) as db:
            return [overlays.public(row, db.get(ProfileOverlayRevision,
                     (row.id, row.current_revision))) for row in db.scalars(
                         select(ProfileOverlay).where(ProfileOverlay.tenant_id == auth['tenant_id'])
                         .order_by(ProfileOverlay.id)).all()]

    @app.put('/api/v2/profile-overlays/{profile_id}')
    async def save_profile_overlay(profile_id: str, request: Request):
        auth = await current(request, mutate=True, permission='profile.overlay.write')
        body = await _json(request)
        if set(body) != {'expected_revision', 'subset'}:
            raise services.PlatformError('invalid_request', '需要 expected_revision 与 subset')
        from . import overlays
        with transaction(platform.factory) as db:
            return overlays.save(db, tenant_id=auth['tenant_id'], user_id=auth['user_id'],
                profile_id=profile_id, payload=body['subset'], expected_revision=body['expected_revision'])

    @app.post('/api/v2/profile-overlays/{overlay_id}/disable')
    async def disable_profile_overlay(overlay_id: str, request: Request):
        auth = await current(request, mutate=True, permission='profile.overlay.write')
        body = await _json(request)
        if set(body) != {'expected_revision'}:
            raise services.PlatformError('invalid_request', '需要 expected_revision')
        from . import overlays
        with transaction(platform.factory) as db:
            return overlays.change_state(db, overlay_id=overlay_id, state='disabled',
                expected_revision=body['expected_revision'], user_id=auth['user_id'],
                tenant_id=auth['tenant_id'])

    @app.put('/api/v2/assets/{asset_id}/profile-overlay')
    async def bind_profile_overlay(asset_id: str, request: Request):
        auth = await current(request, mutate=True, permission='profile.overlay.write')
        body = await _json(request)
        if set(body) != {'overlay_id', 'revision'}:
            raise services.PlatformError('invalid_request', '需要 overlay_id 与 revision')
        from . import overlays
        with transaction(platform.factory) as db:
            return overlays.bind(db, asset_id=asset_id, overlay_id=body['overlay_id'],
                revision=body['revision'], user_id=auth['user_id'], tenant_id=auth['tenant_id'])

    @app.post('/api/v2/platform/profile-overlays/{overlay_id}/withdraw')
    async def withdraw_profile_overlay(overlay_id: str, request: Request):
        auth = await current_platform(request, mutate=True, permission='platform.asset.admit')
        body = await _json(request)
        if set(body) != {'expected_revision'}:
            raise services.PlatformError('invalid_request', '需要 expected_revision')
        from . import overlays
        with transaction(platform.factory) as db:
            return overlays.change_state(db, overlay_id=overlay_id, state='withdrawn',
                expected_revision=body['expected_revision'], user_id=auth['user_id'], platform=True)

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
        plane = platform.plane
        with transaction(platform.factory) as db:
            services.grant_asset(
                db, user_id=str(body.get("user_id", "")),
                asset_id=str(body.get("asset_id", "")), actor=auth["username"],
                ttl_seconds=int(body.get("ttl_seconds", 86400 * 30)),
                tenant_id=auth["tenant_id"],
                actor_user_id=auth["user_id"] if platform.cfg.strict_grants else None,
                plane=plane)
        return {"ok": True}

    @app.post("/api/v2/grants/renew")
    async def renew_grants(request: Request):
        auth = await current(request, mutate=True, permission="grant.write")
        body = await _json(request)
        user_id = str(body.get("user_id") or auth["user_id"])
        asset_ids = body.get("asset_ids")
        if not isinstance(asset_ids, list):
            raise services.PlatformError("invalid_request", "asset_ids 必须是数组", 400)
        ttl = body.get("ttl_seconds")
        absolute = body.get("expires")
        if (ttl is None) == (absolute is None):
            raise services.PlatformError(
                "invalid_request", "ttl_seconds 与 expires 必须且只能提供一个", 400)
        now = time.time()
        seconds = None
        deadline = None
        if ttl is not None:
            try:
                seconds = int(ttl)
            except (TypeError, ValueError):
                raise services.PlatformError("invalid_request", "ttl_seconds 必须是整数秒", 400) from None
            if seconds < 60 or seconds > 10 * 366 * 86400:
                raise services.PlatformError("grant_expiry_invalid", "续期时长须在 1 分钟到 10 年之间", 400)
        else:
            try:
                deadline = float(absolute)
            except (TypeError, ValueError):
                raise services.PlatformError("invalid_request", "expires 必须是 Unix 时间戳", 400) from None
            if deadline > now + 10 * 366 * 86400:
                raise services.PlatformError("grant_expiry_invalid", "到期时间不能超过 10 年后", 400)
        with transaction(platform.factory) as db:
            return services.renew_grants(
                db, user_id=user_id, asset_ids=[str(aid) for aid in asset_ids],
                expires=deadline, extend_seconds=seconds, actor=auth["username"],
                tenant_id=auth["tenant_id"], plane=platform.plane, now=now,
                actor_user_id=auth["user_id"] if platform.cfg.strict_grants else None)

    @app.post("/api/v2/grants/batch")
    async def grants_batch(request: Request):
        auth = await current(request, mutate=True, permission="grant.write")
        body = await _json(request)
        action = str(body.get("action") or "")
        user_id = str(body.get("user_id") or auth["user_id"])
        now = time.time()
        ttl = body.get("ttl_seconds")
        absolute = body.get("expires")
        if ttl is not None:
            try:
                ttl_seconds = int(ttl)
            except (TypeError, ValueError):
                raise services.PlatformError("invalid_request", "ttl_seconds 必须是整数秒", 400) from None
        else:
            ttl_seconds = None
        if ttl_seconds is not None and not 60 <= ttl_seconds <= 10 * 366 * 86400:
            raise services.PlatformError("grant_expiry_invalid", "续期时长须在 1 分钟到 10 年之间", 400)
        if absolute is not None:
            try:
                absolute = float(absolute)
            except (TypeError, ValueError):
                raise services.PlatformError("invalid_request", "expires 必须是 Unix 时间戳", 400) from None
        if action in ("grant", "group_sync") and absolute is not None:
            ttl_seconds = max(60, int(absolute - now))
        if action == "group_sync":
            group_id = str(body.get("group_id") or "")
            if not group_id:
                raise services.PlatformError("invalid_request", "group_sync 需要 group_id", 400)
            with transaction(platform.factory) as db:
                out = services.grant_group(
                    db, group_id=group_id, user_id=user_id, actor=auth["username"],
                    tenant_id=auth["tenant_id"], plane=platform.plane,
                    ttl_seconds=ttl_seconds or 86400 * 30, now=now,
                    actor_user_id=auth["user_id"] if platform.cfg.strict_grants else None)
            return {"action": action, "user_id": user_id, "total": 1,
                    "changed": out["granted"], "items": [],
                    "note": f"组授权完成：新增 {out['granted']} 条，撤销 {out['revoked_stale']} 条"}
        if action not in ("grant", "renew", "revoke"):
            raise services.PlatformError("invalid_request", "action 必须是 grant/renew/revoke/group_sync", 400)
        ids = body.get("asset_ids")
        if not isinstance(ids, list) or not ids:
            raise services.PlatformError("invalid_request", "asset_ids 必须是非空数组", 400)
        asset_ids = list(dict.fromkeys(str(aid) for aid in ids))
        if len(asset_ids) > 500:
            raise services.PlatformError("grant_batch_too_large", "单次最多处理 500 台", 400)
        if action == "renew" and (ttl_seconds is None) == (absolute is None):
            raise services.PlatformError("invalid_request", "续期需要 ttl_seconds 或 expires 之一", 400)
        items = []
        with transaction(platform.factory) as db:
            if action == "renew":
                out = services.renew_grants(
                    db, user_id=user_id, asset_ids=asset_ids, actor=auth["username"],
                    tenant_id=auth["tenant_id"], plane=platform.plane, now=now,
                    extend_seconds=ttl_seconds, expires=absolute,
                    actor_user_id=auth["user_id"] if platform.cfg.strict_grants else None)
                missing = set(out["missing"])
                for aid in asset_ids:
                    items.append({"asset_id": aid,
                                  "status": "missing" if aid in missing else "renewed",
                                  "reason": "",
                                  "expires": None if aid in missing else out["expires"]})
            else:
                for aid in asset_ids:
                    try:
                        if action == "grant":
                            services.grant_asset(
                                db, user_id=user_id, asset_id=aid, actor=auth["username"],
                                tenant_id=auth["tenant_id"], plane=platform.plane, now=now,
                                ttl_seconds=ttl_seconds or 86400 * 30,
                                actor_user_id=auth["user_id"] if platform.cfg.strict_grants else None)
                            items.append({"asset_id": aid, "status": "granted", "reason": "",
                                          "expires": now + (ttl_seconds or 86400 * 30)})
                        else:
                            services.revoke_grant(
                                db, user_id=user_id, asset_id=aid, actor=auth["username"],
                                tenant_id=auth["tenant_id"], plane=platform.plane)
                            items.append({"asset_id": aid, "status": "revoked", "reason": "",
                                          "expires": None})
                    except services.PlatformError as exc:
                        items.append({"asset_id": aid, "status": "denied", "reason": exc.code,
                                      "expires": None})
        changed = sum(1 for item in items
                      if item["status"] in ("granted", "renewed", "revoked"))
        return {"action": action, "user_id": user_id, "total": len(asset_ids),
                "changed": changed, "items": items, "note": ""}

    @app.get("/api/v2/asset-groups")
    async def list_groups(request: Request):
        auth = await current(request, permission="grant.write")
        with transaction(platform.factory) as db:
            return services.list_asset_groups(db, auth["tenant_id"])

    @app.post("/api/v2/asset-groups")
    async def create_group(request: Request):
        auth = await current(request, mutate=True, permission="asset.write")
        body = await _json(request)
        with transaction(platform.factory) as db:
            row = services.create_asset_group(db, name=str(body.get("name", "")),
                                              actor=auth["username"],
                                              tenant_id=auth["tenant_id"])
            return row.public()

    @app.put("/api/v2/asset-groups/{group_id}/members")
    async def set_group_members(group_id: str, request: Request):
        auth = await current(request, mutate=True, permission="asset.write")
        body = await _json(request)
        ids = body.get("asset_ids")
        if not isinstance(ids, list):
            raise services.PlatformError("invalid_request", "asset_ids 必须是数组")
        with transaction(platform.factory) as db:
            return services.set_group_members(
                db, group_id=group_id, asset_ids=[str(x) for x in ids],
                actor=auth["username"], tenant_id=auth["tenant_id"])

    @app.delete("/api/v2/asset-groups/{group_id}")
    async def delete_group(group_id: str, request: Request):
        auth = await current(request, mutate=True, permission="asset.write")
        with transaction(platform.factory) as db:
            services.delete_asset_group(db, group_id=group_id, actor=auth["username"],
                                        tenant_id=auth["tenant_id"])
        return {"ok": True}

    @app.post("/api/v2/asset-groups/{group_id}/grant")
    async def grant_group(group_id: str, request: Request):
        auth = await current(request, mutate=True, permission="grant.write")
        body = await _json(request)
        plane = platform.plane
        with transaction(platform.factory) as db:
            return services.grant_group(
                db, group_id=group_id, user_id=str(body.get("user_id", "")),
                actor=auth["username"], tenant_id=auth["tenant_id"], plane=plane,
                ttl_seconds=int(body.get("ttl_seconds", 86400 * 30)))

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

    async def session_view(*, tenant_id: str | None = None,
                           show_ipmi: bool = True) -> list[dict]:
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
            public_ips = {asset.id: public_ip.public_ips_for_asset(db, asset.id)
                          for asset in assets.values()}
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
                "asset_address": asset.address if asset and show_ipmi else None,
                "asset_public_ip": (public_ips.get(row["asset_id"]) or [None])[0],
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
                services.require(db, auth["user_id"], "asset.write",
                                 tenant_id=auth["tenant_id"])
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
        return await session_view(tenant_id=auth["tenant_id"],
                                  show_ipmi=show_ipmi_for(auth))

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
                                          trace=request.state.trace,
                                          actor=auth["username"])
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
                "max_chars": text_input._MAX_CHARS}

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
                mode=str(body.get("mode", "manager")),
                quotas=body.get("quotas") if isinstance(body.get("quotas"), dict) else None,
                actor=auth["username"])
            return row.public()

    @app.post("/api/v2/platform/tenants/{tenant_id}/status")
    async def platform_tenant_status(tenant_id: str, request: Request):
        auth = await current_platform(request, mutate=True, permission="platform.tenant.write")
        body = await _json(request)
        with transaction(platform.factory) as db:
            row = services.set_tenant_status(db, tenant_id, str(body.get("status", "")),
                                             actor=auth["username"], plane=platform.plane)
            return row.public()

    @app.patch("/api/v2/platform/tenants/{tenant_id}")
    async def platform_update_tenant(tenant_id: str, request: Request):
        auth = await current_platform(request, mutate=True, permission="platform.tenant.write")
        body = await _json(request)
        name = body.get("name")
        plan = body.get("plan")
        mode = body.get("mode")
        quotas = body.get("quotas")
        with transaction(platform.factory) as db:
            row = services.update_tenant(
                db, tenant_id,
                name=name if isinstance(name, str) else None,
                plan=plan if isinstance(plan, str) else None,
                mode=mode if isinstance(mode, str) else None,
                quotas=quotas if isinstance(quotas, dict) else None,
                actor=auth["username"], now=time.time())
            return row.public()

    @app.get("/api/v2/platform/users")
    async def platform_users(request: Request, tenant_id: str = ""):
        await current_platform(request, permission="platform.user.read")
        if not tenant_id:
            raise services.PlatformError("tenant_id_required", "请指定租户", 400)
        with transaction(platform.factory) as db:
            if db.get(Tenant, tenant_id) is None:
                raise services.PlatformError("tenant_not_found", "租户不存在", 404)
            return services.list_users(db, tenant_id=tenant_id)

    @app.post("/api/v2/platform/tenants/{tenant_id}/users")
    async def platform_create_user(tenant_id: str, request: Request):
        auth = await current_platform(request, mutate=True, permission="platform.user.write")
        body = await _json(request)
        with transaction(platform.factory) as db:
            if db.get(Tenant, tenant_id) is None:
                raise services.PlatformError("tenant_not_found", "租户不存在", 404)
            user = services.create_user(
                db, str(body.get("username", "")), str(body.get("password", "")),
                str(body.get("role", "viewer")), actor=auth["username"],
                display_name=str(body.get("display_name", "")), tenant_id=tenant_id)
            return {**user.public(), "roles": services.roles_of(db, user.id)}

    @app.post("/api/v2/platform/users/{user_id}/active")
    async def platform_set_user_active(user_id: str, request: Request):
        auth = await current_platform(request, mutate=True, permission="platform.user.write")
        body = await _json(request)
        active = bool(body.get("active", False))
        with transaction(platform.factory) as db:
            services.set_user_active(db, user_id, active, actor=auth["username"],
                                     tenant_id=None, plane=platform.plane)
        if not active:
            await _drop_user_sessions(platform.state, user_id)
        return {"ok": True}

    @app.patch("/api/v2/platform/users/{user_id}/role")
    async def platform_set_user_role(user_id: str, request: Request):
        auth = await current_platform(request, mutate=True, permission="platform.user.write")
        body = await _json(request)
        with transaction(platform.factory) as db:
            user = services.set_user_role(db, user_id, str(body.get("role", "")),
                                          actor=auth["username"], tenant_id=None,
                                          plane=platform.plane)
            result = {**user.public(), "roles": services.roles_of(db, user_id)}
        await _drop_user_sessions(platform.state, user_id)
        return result

    @app.post("/api/v2/platform/users/{user_id}/password")
    async def platform_reset_user_password(user_id: str, request: Request):
        auth = await current_platform(request, mutate=True, permission="platform.user.write")
        body = await _json(request)
        with transaction(platform.factory) as db:
            services.set_user_password(db, user_id, str(body.get("password", "")),
                                       actor=auth["username"], tenant_id=None)
        await _drop_user_sessions(platform.state, user_id)
        return {"ok": True}

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
            return [{**{key: value for key, value in public_ip.view(
                            asset, db, show_ipmi=True).items() if key != "credential_id"},
                     "tenant_code": codes.get(asset.tenant_id)}
                    for asset in db.scalars(query).all()]

    @app.get("/api/v2/platform/assets/{asset_id}/admission")
    async def platform_asset_admission_status(asset_id: str, request: Request):
        await current_platform(request, permission="platform.asset.read")
        with transaction(platform.factory) as db:
            if db.get(Asset, asset_id) is None:
                raise services.PlatformError("asset_not_found", "资产不存在", 404)
            return connection_config.device_admission_status(db, asset_id=asset_id)

    @app.post("/api/v2/platform/assets")
    async def platform_create_asset(request: Request):
        auth = await current_platform(request, mutate=True, permission="platform.asset.write")
        body = await _json(request)
        tenant_id = str(body.get("tenant_id", "") or "")
        with transaction(platform.factory) as db:
            if not tenant_id or db.get(Tenant, tenant_id) is None:
                raise services.PlatformError("tenant_not_found", "租户不存在", 404)
            asset = _save_asset_from_body(
                db, body, tenant_id=tenant_id, actor=auth["username"])
            return public_ip.view(asset, db, show_ipmi=True)

    @app.post("/api/v2/platform/assets/assign")
    async def platform_assign_asset(request: Request):
        auth = await current_platform(request, mutate=True, permission="platform.asset.write")
        body = await _json(request)
        plane = platform.plane
        with transaction(platform.factory) as db:
            result = services.assign_asset(
                db, address=str(body.get("address", "")),
                tenant_id=str(body.get("tenant_id", "") or ""),
                name=str(body.get("name", "") or ""), actor=auth["username"],
                reassign=bool(body.get("reassign", False)), plane=plane)
            asset = db.get(Asset, result["asset"]["id"])
            if asset is not None:
                result["asset"] = public_ip.view(asset, db, show_ipmi=True)
        return result

    @app.post("/api/v2/platform/assets/grant")
    async def platform_grant_asset(request: Request):
        auth = await current_platform(request, mutate=True, permission="platform.asset.write")
        plane = require_plane()
        body = await _json(request)
        tenant_id = str(body.get("tenant_id", "") or "")
        user_id = str(body.get("user_id", "") or "")
        asset_id = str(body.get("asset_id", "") or "")
        with transaction(platform.factory) as db:
            tenant = db.get(Tenant, tenant_id)
            asset = db.get(Asset, asset_id)
            user = db.get(User, user_id)
            if tenant is None or asset is None or user is None \
                    or asset.tenant_id != tenant_id or user.tenant_id != tenant_id:
                raise services.PlatformError("grant_target_missing", "租户、用户或资产不存在", 404)
            services.grant_asset(
                db, user_id=user_id, asset_id=asset_id, actor=auth["username"],
                ttl_seconds=int(body.get("ttl_seconds", 86400 * 30)),
                tenant_id=tenant_id, actor_user_id=auth["user_id"], plane=plane)
        return {"ok": True, "level": 1, "user_id": user_id, "asset_id": asset_id}

    @app.post("/api/v2/platform/assets/{asset_id}/reset")
    async def platform_reset_asset(asset_id: str, request: Request):
        auth = await current_platform(request, mutate=True,
                                      permission="platform.asset.write")
        with transaction(platform.factory) as db:
            asset = db.get(Asset, asset_id)
            if asset is None or not asset.address:
                raise services.PlatformError("asset_not_found", "资产不存在或未配置地址", 404)
            address = asset.address
            tenant_of_record = asset.tenant_id
            cred_id = asset.credential_id
            if not cred_id:
                raise services.PlatformError("credential_not_found", "该资产未配置 BMC 凭据", 404)
            cred = services.read_credential(db, platform.cipher, cred_id, tenant_id=None)

        try:
            result = await bmc_reset.cold_reset_bmc(
                address, cred["username"], cred["password"])
        except bmc_reset.ResetError as exc:
            with transaction(platform.factory) as db:
                services.audit(db, auth["username"], "asset.bmc_reset_failed",
                               tenant_id=tenant_of_record, actor_type="platform",
                               detail={"asset_id": asset_id, "code": exc.code,
                                       "scope": "platform"},
                               trace=request.state.trace)
            raise services.PlatformError(exc.code, exc.message, 502) from None

        with transaction(platform.factory) as db:
            services.audit(db, auth["username"], "asset.bmc_reset",
                           tenant_id=tenant_of_record, actor_type="platform",
                           detail={"asset_id": asset_id, "code": "ok",
                                   "scope": "platform"},
                           trace=request.state.trace)
        return {"ok": True, "asset_id": asset_id, "address": address,
                "method": "ipmi-cold-reset", "accepted": result["accepted"]}

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
        result = await require_plane().force_revoke(sid, trace=request.state.trace,
                                                    actor=auth["username"])
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
