"""Production control-plane HTTP API (FastAPI)."""
from __future__ import annotations

import time
import uuid
from contextlib import asynccontextmanager
from urllib.parse import urlsplit

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from sqlalchemy import select

from .config import Settings, settings as load_settings
from .db import init_schema, make_engine, seed_roles, session_factory, transaction
from .models import Asset, Role, User, UserRole, VendorProfile
from .redis_state import SESSION_PREFIX, State, create_state
from .security import (CredentialCipher, constant_time_equal, new_session_token,
                       token_digest)
from . import connection, services, text_input, vendor_registry
from .bus import AssemblyBus
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
    def cookie_name(self) -> str:
        return "__Host-kvmhub_sid" if self.cfg.is_prod else "kvmhub_sid"

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

    async def current(request: Request, *, mutate: bool = False, permission: str | None = None) -> dict:
        token = request.cookies.get(platform.cookie_name, "")
        auth = await platform.state.get_session(token_digest(token)) if token else None
        if not auth or float(auth.get("expires", 0)) <= time.time():
            raise services.PlatformError("authentication_required", "请先登录", 401)
        with transaction(platform.factory) as db:
            active = db.scalar(select(User.is_active).where(User.id == auth["user_id"]))
        if active is not True:
            raise services.PlatformError("authentication_required", "账号已停用，请重新登录", 401)
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
            user = services.authenticate(db, str(body.get("username", "")), str(body.get("password", "")))
            roles = [r[0] for r in db.execute(
                select(Role.code).join(UserRole, UserRole.role_id == Role.id)
                .where(UserRole.user_id == user.id)).all()]
        token, csrf = new_session_token(), new_session_token()
        await platform.state.put_session(
            token_digest(token),
            {"user_id": user.id, "username": user.username, "roles": roles, "csrf": csrf,
             "expires": time.time() + platform.cfg.session_ttl}, platform.cfg.session_ttl)
        response = JSONResponse({"user": user.public(), "roles": roles, "csrf": csrf})
        response.set_cookie(platform.cookie_name, token, max_age=platform.cfg.session_ttl,
                            secure=platform.cfg.is_prod, httponly=True, samesite="strict", path="/")
        return response

    @app.post("/api/v2/logout")
    async def logout(request: Request):
        auth = await current(request, mutate=True)
        token = request.cookies.get(platform.cookie_name, "")
        await platform.state.drop_session(token_digest(token))
        with transaction(platform.factory) as db:
            services.audit(db, auth["username"], "logout")
        response = JSONResponse({"ok": True})
        response.delete_cookie(platform.cookie_name, path="/")
        return response

    @app.get("/api/v2/me")
    async def me(request: Request):
        auth = await current(request)
        with transaction(platform.factory) as db:
            perms = sorted(services.permissions_of(db, auth["user_id"]))
        return {"user_id": auth["user_id"], "username": auth["username"],
                "roles": auth["roles"], "permissions": perms, "csrf": auth["csrf"]}

    @app.get("/api/v2/users")
    async def users(request: Request):
        await current(request, permission="user.read")
        with transaction(platform.factory) as db:
            return services.list_users(db)

    @app.post("/api/v2/users")
    async def create_user(request: Request):
        auth = await current(request, mutate=True, permission="user.write")
        body = await _json(request)
        with transaction(platform.factory) as db:
            user = services.create_user(db, str(body.get("username", "")),
                                        str(body.get("password", "")), str(body.get("role", "viewer")),
                                        actor=auth["username"], display_name=str(body.get("display_name", "")))
            return user.public()

    @app.post("/api/v2/users/{user_id}/active")
    async def set_active(user_id: str, request: Request):
        auth = await current(request, mutate=True, permission="user.write")
        body = await _json(request)
        with transaction(platform.factory) as db:
            services.set_user_active(db, user_id, bool(body.get("active", False)), actor=auth["username"])
        if not bool(body.get("active", False)):
            for key in await platform.state.keys(SESSION_PREFIX):
                session = await platform.state.get(key)
                if session and session.get("user_id") == user_id:
                    await platform.state.delete(key)
        return {"ok": True}

    @app.get("/api/v2/assets")
    async def assets(request: Request, scope: str = "granted"):
        if scope not in ("granted", "all"):
            raise services.PlatformError("scope_invalid", "scope 只能是 granted 或 all", 400)
        if scope == "all":
            auth = await current(request, permission="asset.write")
            with transaction(platform.factory) as db:
                rows = services.all_assets(db, auth["user_id"])
        else:
            auth = await current(request, permission="asset.read")
            with transaction(platform.factory) as db:
                rows = services.assets_for_user(db, auth["user_id"])
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
            existing = db.scalar(select(Asset).where(Asset.address == str(body.get("address", ""))))
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
                notes=str(optional["notes"] or ""), actor=auth["username"])
            return asset.public()

    @app.post("/api/v2/credentials")
    async def create_credential(request: Request):
        auth = await current(request, mutate=True, permission="credential.write")
        body = await _json(request)
        with transaction(platform.factory) as db:
            cred = services.save_credential(
                db, platform.cipher, label=str(body.get("label", "")),
                username=str(body.get("username", "")), password=str(body.get("password", "")),
                actor=auth["username"])
            return cred.public()

    @app.post("/api/v2/grants")
    async def grant(request: Request):
        auth = await current(request, mutate=True, permission="grant.write")
        body = await _json(request)
        with transaction(platform.factory) as db:
            services.grant_asset(db, user_id=str(body.get("user_id", "")),
                                 asset_id=str(body.get("asset_id", "")), actor=auth["username"],
                                 ttl_seconds=int(body.get("ttl_seconds", 86400 * 30)))
        return {"ok": True}

    @app.get("/api/v2/vendor-profiles")
    async def profiles(request: Request):
        await current(request, permission="vendor.read")
        with transaction(platform.factory) as db:
            return [row.public() for row in db.scalars(select(VendorProfile).order_by(VendorProfile.priority)).all()]

    @app.post("/api/v2/detect")
    async def detect(request: Request):
        auth = await current(request, mutate=True, permission="asset.write")
        body = await _json(request)
        detection = vendor_registry.detect_from_redfish(body.get("inventory") or {})
        with transaction(platform.factory) as db:
            match = vendor_registry.identify(db, detection)
            draft_id = None
            connection = None
            if match.profile is not None and match.usable:
                draft = services.capability_draft(db, match.profile, detection=detection,
                                                  actor=auth["username"])
                draft_id = draft.id
                connection = vendor_registry.connection_plan(match.profile)
            services.audit(db, auth["username"], "vendor_detected",
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
                    user_id=auth["user_id"], actor=auth["username"])
        except connection.ConnectionRefused as exc:
            raise services.PlatformError(exc.code, exc.message, 409) from exc

    def require_plane():
        if platform.plane is None:
            raise services.PlatformError(
                "data_plane_not_configured",
                "控制台数据面未配置（需要 KVMHUB_DATA_PLANE_STORE / KVMHUB_SIGNING_KEY / KVMHUB_DATA_PLANE_KEY）", 503)
        return platform.plane

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
                    db, asset_id=asset_id, user_id=auth["user_id"], actor=auth["username"])
        except connection.ConnectionRefused as exc:
            raise services.PlatformError(exc.code, exc.message, 409) from exc
        result = await plane.open(assembly, user_id=auth["user_id"], trace=request.state.trace)
        with transaction(platform.factory) as db:
            services.audit(db, auth["username"], "console_ticket_issued", asset_id=asset_id,
                           detail={"sid": result["sid"], "worker_id": result["worker_id"],
                                   "assembly_id": result["assembly_id"]},
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
                                                     trace=request.state.trace)
        with transaction(platform.factory) as db:
            services.audit(db, auth["username"], "console_ticket_revoked",
                           detail={"sid": sid}, trace=request.state.trace)
        return result

    @app.post("/api/v2/consoles/{sid}/cleanup")
    async def console_cleanup(sid: str, request: Request):
        auth = await current(request, mutate=True, permission="console.close")
        manage = False
        with transaction(platform.factory) as db:
            try:
                services.require(db, auth["user_id"], "asset.write")
                manage = True
            except services.PlatformError:
                manage = False
        result = require_plane().confirm_cleanup(
            sid, user_id=auth["user_id"], manage=manage, trace=request.state.trace)
        with transaction(platform.factory) as db:
            services.audit(db, auth["username"], "console_slot_released",
                           detail={"sid": sid, "scope": "manage" if manage else "owner"},
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
        await current(request, permission="audit.read")
        with transaction(platform.factory) as db:
            return services.recent_audit(db)

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
