"""Control-plane mTLS authority listener for G1 managed operations."""
from __future__ import annotations

import json
import logging
import secrets
import time
import uuid
from pathlib import Path

from aiohttp import web
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from sqlalchemy import select, text

from ..common import (INTERNAL_PORT, TRACE_ID, Problem, certificate_common_name,
                      peer_certificate, user_message)
from ..operation_permit import OPERATIONS, issue_operation_permit
from . import services
from .db import transaction
from .models import (AccessGrant, Asset, AssetConnection, Capability,
                     DeviceAdmission, ExecutionDomain, PlaneProjection, Tenant, User)
from ..common import OPERATION_AUDIENCE

logger = logging.getLogger(__name__)

HOST_KEY = web.AppKey("authority_expected_host", str)
TRACE_KEY = web.RequestKey("authority_trace", str)
CFG_KEY = web.AppKey("authority_cfg", dict)
MAX_BODY = 16384
BODY_KEYS = frozenset({
    "schema", "operation", "sid", "asset_id", "user_id", "tenant_id", "domain_id",
    "worker_id", "instance_id", "connection_revision", "admission_revision",
    "digest", "generation", "session_started_at", "hard_until",
})
BODY_TYPES = {
    "schema": str, "operation": str, "sid": str, "asset_id": str, "user_id": str,
    "tenant_id": str, "domain_id": str, "worker_id": str, "instance_id": str,
    "connection_revision": int, "admission_revision": int, "digest": str,
    "generation": str, "session_started_at": float, "hard_until": float,
}
PLATFORM_CLIENT_OPERATIONS = frozenset({"allocate", "exchange"})


def authority_db_timeout_statement(dialect: str) -> str | None:
    if dialect == "sqlite":
        return "PRAGMA busy_timeout = 300"
    if dialect.startswith("mysql"):
        return "SET SESSION max_execution_time = 300"
    if dialect.startswith("postgres"):
        return "SET LOCAL statement_timeout = '300ms'"
    return None


def principal_operations(cfg) -> dict[str, frozenset[str]]:
    authority = cfg.get("authority_cert_cn") or "kvmhub-authority-client"
    platform = cfg.get("platform_cert_cn") or "kvmhub-platform-client"
    return {authority: frozenset(OPERATIONS), platform: PLATFORM_CLIENT_OPERATIONS}


def _body_type_ok(value, kind) -> bool:
    if kind is int:
        return isinstance(value, int) and not isinstance(value, bool)
    if kind is float:
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    return isinstance(value, kind)

SECURITY_HEADERS = {
    "Cache-Control": "no-store",
    "Referrer-Policy": "strict-origin",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
}


def _json(trace: str, body: dict, status: int = 200) -> web.Response:
    return web.json_response({**body, "trace_id": trace}, status=status,
                             headers=SECURITY_HEADERS)


def expected_authority_clients(cfg) -> frozenset[str]:
    authority = cfg.get("authority_cert_cn") or "kvmhub-authority-client"
    platform = cfg.get("platform_cert_cn") or "kvmhub-platform-client"
    return frozenset({authority, platform})


def check_authority_credentials(headers, transport, cfg) -> str:
    presented = certificate_common_name(peer_certificate(transport))
    if presented is None:
        raise Problem("admission_certificate_missing", 403)
    if not any(secrets.compare_digest(presented, name)
               for name in expected_authority_clients(cfg)):
        raise Problem("admission_certificate_mismatch", 403)
    return presented


def authorize(db, *, principal: str, operation: str, sid: str, asset_id: str,
              user_id: str, tenant_id: str, domain_id: str, worker_id: str,
              instance_id: str, connection_revision: int, admission_revision: int,
              digest: str, generation: str, session_started_at: float,
              hard_until: float, signing_key: str, now: float | None = None) -> dict:
    stamp = time.time() if now is None else float(now)
    if operation not in OPERATIONS:
        raise Problem("operation_permit_invalid", 400)
    try:
        services.observe_clock(db, now=stamp, actor=principal,
                               reason=f"authorize:{operation}")
    except services.PlatformError as exc:
        if exc.code != "clock_regression":
            raise
        raise Problem("clock_regression", 409) from None
    asset = db.get(Asset, asset_id)
    if asset is None or asset.tenant_id != tenant_id:
        raise Problem("device_not_admitted", 403)

    admission = db.scalar(select(DeviceAdmission).where(
        DeviceAdmission.asset_id == asset_id).order_by(
            DeviceAdmission.revision.desc()).limit(1))
    if admission is None or admission.state != "approved":
        raise Problem("device_not_admitted", 403)
    if admission.expires <= stamp:
        raise Problem("device_admission_expired", 403)
    if admission.review_due <= stamp:
        raise Problem("device_admission_review_overdue", 403)
    if admission.tenant_id not in (None, tenant_id) or admission.domain_id != domain_id:
        raise Problem("device_not_admitted", 403)

    connection = db.scalar(select(AssetConnection).where(
        AssetConnection.asset_id == asset_id,
        AssetConnection.revision == connection_revision).limit(1))
    if (connection is None or connection.digest != digest
            or admission.revision != admission_revision):
        raise Problem("connection_revision_mismatch", 409)

    from . import overlays
    from .models import parse_json
    try:
        overlay = overlays.check_asset(
            db, asset, now=stamp, operation=operation, require_frozen=True,
            frozen=parse_json(connection.source_versions_json, {}).get('overlay'))
    except overlays.services.PlatformError:
        raise Problem('device_not_admitted', 403) from None

    projection = db.scalar(select(PlaneProjection).where(
        PlaneProjection.asset_id == asset_id, PlaneProjection.domain_id == domain_id))
    draining = overlay and overlay['draining']
    if (projection is None or projection.applied_revision < connection_revision
            or (projection.applied_digest != digest and not draining)):
        raise Problem("connection_config_pending", 409)
    domain = db.get(ExecutionDomain, domain_id)
    if domain is None or domain.health != "healthy" or domain.generation != generation:
        raise Problem("execution_domain_unavailable", 503)
    if domain.policy_fingerprint != projection.policy_fingerprint:
        raise Problem("execution_domain_unavailable", 503)

    user = db.get(User, user_id)
    if user is None or not user.is_active or user.tenant_id != tenant_id:
        raise Problem("device_not_admitted", 403)
    grant = db.get(AccessGrant, (user_id, asset_id))
    if grant is None or grant.expires <= stamp:
        raise Problem("device_not_admitted", 403)
    tenant = db.get(Tenant, tenant_id)
    if tenant is None or (operation in ("allocate", "exchange")
                          and tenant.status != "active"):
        raise Problem("device_not_admitted", 403)
    capability = db.get(Capability, asset.capability_id) if asset.capability_id else None
    if capability is None or capability.status != "verified" or capability.expires <= stamp:
        raise Problem("device_not_admitted", 403)
    if hard_until <= stamp or session_started_at > stamp + 2:
        raise Problem("operation_permit_invalid", 400)

    private_key = load_pem_private_key(Path(signing_key).read_bytes(), password=None)
    if operation == "allocate":
        deadline = hard_until
    else:
        deadline = stamp + 30.0
    lease_not_after = min(deadline, hard_until, admission.expires,
                          admission.review_due, grant.expires, capability.expires)
    if overlay:
        lease_not_after = min(lease_not_after, overlay['expires'])
    token = issue_operation_permit(
        private_key, operation=operation, sid=sid, asset_id=asset_id,
        tenant_id=tenant_id, user_id=user_id, domain_id=domain_id,
        worker_id=worker_id, instance_id=instance_id,
        connection_revision=connection_revision,
        admission_revision=admission.revision, digest=digest, generation=generation,
        lease_not_after=lease_not_after, now=stamp)
    return {
        "ok": True,
        "permit": token,
        "audience": OPERATION_AUDIENCE,
        "lease_not_after": lease_not_after,
        "connection_revision": connection.revision,
        "admission_revision": admission.revision,
        "digest": digest,
        "generation": generation,
    }


def create_admission_app(cfg, factory, *, expected_host: str | None = None) -> web.Application:

    @web.middleware
    async def guards(request: web.Request, handler):
        incoming = request.headers.get("X-Trace-ID", "")
        trace = incoming if TRACE_ID.fullmatch(incoming) else uuid.uuid4().hex
        request[TRACE_KEY] = trace
        if request.headers.get("host") != request.app[HOST_KEY]:
            return _json(trace, {"error": "invalid_host",
                                 "message": user_message("invalid_host")}, 421)
        try:
            response = await handler(request)
        except Problem as exc:
            return _json(trace, {"error": exc.code,
                                 "message": user_message(exc.code)}, exc.status)
        except web.HTTPException as exc:
            return _json(trace, {"error": "invalid_request",
                                 "message": None}, exc.status)
        response.headers.update(SECURITY_HEADERS)
        response.headers["X-Trace-ID"] = trace
        return response

    async def authorize_api(request: web.Request) -> web.Response:
        principal = check_authority_credentials(request.headers, request.transport,
                                                request.app[CFG_KEY])
        declared = request.headers.get("Content-Length")
        if declared is not None and (not declared.isdigit() or int(declared) > MAX_BODY):
            raise Problem("request_too_large", 413)
        raw = await request.content.read(MAX_BODY + 1)
        if len(raw) > MAX_BODY:
            raise Problem("request_too_large", 413)
        try:
            body = json.loads(raw or b"{}")
        except (ValueError, TypeError):
            raise Problem("invalid_request", 400) from None
        if not isinstance(body, dict):
            raise Problem("invalid_request", 400)
        if set(body) - BODY_KEYS or body.get("schema") != "g1-v2":
            raise Problem("projection_schema_unsupported", 409)
        required = BODY_KEYS - {"schema"}
        if any(key not in body for key in required):
            raise Problem("invalid_request", 400)
        if any(not _body_type_ok(body[key], kind) for key, kind in BODY_TYPES.items()):
            raise Problem("invalid_request", 400)
        allowed = principal_operations(cfg).get(principal, frozenset())
        if body["operation"] not in allowed:
            raise Problem("permission_denied", 403)
        with transaction(factory) as db:
            deadline = authority_db_timeout_statement(db.get_bind().dialect.name)
            if deadline:
                db.execute(text(deadline))
            result = authorize(
                db, principal=principal, signing_key=cfg["signing_key"],
                **{key: body[key] for key in BODY_KEYS if key not in ("schema",)})
        return _json(request[TRACE_KEY], result)

    app = web.Application(middlewares=[guards])
    app.router.add_post("/authority/v2/authorize", authorize_api)
    app[HOST_KEY] = expected_host or f"localhost:{INTERNAL_PORT}"
    app[CFG_KEY] = cfg
    return app
