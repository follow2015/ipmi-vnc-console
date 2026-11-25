"""The Manager's internal API: the only listener a Worker may call."""
from __future__ import annotations

import asyncio
import json
import secrets
import uuid
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from pathlib import Path

from aiohttp import web
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from .admission_runtime import (authority_from_env, authority_request)
from .common import (INTERNAL_PORT, TRACE_ID, Problem, certificate_common_name,
                     expected_projector_cert_cn, expected_worker_cert_cn,
                     peer_certificate, secret_matches, user_message, verify)
from .store import Store

SECURITY_HEADERS = {
    "Cache-Control": "no-store",
    "Referrer-Policy": "strict-origin",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
}

MAX_BODY = 16384

HOST_KEY = web.AppKey("expected_host", str)
EXECUTOR_KEY = web.AppKey("store_executor", ThreadPoolExecutor)
TRACE_KEY = web.RequestKey("trace", str)


def _json(trace: str, body: dict, status: int = 200) -> web.Response:
    return web.json_response({**body, "trace_id": trace}, status=status, headers=SECURITY_HEADERS)


def worker_identity(transport) -> str | None:
    return certificate_common_name(peer_certificate(transport))


def check_worker_credentials(headers, transport, cfg) -> None:
    if not secret_matches(headers.get("x-worker-proof", ""), cfg["worker_proof_hash"]):
        raise Problem("worker_authentication_failed", 403)
    presented = worker_identity(transport)
    if presented is None:
        raise Problem("worker_certificate_missing", 403)
    if not secrets.compare_digest(presented, expected_worker_cert_cn(cfg)):
        raise Problem("worker_certificate_mismatch", 403)


def check_projector_credentials(headers, transport, cfg) -> None:
    presented = worker_identity(transport)
    if presented is None:
        raise Problem("projector_certificate_missing", 403)
    if not secrets.compare_digest(presented, expected_projector_cert_cn(cfg)):
        raise Problem("projector_certificate_mismatch", 403)


async def _payload(request: web.Request) -> dict:
    declared = request.headers.get("Content-Length")
    if declared is not None and (not declared.isdigit() or int(declared) > MAX_BODY):
        raise Problem("request_too_large", 413)
    raw = await request.content.read(MAX_BODY + 1)
    if len(raw) > MAX_BODY:
        raise Problem("request_too_large", 413)
    try:
        value = json.loads(raw or b"{}")
    except (ValueError, TypeError):
        raise Problem("invalid_request", 400) from None
    if not isinstance(value, dict):
        raise Problem("invalid_request", 400)
    return value


def create_app(cfg, store: Store, *, expected_host: str | None = None,
               authority=None, managed_domains: tuple[str, ...] | None = None,
               authority_host: str = "", permit_public_key=None) -> web.Application:
    private = load_pem_private_key(Path(cfg["signing_key"]).read_bytes(), password=None)
    public = private.public_key()
    permit_public_key = permit_public_key or public
    if authority is None:
        authority, from_env, host = authority_from_env(permit_public_key)
        managed_domains = tuple(from_env) if managed_domains is None else managed_domains
        authority_host = authority_host or host
    managed_domains = frozenset(managed_domains or ())
    executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="kvmhub-store")

    async def run_store(fn, *args, **kwargs):
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(executor, partial(fn, *args, **kwargs))

    async def shutdown(_app):
        executor.shutdown(wait=True)

    async def managed_permit(sid: str, operation: str, trace: str):
        if authority is None and not managed_domains:
            return None, "", None
        row = await run_store(store.get, sid)
        if row.get("domain_id") not in managed_domains or not row.get("binding_digest"):
            return None, "", None
        if authority is None:
            raise Problem("admission_service_unavailable", 503)
        request = authority_request(
            operation=operation, sid=sid, asset_id=row["asset_id"],
            user_id=row["user_id"], tenant_id=row.get("tenant_id") or "",
            domain_id=row["domain_id"], worker_id=cfg["worker_id"],
            instance_id=cfg["instance_id"],
            connection_revision=int(row["connection_revision"] or 0),
            admission_revision=int(row["admission_revision"] or 0),
            digest=row.get("snapshot_digest") or "", generation=row.get("generation") or "",
            session_started_at=float(row["created"]), hard_until=float(row["hard_until"]))
        answer = await authority.authorize(host=authority_host, **request)
        return answer["permit"], row["binding_digest"], answer["claims"]

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
            return _json(trace, {"error": "unknown_operation" if exc.status == 404 else "invalid_request",
                                 "message": None}, exc.status)
        response.headers.update(SECURITY_HEADERS)
        response.headers["X-Trace-ID"] = trace
        return response

    async def worker_api(request: web.Request) -> web.Response:
        check_worker_credentials(request.headers, request.transport, cfg)
        sid = request.match_info["sid"]
        operation = request.match_info["operation"]
        trace = request[TRACE_KEY]
        body = await _payload(request)
        if operation == "exchange":
            claims = verify(public, body.get("ticket", ""), cfg["worker_id"], cfg["instance_id"])
            if claims["sid"] != sid:
                raise Problem("invalid_ticket", 403)
            permit, binding, authority_claims = await managed_permit(sid, "exchange", trace)
            if permit is not None:
                assembly_binding = str(body.get("binding") or "")
                if not assembly_binding or assembly_binding != binding:
                    raise Problem("connection_revision_mismatch", 409)
                if authority_claims.get("aid") != claims["aid"]:
                    raise Problem("connection_revision_mismatch", 409)
            return _json(trace, await run_store(
                store.exchange, claims, trace, permit=permit,
                public_key=permit_public_key, binding=binding,
                assembly_binding=assembly_binding if permit is not None else ""))
        if operation in ("active", "renew"):
            op = "activate" if operation == "active" else "renew"
            permit, binding, _ = await managed_permit(sid, op, trace)
            return _json(trace, await run_store(
                store.renew, sid, cfg["worker_id"], cfg["instance_id"],
                operation == "active", trace=trace, permit=permit,
                public_key=permit_public_key, binding=binding))
        if operation in ("reconnect", "recover"):
            permit, binding, _ = await managed_permit(sid, operation, trace)
            if permit is None:
                return _json(trace, {"ok": True, "legacy": True})
            return _json(trace, await run_store(
                store.start_operation, sid, cfg["worker_id"], cfg["instance_id"],
                operation, permit=permit, public_key=permit_public_key, binding=binding))
        if operation == "finish":
            await run_store(store.finish, sid, cfg["worker_id"], cfg["instance_id"],
                            body.get("cleanup"), body.get("reason"), trace=trace,
                            evidence=body.get("evidence"))
            return _json(trace, {"ok": True})
        raise Problem("unknown_operation", 404)

    async def projection_api(request: web.Request) -> web.Response:
        check_projector_credentials(request.headers, request.transport, cfg)
        raw_revision = request.match_info["revision"]
        if not raw_revision.isdigit() or int(raw_revision) < 1:
            raise Problem("projection_invalid", 400)
        revision = int(raw_revision)
        asset_id = request.match_info["asset_id"]
        body = await _payload(request)
        snapshot = body.get("snapshot")
        digest = str(body.get("digest") or "")
        domain_id = str(body.get("domain_id") or "")
        generation = str(body.get("generation") or "")
        policy_fingerprint = str(body.get("policy_fingerprint") or "")
        if (not isinstance(snapshot, dict) or not asset_id
                or not all((digest, domain_id, generation, policy_fingerprint))):
            raise Problem("projection_invalid", 400)
        trace = request[TRACE_KEY]
        projection = await run_store(
            store.put_connection_snapshot, asset_id, revision, snapshot,
            digest=digest, domain_id=domain_id, generation=generation,
            policy_fingerprint=policy_fingerprint)
        acknowledged = await run_store(store.ack_projection, asset_id, revision,
                                       digest=digest)
        if not acknowledged:
            state = await run_store(store.projection_state, asset_id)
            if not (state and state["current_revision"] == revision
                    and state["current_digest"] == digest
                    and state["status"] == "ready"):
                raise Problem("connection_snapshot_conflict", 409)
        return _json(trace, {
            "ok": True,
            "asset_id": asset_id,
            "revision": revision,
            "digest": digest,
            "generation": generation,
            "policy_fingerprint": policy_fingerprint,
            "projection": projection,
        })

    app = web.Application(middlewares=[guards])
    app.router.add_post("/internal/v1/sessions/{sid}/{operation}", worker_api)
    app.router.add_put("/internal/v2/projections/{asset_id}/{revision}", projection_api)
    app[HOST_KEY] = expected_host or f"localhost:{INTERNAL_PORT}"
    app[EXECUTOR_KEY] = executor
    app.on_cleanup.append(shutdown)
    return app
