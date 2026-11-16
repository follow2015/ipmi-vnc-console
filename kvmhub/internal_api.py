"""The Manager's internal API: the only listener a Worker may call."""
from __future__ import annotations

import json
import secrets
import uuid
from pathlib import Path

from aiohttp import web
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from .common import (INTERNAL_PORT, TRACE_ID, Problem, certificate_common_name,
                     expected_worker_cert_cn, peer_certificate, secret_matches,
                     user_message, verify)
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


def create_app(cfg, store: Store, *, expected_host: str | None = None) -> web.Application:
    private = load_pem_private_key(Path(cfg["signing_key"]).read_bytes(), password=None)
    public = private.public_key()

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
            return _json(trace, store.exchange(claims, trace))
        if operation in ("active", "renew"):
            return _json(trace, store.renew(sid, cfg["worker_id"], cfg["instance_id"],
                                            operation == "active", trace=trace))
        if operation == "finish":
            store.finish(sid, cfg["worker_id"], cfg["instance_id"], body.get("cleanup"),
                         body.get("reason"), trace=trace, evidence=body.get("evidence"))
            return _json(trace, {"ok": True})
        raise Problem("unknown_operation", 404)

    app = web.Application(middlewares=[guards])
    app.router.add_post("/internal/v1/sessions/{sid}/{operation}", worker_api)
    app[HOST_KEY] = expected_host or f"localhost:{INTERNAL_PORT}"
    return app
