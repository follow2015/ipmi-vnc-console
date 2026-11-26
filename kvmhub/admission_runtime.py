"""G1 runtime bridge: binding digests and the authority client."""
from __future__ import annotations

import asyncio
import json
import os
from typing import Any, Awaitable, Callable
from urllib.parse import urlparse

import aiohttp

from .common import OPERATION_AUDIENCE, Problem, client_tls, digest
from .operation_permit import OPERATIONS, verify_operation_permit

TRUSTED_AUTHORITY_CODES = frozenset({
    "device_not_admitted", "device_admission_expired", "device_admission_review_overdue",
    "connection_config_pending", "connection_revision_mismatch",
    "execution_domain_unavailable", "target_network_denied",
    "projection_schema_unsupported", "admission_service_unavailable",
    "operation_permit_invalid", "operation_permit_replayed",
    "clock_skew",
})

BINDING_FIELDS = (
    "sid", "asset_id", "tenant_id", "user_id", "domain_id", "worker_id",
    "instance_id", "connection_revision", "admission_revision", "digest", "generation",
)


def binding_payload(**values: Any) -> dict:
    payload = {name: values[name] for name in BINDING_FIELDS if name in values}
    if set(payload) != set(BINDING_FIELDS):
        raise ValueError("incomplete operation binding")
    return payload


def binding_digest(payload: dict) -> str:
    return digest(json.dumps(binding_payload(**payload), sort_keys=True,
                             separators=(",", ":")))


class AuthorityClient:

    def __init__(self, url: str, *, ca: str, cert: str, key: str,
                 public_key, timeout: float = 1.0,
                 post: Callable[..., Awaitable[dict]] | None = None,
                 principal: str = "kvmhub-authority-client"):
        if not url.startswith("https://"):
            raise ValueError("authority URL must use https")
        self.url = url.rstrip("/") + "/authority/v2/authorize"
        self.public_key = public_key
        self.timeout = aiohttp.ClientTimeout(total=timeout, connect=timeout,
                                             sock_connect=timeout, sock_read=timeout)
        self.principal = principal
        self._post = post
        self._session: aiohttp.ClientSession | None = None
        self._session_lock: asyncio.Lock | None = None
        if post is None:
            ctx = client_tls(ca, cert, key)

            async def post_impl(payload: dict, expected_host: str) -> dict:
                if self._session is None:
                    if self._session_lock is None:
                        self._session_lock = asyncio.Lock()
                    async with self._session_lock:
                        if self._session is None:
                            connector = aiohttp.TCPConnector(ssl=ctx)
                            self._session = aiohttp.ClientSession(
                                connector=connector, timeout=self.timeout)
                async with self._session.post(
                        self.url, json=payload,
                        headers={"Host": expected_host, "X-Trace-ID": payload.get("trace_id", "")},
                        timeout=self.timeout) as response:
                    if response.status != 200:
                        body = await response.json(content_type=None)
                        code = str(body.get("error") or "")
                        if code in TRUSTED_AUTHORITY_CODES:
                            detail = body.get("detail")
                            raise Problem(code, response.status,
                                          detail=detail if isinstance(detail, dict) else None)
                        raise Problem("admission_service_unavailable", 503)
                    result = await response.json(content_type=None)
                    if not isinstance(result, dict) or not isinstance(result.get("permit"), str):
                        raise Problem("admission_service_unavailable", 503)
                    return result

            self._post = post_impl

    async def close(self) -> None:
        if self._session is not None:
            await self._session.close()
            self._session = None
        self._session_lock = None

    async def authorize(self, *, host: str, **fields: Any) -> dict:
        operation = str(fields.get("operation") or "")
        if operation not in OPERATIONS:
            raise Problem("operation_permit_invalid", 400)
        payload = dict(fields)
        if set(payload) != {
                "schema", "operation", "sid", "asset_id", "user_id", "tenant_id",
                "domain_id", "worker_id", "instance_id", "connection_revision",
                "admission_revision", "digest", "generation", "session_started_at",
                "hard_until"}:
            raise Problem("admission_service_unavailable", 503)
        try:
            result = await self._post(payload, host)
            claims = verify_operation_permit(
                self.public_key, result["permit"],
                expected={"op": operation, "aud": OPERATION_AUDIENCE,
                          "schema": "g1-v2",
                          "sid": payload["sid"], "aid": payload["asset_id"],
                          "usr": payload["user_id"], "tid": payload["tenant_id"],
                          "dom": payload["domain_id"], "wid": payload["worker_id"],
                          "iid": payload["instance_id"], "dgs": payload["digest"],
                          "gen": payload["generation"],
                          "cr": int(payload["connection_revision"]),
                          "ar": int(payload["admission_revision"])})
        except Problem:
            raise
        except Exception:
            raise Problem("admission_service_unavailable", 503) from None
        return {"permit": result["permit"], "claims": claims}


def authority_from_env(public_key, *, principal: str = "kvmhub-authority-client"):
    url = os.getenv("KVMHUB_AUTHORITY_URL", "").strip()
    domains = tuple(item.strip() for item in
                    os.getenv("KVMHUB_MANAGED_DOMAINS", "").split(",") if item.strip())
    if not url:
        if domains:
            raise ValueError("KVMHUB_MANAGED_DOMAINS requires KVMHUB_AUTHORITY_URL")
        return None, (), ""
    ca = os.getenv("KVMHUB_AUTHORITY_CA", "").strip()
    cert = os.getenv("KVMHUB_AUTHORITY_CERT", "").strip()
    key = os.getenv("KVMHUB_AUTHORITY_KEY", "").strip()
    if not all((ca, cert, key)):
        raise ValueError("KVMHUB_AUTHORITY_URL needs CA/cert/key environment paths")
    return (AuthorityClient(url, ca=ca, cert=cert, key=key, public_key=public_key,
                            principal=principal),
            domains, urlparse(url).netloc)


def authority_request(*, operation: str, sid: str, asset_id: str, user_id: str,
                      tenant_id: str, domain_id: str, worker_id: str, instance_id: str,
                      connection_revision: int, admission_revision: int, digest: str,
                      generation: str, session_started_at: float,
                      hard_until: float) -> dict:
    return {
        "schema": "g1-v2", "operation": operation, "sid": sid,
        "asset_id": asset_id, "user_id": user_id, "tenant_id": tenant_id,
        "domain_id": domain_id, "worker_id": worker_id, "instance_id": instance_id,
        "connection_revision": int(connection_revision),
        "admission_revision": int(admission_revision), "digest": digest,
        "generation": generation, "session_started_at": float(session_started_at),
        "hard_until": float(hard_until),
    }
