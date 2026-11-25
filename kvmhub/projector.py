"""G0 projector: leased outbox delivery to the mTLS projection listener."""
from __future__ import annotations

import logging
import random
import time
import uuid
from typing import Any, Callable

from sqlalchemy import select

from .common import INTERNAL_PORT
from .platform.connection_config import ack_projection, resolve_domain_id
from .platform.db import transaction
from .platform.models import (Asset, AssetConnection, ExecutionDomain, PlaneOutbox,
                              PlaneProjection)

logger = logging.getLogger(__name__)

LEASE_SECONDS = 30.0
MAX_ATTEMPTS = 8
OWNER = f"projector-{uuid.uuid4().hex}"


def _backoff(attempts: int) -> float:
    base = float(min(60, 2 ** max(1, min(attempts, 6))))
    return base * random.uniform(0.5, 1.0)


def _snapshot_fields(conn: AssetConnection, *, event_id: str) -> dict:
    return {
        "event_id": event_id,
        "asset_id": conn.asset_id,
        "revision": conn.revision,
        "snapshot": {
            "endpoint_json": conn.endpoint_json,
            "adapter": conn.adapter,
            "identity_policy": conn.identity_policy,
            "source_versions_json": conn.source_versions_json,
            "secret_ref": conn.secret_ref,
            "secret_source": conn.secret_source,
            "secret_revision": conn.secret_revision,
            "schema": conn.schema,
            "created": conn.created,
        },
    }


def _permanent_failure(exc: Exception) -> bool:
    text = str(exc)
    if text.startswith("projection_http_"):
        try:
            status = int(text.rsplit("_", 1)[1])
        except (ValueError, IndexError):
            return False
        return 400 <= status < 500 and status not in (408, 429)
    return text in {"projection_rejected", "projection_ack_stale"}


_PROJECTION_PATH = "/internal/v2/projections/"


def projection_url(endpoint: str, asset_id: str, revision: int) -> str:
    base = str(endpoint).rstrip("/")
    if _PROJECTION_PATH in base:
        return base
    return f"{base}{_PROJECTION_PATH}{asset_id}/{int(revision)}"


async def _http_put(url: str, body: dict, headers: dict, tls: Any) -> dict:
    import aiohttp

    timeout = aiohttp.ClientTimeout(total=5.0, connect=2.0)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        async with session.put(url, json=body, headers=headers, ssl=tls,
                               allow_redirects=False) as response:
            if response.status != 200:
                raise RuntimeError(f"projection_http_{response.status}")
            payload = await response.json(content_type=None)
            if not isinstance(payload, dict) or payload.get("ok") is not True:
                raise RuntimeError("projection_rejected")
            return payload


async def run_projector_once(factory, store_factory=None, *, now: float | None = None,
                             http_put: Callable | None = None, endpoint: str | None = None,
                             tls: Any = None, headers: dict | None = None,
                             cipher=None, secret_provider: Callable | None = None,
                             limit: int = 8) -> dict:
    stamp = time.time() if now is None else float(now)
    if store_factory is not None:
        info = store_factory() or {}
        endpoint = endpoint or info.get("endpoint")
        if tls is None:
            tls = info.get("tls")
        headers = {**(info.get("headers") or {}), **(headers or {})}
    endpoint = endpoint or f"https://127.0.0.1:{INTERNAL_PORT}"
    headers = dict(headers or {})
    headers.setdefault("X-Trace-ID", uuid.uuid4().hex)

    claimed: list[dict] = []
    with transaction(factory) as db:
        rows = db.scalars(
            select(PlaneOutbox)
            .where(PlaneOutbox.attempts < MAX_ATTEMPTS,
                   PlaneOutbox.lease_until <= stamp,
                   PlaneOutbox.next_attempt <= stamp)
            .order_by(PlaneOutbox.created, PlaneOutbox.event_id)
            .limit(limit)
            .with_for_update(skip_locked=True)).all()
        for event in rows:
            conn = db.scalar(select(AssetConnection).where(
                AssetConnection.asset_id == event.asset_id,
                AssetConnection.revision == event.revision))
            domain_id = resolve_domain_id(db, event.asset_id)
            projection = db.scalar(select(PlaneProjection).where(
                PlaneProjection.asset_id == event.asset_id,
                PlaneProjection.domain_id == domain_id))
            domain = db.get(ExecutionDomain, domain_id)
            asset = db.get(Asset, event.asset_id)
            if (conn is None or projection is None or domain is None or asset is None
                    or projection.desired_revision != event.revision):
                event.attempts += 1
                event.next_attempt = stamp + _backoff(event.attempts)
                continue
            if projection.applied_revision >= event.revision:
                event.attempts = MAX_ATTEMPTS
                event.lease_owner = ""
                event.lease_until = 0.0
                event.next_attempt = 0.0
                continue
            body = _snapshot_fields(conn, event_id=event.event_id)
            body.update({
                "digest": conn.digest,
                "domain_id": projection.domain_id,
                "generation": domain.generation,
                "policy_fingerprint": domain.policy_fingerprint,
            })
            claimed.append({"event": body, "domain": domain})
            event.lease_owner = OWNER
            event.lease_until = stamp + LEASE_SECONDS
            event.attempts += 1

    result = {"claimed": len(claimed), "delivered": 0, "acknowledged": 0, "failed": 0}
    for item in claimed:
        body = item["event"]
        domain = item["domain"]
        try:
            url = projection_url(endpoint, body["asset_id"], body["revision"])
            await (http_put or _http_put)(url, body, headers, tls)
            result["delivered"] += 1
            with transaction(factory) as db:
                ok = ack_projection(
                    db,
                    event_id=body["event_id"],
                    asset_id=body["asset_id"], revision=body["revision"],
                    digest=body["digest"], domain_id=body["domain_id"],
                    generation=domain.generation,
                    policy_fingerprint=domain.policy_fingerprint, now=stamp)
                if not ok:
                    raise RuntimeError("projection_ack_stale")
            result["acknowledged"] += 1
        except Exception as exc:
            result["failed"] += 1
            detail = str(exc) or type(exc).__name__
            logger.warning("projection_delivery_failed asset=%s revision=%s code=%s",
                           body["asset_id"], body["revision"], detail)
            with transaction(factory) as db:
                event = db.get(PlaneOutbox, body.get("event_id", ""))
                if event is not None:
                    event.lease_owner = ""
                    event.lease_until = 0.0
                    event.next_attempt = stamp + _backoff(event.attempts)
                projection = db.scalar(select(PlaneProjection).where(
                    PlaneProjection.asset_id == body["asset_id"],
                    PlaneProjection.domain_id == body["domain_id"]))
                if (projection is not None and projection.desired_revision == body["revision"]
                        and _permanent_failure(exc)):
                    projection.status = "blocked"
                    projection.error = detail

    return result
