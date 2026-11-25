"""Transactional G0 change service: approval, immutable snapshot and outbox."""
from __future__ import annotations

import hashlib
import json
import time
import uuid
from collections.abc import Sequence

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .models import (Asset, AssetConnection, Capability, Credential, DeviceAdmission,
                     ExecutionDomain, PlaneOutbox, PlaneProjection, VendorProfile,
                     json_field)
from .services import PlatformError, audit

DEFAULT_DOMAIN_ID = "admission-canary"
ADMISSION_PENDING = "pending"
ADMISSION_APPROVED = "approved"
ADMISSION_REVOKED = "revoked"


def resolve_domain_id(db: Session, asset_id: str, *, preferred: str | None = None) -> str:
    if preferred:
        return preferred
    admission_domain = db.scalar(select(DeviceAdmission.domain_id).where(
        DeviceAdmission.asset_id == asset_id,
        DeviceAdmission.domain_id != "").order_by(
            DeviceAdmission.revision.desc()).limit(1))
    if admission_domain:
        return str(admission_domain)
    projection_domain = db.scalar(select(PlaneProjection.domain_id).where(
        PlaneProjection.asset_id == asset_id,
        PlaneProjection.domain_id != "").limit(1))
    if projection_domain:
        return str(projection_domain)
    domains = db.scalars(select(ExecutionDomain.domain_id).where(
        ExecutionDomain.health != "retired").order_by(ExecutionDomain.domain_id)).all()
    if not domains:
        return DEFAULT_DOMAIN_ID
    if len(domains) == 1:
        return str(domains[0])
    raise PlatformError("execution_domain_unavailable",
                        "多个执行域并存且资产未指定域，拒绝猜测", 503)


def _next_revision(db: Session, model, asset_id: str) -> int:
    current = db.scalar(select(func.max(model.revision)).where(model.asset_id == asset_id))
    return int(current or 0) + 1


def _identity_digest(asset: Asset) -> str:
    material = json.dumps({"tenant": asset.tenant_id, "address": asset.address,
                           "fingerprint": (asset.fingerprint or "").lower(),
                           "credential": asset.credential_id},
                          sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(material).hexdigest()


def _snapshot(db: Session, asset: Asset, stamp: float) -> dict:
    capability = db.get(Capability, asset.capability_id) if asset.capability_id else None
    profile = db.get(VendorProfile, asset.profile_id) if asset.profile_id else None
    credential = db.get(Credential, asset.credential_id) if asset.credential_id else None
    hidden_vnc = bool(asset.vnc_password_cipher)
    recipe_id = str(getattr(profile, "recipe_id", "") or "")
    recipe_revision = int(getattr(profile, "recipe_revision", 0) or 0)
    config_schema = str(getattr(profile, "config_schema_version", "") or "")
    bundle_revision = str(getattr(capability, "bundle_revision", "") or "")
    versions = {
        "profile": int(getattr(profile, "revision", 0) or 0),
        "capability": int(getattr(capability, "revision", 0) or 0),
        "credential": int(getattr(credential, "revision", 0) or 0),
        "vnc_secret": int(asset.vnc_secret_revision or 0) if hidden_vnc else 0,
        "recipe_revision": recipe_revision,
        "recipe_id": recipe_id,
        "config_schema": config_schema,
    }
    if recipe_id and bundle_revision:
        from ..video.client_v2 import protocol_contract
        versions["protocol_contract"] = protocol_contract()
    else:
        versions["bundle_revision"] = bundle_revision
    from .overlays import snapshot_material
    overlay = snapshot_material(db, asset.id)
    if overlay is not None:
        versions['overlay'] = overlay
    payload = {
        "asset_id": asset.id,
        "endpoint_json": json_field([{"transport": "bmc", "host": asset.address}]),
        "adapter": getattr(capability, "adapter", "") or "",
        "identity_policy": json_field({
            "fingerprint": asset.fingerprint or "",
            "pin_mode": "asset_fingerprint" if asset.fingerprint else "none",
        }),
        "source_versions_json": json_field(versions),
        "secret_ref": asset.credential_id or "",
        "secret_source": "vnc_hidden" if hidden_vnc else "bmc",
        "secret_revision": versions["vnc_secret"] if hidden_vnc else versions["credential"],
        "schema": "v2",
        "created": stamp,
    }
    digest_material = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    payload["digest"] = hashlib.sha256(digest_material).hexdigest()
    payload.pop("asset_id")
    return payload


def _upsert_projection(db: Session, *, asset_id: str, revision: int, digest: str,
                       domain_id: str, now: float) -> PlaneProjection:
    row = db.scalar(select(PlaneProjection).where(
        PlaneProjection.asset_id == asset_id, PlaneProjection.domain_id == domain_id))
    if row is None:
        row = PlaneProjection(id=str(uuid.uuid4()), asset_id=asset_id,
                              domain_id=domain_id, status="pending",
                              desired_revision=0, desired_digest="",
                              applied_revision=0, applied_digest="",
                              generation="", policy_fingerprint="",
                              error="", ack_at=0.0)
        db.add(row)
    if revision > row.desired_revision or (
            revision == row.desired_revision and not row.desired_digest):
        row.desired_revision = revision
        row.desired_digest = digest
        row.status = "pending"
        row.error = ""
        row.ack_at = 0.0
    elif revision == row.desired_revision and row.desired_digest != digest:
        raise PlatformError("connection_revision_mismatch",
                            "同版本摘要不一致，拒绝覆盖已确认配置", 409)
    db.flush()
    return row


def record_change(db: Session, *, asset_ids: Sequence[str], reason: str, actor: str,
                  now: float | None = None, create_pending: bool = True,
                  domain_id: str | None = None) -> list[str]:
    stamp = time.time() if now is None else now
    ids = sorted(set(asset_ids))
    if not ids:
        return []
    assets = db.scalars(select(Asset).where(Asset.id.in_(ids))
                        .order_by(Asset.id).with_for_update()).all()
    if len(assets) != len(ids):
        raise PlatformError("asset_not_found", "资产不存在", 404)

    event_ids: list[str] = []
    for asset in assets:
        target_domain = resolve_domain_id(db, asset.id, preferred=domain_id)
        conn_revision = _next_revision(db, AssetConnection, asset.id)
        snapshot = _snapshot(db, asset, stamp)
        db.add(AssetConnection(id=str(uuid.uuid4()), asset_id=asset.id,
                               revision=conn_revision, **snapshot))
        if create_pending:
            db.add(DeviceAdmission(
                id=str(uuid.uuid4()), asset_id=asset.id,
                revision=_next_revision(db, DeviceAdmission, asset.id),
                state=ADMISSION_PENDING, tenant_id=asset.tenant_id,
                identity_digest=_identity_digest(asset),
                domain_id=target_domain, created=stamp))
        _upsert_projection(db, asset_id=asset.id, revision=conn_revision,
                           digest=snapshot["digest"], domain_id=target_domain,
                           now=stamp)
        event_id = str(uuid.uuid4())
        db.add(PlaneOutbox(event_id=event_id, asset_id=asset.id,
                           revision=conn_revision, event_type=reason,
                           created=stamp, next_attempt=stamp))
        audit(db, actor, "connection_config_changed", asset_id=asset.id,
              detail={"reason": reason, "revision": conn_revision,
                      "digest": snapshot["digest"]}, now=stamp,
              tenant_id=asset.tenant_id)
        event_ids.append(event_id)
        db.flush()
    db.flush()
    return event_ids


def admit_asset(db: Session, *, asset_id: str, tenant_id: str | None, approver: str,
                evidence: str, review_due: float, expires: float, domain_id: str,
                actor: str, now: float | None = None) -> DeviceAdmission:
    stamp = time.time() if now is None else now
    asset = db.get(Asset, asset_id)
    if asset is None:
        raise PlatformError("asset_not_found", "资产不存在", 404)
    row = DeviceAdmission(
        id=str(uuid.uuid4()), asset_id=asset_id,
        revision=_next_revision(db, DeviceAdmission, asset_id),
        state=ADMISSION_APPROVED, tenant_id=tenant_id,
        identity_digest=_identity_digest(asset), domain_id=domain_id,
        approver=approver, evidence=evidence, review_due=review_due,
        expires=expires, created=stamp)
    db.add(row)
    record_change(db, asset_ids=[asset_id], reason="admission_approved",
                  actor=actor, now=stamp, create_pending=False, domain_id=domain_id)
    db.flush()
    return row


def revoke_admission(db: Session, *, asset_id: str, actor: str,
                     now: float | None = None) -> DeviceAdmission:
    stamp = time.time() if now is None else now
    asset = db.get(Asset, asset_id)
    if asset is None:
        raise PlatformError("asset_not_found", "资产不存在", 404)
    domain_id = resolve_domain_id(db, asset_id)
    row = DeviceAdmission(
        id=str(uuid.uuid4()), asset_id=asset_id,
        revision=_next_revision(db, DeviceAdmission, asset_id),
        state=ADMISSION_REVOKED, tenant_id=asset.tenant_id,
        identity_digest=_identity_digest(asset),
        domain_id=domain_id, created=stamp)
    db.add(row)
    record_change(db, asset_ids=[asset_id], reason="admission_revoked",
                  actor=actor, now=stamp, create_pending=False,
                  domain_id=domain_id)
    db.flush()
    return row


def ack_projection(db: Session, *, event_id: str, asset_id: str, revision: int,
                   digest: str, domain_id: str, generation: str,
                   policy_fingerprint: str, now: float | None = None) -> bool:
    stamp = time.time() if now is None else now
    row = db.scalar(select(PlaneProjection).where(
        PlaneProjection.asset_id == asset_id, PlaneProjection.domain_id == domain_id))
    if row is None or row.desired_revision != revision or row.desired_digest != digest:
        return False
    row.applied_revision = revision
    row.applied_digest = digest
    row.generation = generation
    row.policy_fingerprint = policy_fingerprint
    row.status = "ready"
    row.error = ""
    row.ack_at = stamp
    event = db.get(PlaneOutbox, event_id)
    if event is not None and event.asset_id == asset_id and event.revision == revision:
        event.lease_owner = ""
        event.lease_until = 0.0
        event.next_attempt = 0.0
    db.flush()
    return True


def device_admission_status(db: Session, *, asset_id: str,
                            now: float | None = None) -> dict:
    stamp = time.time() if now is None else float(now)
    admission = db.scalar(select(DeviceAdmission).where(
        DeviceAdmission.asset_id == asset_id).order_by(
            DeviceAdmission.revision.desc()).limit(1))
    connection = db.scalar(select(AssetConnection).where(
        AssetConnection.asset_id == asset_id).order_by(
            AssetConnection.revision.desc()).limit(1))
    domain_id = (admission.domain_id if admission is not None and admission.domain_id
                 else resolve_domain_id(db, asset_id))
    projection = db.scalar(select(PlaneProjection).where(
        PlaneProjection.asset_id == asset_id,
        PlaneProjection.domain_id == domain_id))
    domain = (db.get(ExecutionDomain, projection.domain_id)
              if projection is not None and projection.domain_id else None)

    desired = None
    applied = None
    if connection is not None:
        desired = {
            "revision": connection.revision,
            "digest": connection.digest,
            "domain_id": projection.domain_id if projection else domain_id,
            "generation": domain.generation if domain else "",
            "policy_fingerprint": domain.policy_fingerprint if domain else "",
        }
    if projection is not None and projection.applied_revision:
        applied = {
            "revision": projection.applied_revision,
            "digest": projection.applied_digest,
            "ack_at": projection.ack_at,
        }

    reason = None
    if admission is None or admission.state == ADMISSION_PENDING:
        state, available = "pending", False
        reason = "approval_pending"
    elif admission.state == ADMISSION_REVOKED:
        state, available = "unavailable", False
        reason = "admission_revoked"
    elif admission.expires <= stamp:
        state, available = "unavailable", False
        reason = "admission_expired"
    elif admission.review_due <= stamp:
        state, available = "unavailable", False
        reason = "review_overdue"
    elif connection is None or not connection.adapter:
        state, available = "incomplete", False
        reason = "connection_incomplete"
    elif projection is None or projection.applied_revision < connection.revision:
        state = "sync_failed" if projection is not None and projection.status == "blocked" else "syncing"
        available, reason = False, "projection_pending"
    elif projection.applied_digest != connection.digest:
        state, available, reason = "sync_failed", False, "digest_mismatch"
    elif domain is None or domain.health != "healthy":
        state, available, reason = "domain_unavailable", False, "domain_unavailable"
    elif projection.generation != domain.generation:
        state, available, reason = "domain_unavailable", False, "generation_mismatch"
    else:
        state, available = "available", True
    return {
        "asset_id": asset_id,
        "checked_at": stamp,
        "state": state,
        "available": available,
        "reason": reason,
        "desired": desired,
        "applied": applied,
    }
