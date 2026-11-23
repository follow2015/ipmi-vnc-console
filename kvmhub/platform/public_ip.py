"""Tenant-facing public IP aliases, kept strictly separate from IPMI addresses."""
from __future__ import annotations

import ipaddress
import re
import time
import uuid

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .models import Asset, PublicIpAlias, PublicIpMapping
from .services import PlatformError, audit

_SPLIT = re.compile(r"[,，;；\s]+")
_HOSTNAME = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")


def normalize_public_ips(raw) -> list[str]:
    if raw is None:
        return []
    if isinstance(raw, (list, tuple)):
        parts = [str(item) for item in raw]
    else:
        parts = _SPLIT.split(str(raw))
    out: list[str] = []
    seen: set[str] = set()
    for token in parts:
        value = token.strip()
        if not value:
            continue
        try:
            ipaddress.ip_address(value)
        except ValueError:
            if re.fullmatch(r"\d+(?:\.\d+)+", value):
                raise PlatformError("public_ip_invalid", f"公网 IP 格式不合法：{value[:64]}") from None
            if len(value) > 253 or not _HOSTNAME.match(value):
                raise PlatformError("public_ip_invalid", f"公网 IP 格式不合法：{value[:64]}") from None
        key = value.lower()
        if key not in seen:
            seen.add(key)
            out.append(value)
    return out


def mapping_for_asset(session: Session, asset_id: str) -> PublicIpMapping | None:
    return session.scalar(select(PublicIpMapping).where(PublicIpMapping.asset_id == asset_id))


def public_ips_for_asset(session: Session, asset_id: str) -> list[str]:
    row = mapping_for_asset(session, asset_id)
    if row is None:
        return []
    return [row.primary_ip, *[p for p in _SPLIT.split(row.additional_ips or "") if p.strip()]]


def all_ips(row: PublicIpMapping) -> list[str]:
    return [row.primary_ip, *[p for p in _SPLIT.split(row.additional_ips or "") if p.strip()]]


def _alias_rows(session: Session, mapping_id: str) -> list[PublicIpAlias]:
    return list(session.scalars(select(PublicIpAlias).where(
        PublicIpAlias.mapping_id == mapping_id)).all())


def _replace_aliases(session: Session, mapping: PublicIpMapping,
                     ips: list[str], stamp: float) -> None:
    for row in _alias_rows(session, mapping.id):
        session.delete(row)
    session.flush()
    for ip in ips:
        session.add(PublicIpAlias(
            id=str(uuid.uuid4()), tenant_id=mapping.tenant_id, ip=ip.lower(),
            asset_id=mapping.asset_id, mapping_id=mapping.id,
            created=stamp, updated=stamp))
    session.flush()


def view(asset: Asset, session: Session, *, show_ipmi: bool) -> dict:
    ips = public_ips_for_asset(session, asset.id)
    return asset.public(public_ip=ips[0] if ips else None, public_ips=ips,
                        show_ipmi=show_ipmi)


def upsert_public_ip(session: Session, *, tenant_id: str, asset_id: str,
                     raw, actor: str, now: float | None = None) -> PublicIpMapping | None:
    stamp = time.time() if now is None else now
    asset = session.get(Asset, asset_id)
    if asset is None or asset.tenant_id != tenant_id:
        raise PlatformError("cross_tenant_asset", "资产不存在或不属于该租户", 403)
    ips = normalize_public_ips(raw)
    existing = mapping_for_asset(session, asset_id)
    if not ips:
        if existing is not None:
            for row in _alias_rows(session, existing.id):
                session.delete(row)
            session.delete(existing)
            audit(session, actor, "public_ip_cleared", asset_id=asset_id,
                  tenant_id=tenant_id, detail={"asset_id": asset_id}, now=stamp)
            session.flush()
        return None
    claimed: dict[str, str] = {}
    for other in session.scalars(select(Asset).where(Asset.tenant_id == tenant_id)):
        if other.id == asset_id:
            continue
        if other.address:
            claimed[other.address.strip().lower()] = other.id
    for row in session.scalars(select(PublicIpMapping).where(
            PublicIpMapping.tenant_id == tenant_id)):
        if row.asset_id == asset_id:
            continue
        for ip in all_ips(row):
            claimed[ip.lower()] = row.asset_id
    for row in session.scalars(select(PublicIpAlias).where(
            PublicIpAlias.tenant_id == tenant_id)):
        if row.asset_id != asset_id:
            claimed[row.ip] = row.asset_id
    for ip in ips:
        owner = claimed.get(ip.lower())
        if owner:
            raise PlatformError("public_ip_conflict",
                                "公网 IP 已被本租户其它资产占用", 409)
    if existing is None:
        existing = PublicIpMapping(id=str(uuid.uuid4()), tenant_id=tenant_id,
                                   asset_id=asset_id, primary_ip=ips[0],
                                   created=stamp, updated=stamp)
        session.add(existing)
        action = "public_ip_created"
    else:
        action = "public_ip_updated"
    existing.primary_ip = ips[0]
    existing.additional_ips = ",".join(ips[1:])
    existing.updated = stamp
    audit(session, actor, action, asset_id=asset_id, tenant_id=tenant_id,
          detail={"asset_id": asset_id, "public_ips": ips}, now=stamp)
    try:
        session.flush()
        _replace_aliases(session, existing, ips, stamp)
    except IntegrityError as exc:
        raise PlatformError("public_ip_conflict",
                            "公网 IP 已被本租户其它资产占用", 409) from exc
    return existing


def asset_by_public_ip(session: Session, tenant_id: str | None,
                       address: str) -> Asset | None:
    value = (address or "").strip()
    if not value:
        return None
    by_ipmi = session.scalars(select(Asset).where(Asset.address == value)).all()
    if tenant_id is not None:
        by_ipmi = [a for a in by_ipmi if a.tenant_id == tenant_id]
    if len(by_ipmi) == 1:
        return by_ipmi[0]
    if len(by_ipmi) > 1:
        return None
    query = select(PublicIpMapping)
    if tenant_id is not None:
        query = query.where(PublicIpMapping.tenant_id == tenant_id)
    matched_asset_ids = set()
    for row in session.scalars(query):
        if any(ip.lower() == value.lower() for ip in all_ips(row)):
            matched_asset_ids.add(row.asset_id)
    if len(matched_asset_ids) != 1:
        return None
    asset = session.get(Asset, next(iter(matched_asset_ids)))
    if asset is None:
        return None
    if tenant_id is not None and asset.tenant_id != tenant_id:
        return None
    return asset


def rehome_mapping(session: Session, *, asset_id: str, tenant_id: str | None,
                   actor: str, now: float | None = None) -> None:
    stamp = time.time() if now is None else now
    row = mapping_for_asset(session, asset_id)
    if row is None:
        return
    if tenant_id is None:
        previous = row.tenant_id
        for alias in _alias_rows(session, row.id):
            session.delete(alias)
        session.delete(row)
        audit(session, actor, "public_ip_removed_on_unassign", asset_id=asset_id,
              tenant_id=previous, detail={"asset_id": asset_id}, now=stamp)
    elif row.tenant_id != tenant_id:
        previous = row.tenant_id
        row.tenant_id = tenant_id
        row.updated = stamp
        for alias in _alias_rows(session, row.id):
            alias.tenant_id = tenant_id
            alias.updated = stamp
        audit(session, actor, "public_ip_rehomed", asset_id=asset_id,
              tenant_id=tenant_id, detail={"from": previous, "to": tenant_id},
              now=stamp)


def mapping_view(row: PublicIpMapping) -> dict:
    ips = all_ips(row)
    return {"id": row.id, "tenant_id": row.tenant_id, "asset_id": row.asset_id,
            "primary_ip": row.primary_ip, "additional_ips": row.additional_ips,
            "public_ips": ips, "created": row.created, "updated": row.updated}
