"""Control-plane use cases: accounts, RBAC, assets, credentials, grants, audit."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import re
import secrets
import sqlite3
import time
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import and_, delete, func, select, update
from sqlalchemy.orm import Session

from .models import (AccessGrant, Asset, AuditLog, Capability, Credential,
                     DEFAULT_TENANT_CODE, DEFAULT_TENANT_ID, Permission, Role,
                     RolePermission, ROLE_ADMIN, ROLE_OPERATOR, ROLE_PLATFORM_ADMIN,
                     TENANT_ACTIVE, QuotaUsage, ServiceToken, Tenant, User, UserRole,
                     VendorProfile, json_field, parse_json)
from .security import (CredentialCipher, hash_password, verify_password)

MAX_FAILED_ATTEMPTS = 5
LOCK_SECONDS = 900


class PlatformError(Exception):
    def __init__(self, code: str, message: str, status: int = 400):
        super().__init__(f"{code}: {message}")
        self.code, self.message, self.status = code, message, status


def default_tenant() -> str:
    return DEFAULT_TENANT_ID


def resolve_tenant(session: Session, code: str) -> Tenant:
    row = session.scalar(select(Tenant).where(Tenant.code == (code or "").strip()))
    if row is None:
        raise PlatformError("tenant_not_found", "租户不存在或已停用", 401)
    if row.status != "active":
        raise PlatformError("tenant_suspended", "租户已停用", 403)
    return row


def audit(session: Session, actor: str, action: str, *, asset_id: str | None = None,
          detail: dict | None = None, trace: str = "", now: float | None = None,
          tenant_id: str | None = default_tenant(), actor_type: str = "user",
          actor_tenant: str | None = None) -> None:
    session.add(AuditLog(ts=time.time() if now is None else now, trace_id=trace,
                         tenant_id=tenant_id, actor=actor, actor_type=actor_type,
                         actor_tenant=actor_tenant, action=action, asset_id=asset_id,
                         detail=json_field(detail or {})))


def authenticate(session: Session, username: str, password: str,
                 *, now: float | None = None, tenant_code: str = "") -> User:
    stamp = time.time() if now is None else now
    query = select(User).where(User.username == username)
    if tenant_code:
        query = query.where(User.tenant_id == resolve_tenant(session, tenant_code).id)
    matches = list(session.scalars(query).all())
    if not matches:
        verify_password(password, "$2b$12$" + "x" * 53)
        audit(session, username, "login_failed", tenant_id=None,
              detail={"reason": "unknown_account", "tenant_code": tenant_code}, now=stamp)
        session.commit()
        raise PlatformError("authentication_failed", "用户名或口令不正确", 401)
    if len(matches) > 1:
        raise PlatformError("tenant_required", "该用户名存在于多个租户，请填写租户码", 400)
    user = matches[0]
    if not bool(user.is_active):
        raise PlatformError("authentication_failed", "用户名或口令不正确", 401)
    if float(user.locked_until or 0) > stamp:
        raise PlatformError("account_locked", "账号暂时锁定，请稍后再试", 423)
    if not verify_password(password, user.password_hash):
        user.failed_attempts = int(user.failed_attempts or 0) + 1
        if user.failed_attempts >= MAX_FAILED_ATTEMPTS:
            user.failed_attempts = 0
            user.locked_until = stamp + LOCK_SECONDS
        audit(session, username, "login_failed", tenant_id=user.tenant_id,
              detail={"attempts": user.failed_attempts}, now=stamp)
        session.commit()
        raise PlatformError("authentication_failed", "用户名或口令不正确", 401)
    user.failed_attempts = 0
    user.locked_until = 0.0
    user.last_login = stamp
    audit(session, username, "login_succeeded", tenant_id=user.tenant_id, now=stamp)
    session.commit()
    return user


def roles_of(session: Session, user_id: str) -> list[str]:
    return [row[0] for row in session.execute(
        select(Role.code).join(UserRole, UserRole.role_id == Role.id)
        .where(UserRole.user_id == user_id)).all()]


def permissions_of(session: Session, user_id: str) -> set[str]:
    rows = session.execute(
        select(Permission.code)
        .join(RolePermission, RolePermission.permission_id == Permission.id)
        .join(UserRole, UserRole.role_id == RolePermission.role_id)
        .where(UserRole.user_id == user_id)).all()
    return {row[0] for row in rows}


def require(session: Session, user_id: str, code: str) -> None:
    if code not in permissions_of(session, user_id):
        raise PlatformError("permission_denied", f"缺少权限：{code}", 403)


def create_user(session: Session, username: str, password: str, role: str,
                *, actor: str, display_name: str = "", now: float | None = None,
                tenant_id: str = DEFAULT_TENANT_ID) -> User:
    if not username or not username.strip():
        raise PlatformError("invalid_username", "用户名不能为空")
    if tenant_id is None and role != ROLE_PLATFORM_ADMIN:
        raise PlatformError("invalid_tenant", "只有平台管理员可以不属于任何租户", 400)
    if session.get(Tenant, tenant_id) is None:
        raise PlatformError("tenant_not_found", "租户不存在", 404)
    if session.scalar(select(User.id).where(User.tenant_id == tenant_id,
                                           User.username == username)) is not None:
        raise PlatformError("user_exists", "该租户下用户名已存在", 409)
    role_row = session.scalar(select(Role).where(Role.code == role))
    if role_row is None:
        raise PlatformError("unknown_role", f"未知角色：{role}")
    user = User(id=str(uuid.uuid4()), tenant_id=tenant_id, username=username.strip(),
                display_name=display_name, password_hash=hash_password(password),
                is_active=True, created=time.time() if now is None else now)
    session.add(user)
    session.flush()
    session.add(UserRole(user_id=user.id, role_id=role_row.id))
    audit(session, actor, "user_created", now=now, tenant_id=tenant_id,
          actor_type="platform" if tenant_id is None else "user",
          detail={"username": user.username, "role": role})
    session.commit()
    return user


def list_users(session: Session, *, tenant_id: str = DEFAULT_TENANT_ID) -> list[dict]:
    out = []
    for user in session.scalars(
            select(User).where(User.tenant_id == tenant_id).order_by(User.created)).all():
        item = user.public()
        item["roles"] = roles_of(session, user.id)
        out.append(item)
    return out


def set_user_active(session: Session, user_id: str, active: bool, *, actor: str,
                    tenant_id: str = DEFAULT_TENANT_ID) -> None:
    user = session.get(User, user_id)
    if user is None or user.tenant_id != tenant_id:
        raise PlatformError("user_not_found", "用户不存在", 404)
    session.execute(update(User).where(User.id == user_id).values(is_active=active))
    audit(session, actor, "user_activation_changed", tenant_id=tenant_id,
          detail={"user_id": user_id, "active": active})
    session.commit()


def save_credential(session: Session, cipher: CredentialCipher, *, label: str,
                    username: str, password: str, actor: str,
                    now: float | None = None,
                    tenant_id: str = DEFAULT_TENANT_ID) -> Credential:
    if not cipher.available:
        raise PlatformError("credential_key_missing", "凭据主密钥未配置，无法写入 BMC 账号", 503)
    if not label or not username or not password:
        raise PlatformError("invalid_credential", "标签、账号与口令均不能为空")
    cred = Credential(id=str(uuid.uuid4()), tenant_id=tenant_id, label=label,
                      username_cipher=b"", password_cipher=b"",
                      created_by=actor, created=time.time() if now is None else now)
    cred.username_cipher = cipher.encrypt(username, aad=cred.id + ":username")
    cred.password_cipher = cipher.encrypt(password, aad=cred.id + ":password")
    session.add(cred)
    audit(session, actor, "credential_created", tenant_id=tenant_id,
          detail={"credential_id": cred.id, "label": label}, now=now)
    session.commit()
    return cred


def read_credential(session: Session, cipher: CredentialCipher, credential_id: str,
                    *, tenant_id: str | None = DEFAULT_TENANT_ID) -> dict:
    cred = session.get(Credential, credential_id)
    if cred is None or (tenant_id is not None and cred.tenant_id != tenant_id):
        raise PlatformError("credential_not_found", "凭据不存在", 404)
    if not cipher.available:
        raise PlatformError("credential_key_missing", "凭据主密钥未配置", 503)
    return {"id": cred.id, "label": cred.label,
            "username": cipher.decrypt(cred.username_cipher, aad=cred.id + ":username"),
            "password": cipher.decrypt(cred.password_cipher, aad=cred.id + ":password")}


def upsert_asset(session: Session, *, name: str, address: str, vendor: str = "",
                 model: str = "", firmware: str = "", fingerprint: str = "",
                 credential_id: str | None = None, profile_id: str | None = None,
                 capability_id: str | None = None, licence: str = "", notes: str = "",
                 actor: str, now: float | None = None,
                 tenant_id: str = DEFAULT_TENANT_ID) -> Asset:
    stamp = time.time() if now is None else now
    if not name or not address:
        raise PlatformError("invalid_asset", "资产名称与地址不能为空")
    existing = session.scalar(select(Asset).where(Asset.tenant_id == tenant_id,
                                                  Asset.address == address))
    if existing is None:
        enforce_asset_quota(session, tenant_id)
        existing = Asset(id=str(uuid.uuid4()), tenant_id=tenant_id, name=name,
                         address=address, created=stamp, updated=stamp)
        session.add(existing)
        action = "asset_created"
    else:
        action = "asset_updated"
    existing.name = name
    existing.vendor, existing.model, existing.firmware = vendor, model, firmware
    existing.fingerprint = fingerprint
    existing.credential_id = credential_id
    existing.profile_id = profile_id
    existing.capability_id = capability_id
    existing.licence, existing.notes = licence, notes
    existing.updated = stamp
    audit(session, actor, action, asset_id=existing.id, tenant_id=tenant_id,
          detail={"address": address, "vendor": vendor, "model": model,
                  "firmware": firmware, "profile_id": profile_id}, now=stamp)
    session.commit()
    return existing


def assign_asset(session: Session, *, address: str, tenant_id: str | None, actor: str,
                 name: str = "", reassign: bool = False,
                 now: float | None = None) -> dict:
    stamp = time.time() if now is None else now
    addr = (address or "").strip()
    if not addr:
        raise PlatformError("invalid_asset", "请填写设备 IP 地址")
    target = (tenant_id or "").strip() or None
    tenant = None
    if target is not None:
        tenant = session.get(Tenant, target)
        if tenant is None:
            raise PlatformError("tenant_not_found", "租户不存在", 404)
        if tenant.status != TENANT_ACTIVE:
            raise PlatformError("tenant_suspended", "租户已停用，不能接收设备", 403)

    candidates = session.scalars(
        select(Asset).where(Asset.address == addr).order_by(Asset.created)).all()
    if not candidates:
        if target is None:
            raise PlatformError("asset_not_found", "没有这个地址的设备", 404)
        enforce_asset_quota(session, target)
        asset = Asset(id=str(uuid.uuid4()), tenant_id=target, name=(name or addr).strip() or addr,
                      address=addr, created=stamp, updated=stamp)
        session.add(asset)
        session.flush()
        audit(session, actor, "asset_assigned", asset_id=asset.id, tenant_id=target,
              detail={"address": addr, "to": tenant.code, "action": "created"}, now=stamp)
        session.commit()
        return {"asset": asset.public(), "action": "created", "previous_tenant": None}

    same = next((row for row in candidates if row.tenant_id == target), None)
    if same is not None:
        if name and name.strip() and same.name != name.strip():
            same.name = name.strip()
            same.updated = stamp
            session.commit()
        return {"asset": same.public(), "action": "unchanged", "previous_tenant": None}

    if len(candidates) > 1:
        codes = sorted({session.get(Tenant, row.tenant_id).code if row.tenant_id else "(pool)"
                        for row in candidates})
        raise PlatformError("asset_ambiguous",
                            f"该地址已存在于多个归属：{', '.join(codes)}，请先合并重复记录", 409)

    asset = candidates[0]
    origin = session.get(Tenant, asset.tenant_id) if asset.tenant_id else None
    origin_code = origin.code if origin is not None else None
    if origin_code is not None and not reassign:
        raise PlatformError("asset_owned_by_tenant",
                            f"设备当前属于租户 {origin_code}，改派或回收需要显式确认", 409)
    if target is not None:
        enforce_asset_quota(session, target)
    if asset.credential_id:
        siblings = session.scalar(select(func.count()).select_from(Asset)
                                  .where(Asset.credential_id == asset.credential_id,
                                         Asset.id != asset.id)) or 0
        if siblings:
            raise PlatformError("credential_shared",
                                "该设备的凭据还被其他设备共用，请先拆分凭据再改派", 409)
    capability = session.get(Capability, asset.capability_id) if asset.capability_id else None
    asset.tenant_id = target
    if name and name.strip():
        asset.name = name.strip()
    asset.updated = stamp
    if capability is not None and capability.tenant_id != target:
        previous_tenant = (session.get(Tenant, capability.tenant_id).code
                           if capability.tenant_id else None)
        capability.tenant_id = target
        audit(session, actor, "capability_rehomed", asset_id=asset.id, tenant_id=target,
              detail={"capability_id": capability.id, "from": previous_tenant,
                      "to": tenant.code if tenant is not None else None}, now=stamp)
    if asset.credential_id:
        credential = session.get(Credential, asset.credential_id)
        if credential is not None and credential.tenant_id != target:
            credential.tenant_id = target
            audit(session, actor, "credential_rehomed", asset_id=asset.id, tenant_id=target,
                  detail={"credential_id": credential.id,
                          "to": tenant.code if tenant is not None else None}, now=stamp)
    action = "unassigned" if target is None else ("moved" if origin_code else "assigned")
    audit(session, actor, f"asset_{action}", asset_id=asset.id, tenant_id=target,
          detail={"address": addr, "from": origin_code,
                  "to": tenant.code if tenant is not None else None}, now=stamp)
    session.commit()
    return {"asset": asset.public(), "action": action, "previous_tenant": origin_code}


def assets_for_user(session: Session, user_id: str, *, now: float | None = None,
                    tenant_id: str = DEFAULT_TENANT_ID) -> list[dict]:
    stamp = time.time() if now is None else now
    rows = session.execute(
        select(Asset, AccessGrant.expires)
        .join(AccessGrant, AccessGrant.asset_id == Asset.id)
        .where(AccessGrant.user_id == user_id, AccessGrant.expires > stamp,
               Asset.tenant_id == tenant_id, AccessGrant.tenant_id == tenant_id)
        .order_by(Asset.name)).all()
    return [{**asset.public(), "grant_expires": expires} for asset, expires in rows]


def all_assets(session: Session, user_id: str, *, now: float | None = None,
               tenant_id: str = DEFAULT_TENANT_ID) -> list[dict]:
    stamp = time.time() if now is None else now
    rows = session.execute(
        select(Asset, AccessGrant.expires)
        .outerjoin(AccessGrant, and_(AccessGrant.asset_id == Asset.id,
                                     AccessGrant.user_id == user_id,
                                     AccessGrant.expires > stamp))
        .where(Asset.tenant_id == tenant_id)
        .order_by(Asset.name)).all()
    return [{**asset.public(), "grant_expires": expires} for asset, expires in rows]


def grant_asset(session: Session, *, user_id: str, asset_id: str, actor: str,
                ttl_seconds: int = 86400 * 30, now: float | None = None,
                tenant_id: str = DEFAULT_TENANT_ID) -> None:
    stamp = time.time() if now is None else now
    user = session.get(User, user_id)
    asset = session.get(Asset, asset_id)
    if user is None or user.tenant_id != tenant_id:
        raise PlatformError("grant_target_missing", "用户或资产不存在", 404)
    if asset is None or asset.tenant_id != tenant_id:
        raise PlatformError("grant_target_missing", "用户或资产不存在", 404)
    session.merge(AccessGrant(tenant_id=tenant_id, user_id=user_id, asset_id=asset_id,
                              expires=stamp + ttl_seconds, granted_by=actor, created=stamp))
    audit(session, actor, "grant_created", asset_id=asset_id, tenant_id=tenant_id,
          detail={"user_id": user_id, "expires": stamp + ttl_seconds}, now=stamp)
    session.commit()


def revoke_grant(session: Session, *, user_id: str, asset_id: str, actor: str,
                 tenant_id: str = DEFAULT_TENANT_ID) -> None:
    session.execute(delete(AccessGrant).where(AccessGrant.user_id == user_id,
                                              AccessGrant.asset_id == asset_id,
                                              AccessGrant.tenant_id == tenant_id))
    audit(session, actor, "grant_revoked", asset_id=asset_id, tenant_id=tenant_id,
          detail={"user_id": user_id})
    session.commit()


def capability_draft(session: Session, profile: VendorProfile, *, detection: dict,
                     actor: str, now: float | None = None,
                     tenant_id: str = DEFAULT_TENANT_ID) -> Capability:
    stamp = time.time() if now is None else now
    row = Capability(id=str(uuid.uuid4()), tenant_id=tenant_id,
                     vendor=profile.vendor,
                     model=str(detection.get("model") or ""),
                     firmware=str(detection.get("firmware") or ""),
                     adapter=profile.console_impl or "passthrough",
                     profile_id=profile.id, status="draft", expires=0.0,
                     evidence=profile.evidence, approver="", console_impl=profile.console_impl,
                     licence=profile.licence, models=json_field([detection.get("model") or ""]),
                     firmware_min=profile.firmware_min, firmware_max=profile.firmware_max,
                     protocol_versions=json_field([profile.rfb_version] if profile.rfb_version else []),
                     status_reason="auto-matched; awaiting out-of-band approval", created=stamp)
    session.add(row)
    audit(session, actor, "capability_draft_created", tenant_id=tenant_id,
          detail={"profile_id": profile.id, "capability_id": row.id,
                  "detection": {k: detection.get(k) for k in ("vendor", "model", "firmware")}}, now=stamp)
    session.commit()
    return row


def recent_audit(session: Session, limit: int = 100, *,
                 tenant_id: str | None = DEFAULT_TENANT_ID) -> list[dict]:
    query = select(AuditLog).order_by(AuditLog.id.desc()).limit(min(limit, 500))
    if tenant_id is not None:
        query = query.where(AuditLog.tenant_id == tenant_id)
    rows = session.scalars(query).all()
    return [{"id": r.id, "ts": r.ts, "tenant_id": r.tenant_id, "trace_id": r.trace_id,
             "actor": r.actor, "actor_type": r.actor_type, "actor_tenant": r.actor_tenant,
             "action": r.action, "asset_id": r.asset_id,
             "detail": json.loads(r.detail) if r.detail else {}} for r in rows]


def list_tenants(session: Session) -> list[dict]:
    return [row.public() for row in session.scalars(select(Tenant).order_by(Tenant.created)).all()]


QUOTA_KEYS = ("max_assets", "max_concurrent_sessions", "max_session_minutes")


def normalise_quotas(raw: dict) -> dict:
    clean: dict[str, int] = {}
    unknown = sorted(set(raw) - set(QUOTA_KEYS))
    if unknown:
        raise PlatformError("invalid_quota",
                            f"未知配额字段：{', '.join(unknown)}（可用：{', '.join(QUOTA_KEYS)}）", 400)
    for key in QUOTA_KEYS:
        value = raw.get(key)
        if value is None or value == "":
            continue
        if isinstance(value, bool) or not isinstance(value, (int, float, str)):
            raise PlatformError("invalid_quota", f"{key} 必须是整数或留空", 400)
        try:
            number = int(value)
        except (TypeError, ValueError):
            raise PlatformError("invalid_quota", f"{key} 必须是整数或留空", 400) from None
        if number < 0:
            raise PlatformError("invalid_quota", f"{key} 不能为负数", 400)
        if number > 0:
            clean[key] = number
    return clean


def update_tenant(session: Session, tenant_id: str, *, name: str | None = None,
                  plan: str | None = None, quotas: dict | None = None,
                  actor: str, now: float | None = None) -> Tenant:
    row = session.get(Tenant, tenant_id)
    if row is None:
        raise PlatformError("tenant_not_found", "租户不存在", 404)
    before = {"name": row.name, "plan": row.plan, "quotas": parse_json(row.quotas_json, {})}
    if name is not None:
        name = name.strip()
        if not name:
            raise PlatformError("invalid_tenant_name", "租户名称不能为空", 400)
        row.name = name
    if plan is not None:
        plan = plan.strip()
        if not plan:
            raise PlatformError("invalid_plan", "套餐不能为空", 400)
        row.plan = plan
    if quotas is not None:
        row.quotas_json = json_field(normalise_quotas(quotas))
    after = {"name": row.name, "plan": row.plan, "quotas": parse_json(row.quotas_json, {})}
    audit(session, actor, "tenant_updated", tenant_id=None, actor_type="platform",
          detail={"tenant_id": tenant_id, "code": row.code,
                  "before": before, "after": after}, now=now)
    session.commit()
    return row


def tenant_quotas(session: Session, tenant_id: str | None) -> dict:
    tenant = session.get(Tenant, tenant_id) if tenant_id else None
    return parse_json(tenant.quotas_json, {}) if tenant is not None else {}


def quota_limit(quotas: dict, key: str) -> int | None:
    try:
        value = int(quotas.get(key) or 0)
    except (TypeError, ValueError):
        return None
    return value if value > 0 else None


def enforce_asset_quota(session: Session, tenant_id: str) -> None:
    limit = quota_limit(tenant_quotas(session, tenant_id), "max_assets")
    if limit is None:
        return
    used = session.scalar(select(func.count()).select_from(Asset)
                          .where(Asset.tenant_id == tenant_id)) or 0
    if used >= limit:
        raise PlatformError("quota_exceeded", f"租户资产数已达上限（{limit}）", 429)


def create_tenant(session: Session, *, code: str, name: str, plan: str = "standard",
                  quotas: dict | None = None, actor: str,
                  now: float | None = None) -> Tenant:
    code = (code or "").strip()
    if not code or not code.replace("-", "").replace("_", "").isalnum():
        raise PlatformError("invalid_tenant_code", "租户码只能包含字母、数字、下划线与短横线", 400)
    if session.scalar(select(Tenant.id).where(Tenant.code == code)) is not None:
        raise PlatformError("tenant_exists", "租户码已存在", 409)
    stamp = time.time() if now is None else now
    row = Tenant(id=str(uuid.uuid4()), code=code, name=name or code, status="active",
                 plan=plan or "standard", quotas_json=json_field(quotas or {}), created=stamp)
    session.add(row)
    audit(session, actor, "tenant_created", tenant_id=None, actor_type="platform",
          detail={"tenant_id": row.id, "code": code, "plan": row.plan}, now=stamp)
    session.commit()
    return row


def set_tenant_status(session: Session, tenant_id: str, status: str, *, actor: str,
                      now: float | None = None) -> Tenant:
    if status not in ("active", "suspended"):
        raise PlatformError("invalid_status", "status 只能是 active 或 suspended", 400)
    row = session.get(Tenant, tenant_id)
    if row is None:
        raise PlatformError("tenant_not_found", "租户不存在", 404)
    if row.code == DEFAULT_TENANT_CODE and status != "active":
        raise PlatformError("default_tenant_protected", "默认租户不能停用", 400)
    row.status = status
    audit(session, actor, "tenant_status_changed", tenant_id=None, actor_type="platform",
          detail={"tenant_id": tenant_id, "code": row.code, "status": status},
          now=now)
    session.commit()
    return row


PERIOD_RE = re.compile(r"^\d{4}-(?:0[1-9]|1[0-2])$")


def period_bounds(period: str) -> tuple[float, float]:
    if not PERIOD_RE.fullmatch(str(period or "")):
        raise PlatformError("invalid_period", "period 必须是 YYYY-MM（UTC）", 400)
    start = datetime.strptime(period, "%Y-%m").replace(tzinfo=timezone.utc).timestamp()
    year, month = int(period[:4]), int(period[5:])
    end = (datetime(year + 1, 1, 1, tzinfo=timezone.utc).timestamp()
           if month == 12 else
           datetime(year, month + 1, 1, tzinfo=timezone.utc).timestamp())
    return start, end


def _plane_usage(plane_db: str, sids: set[str], start: float, end: float,
                 now: float) -> dict[str, tuple[int, int]]:
    try:
        db = sqlite3.connect(f"file:{plane_db}?mode=ro", uri=True)
    except sqlite3.Error as exc:
        raise PlatformError("data_plane_unavailable", f"数据面库不可读：{exc}", 503) from exc
    try:
        db.row_factory = sqlite3.Row
        ended, started = {}, {}
        for action, target in (("session_finished", ended), ("ticket_consumed", started)):
            for row in db.execute("SELECT session_id, MAX(ts) AS ts FROM audit "
                                  "WHERE action=? AND session_id IS NOT NULL "
                                  "GROUP BY session_id", (action,)):
                target[row["session_id"]] = row["ts"]
        usage: dict[str, tuple[int, int]] = {}
        for row in db.execute("SELECT id, created, consumed, hard_until, status "
                              "FROM session WHERE created>=? AND created<?", (start, end)):
            sid = row["id"]
            if sid not in sids or not row["consumed"]:
                continue
            finish = ended.get(sid)
            if finish is None and row["status"] not in ("closed", "failed", "lost"):
                finish = now
            first = max(row["created"], started.get(sid, row["created"]))
            last = min(finish if finish is not None else row["hard_until"],
                       row["hard_until"])
            minutes = max(1, math.ceil((last - first) / 60)) if last > first else 0
            usage[sid] = (1, minutes)
        return usage
    finally:
        db.close()


def rebuild_quota_usage(session: Session, *, plane_db: str, period: str,
                        now: float | None = None) -> dict:
    stamp = time.time() if now is None else now
    start, end = period_bounds(period)
    tickets: dict[str, str] = {}
    for row in session.scalars(select(AuditLog).where(
            AuditLog.action == "console_ticket_issued",
            AuditLog.ts >= start, AuditLog.ts < end)):
        detail = parse_json(row.detail, {})
        sid = str(detail.get("sid") or "")
        if sid and row.tenant_id:
            tickets[sid] = str(row.tenant_id)
    plane = _plane_usage(plane_db, set(tickets), start, end, stamp)
    tenants = [str(row) for row in session.scalars(select(Tenant.id))]
    sessions = {tenant: 0 for tenant in tenants}
    minutes = {tenant: 0 for tenant in tenants}
    for sid, tenant in tickets.items():
        count, total = plane.get(sid, (0, 0))
        sessions.setdefault(tenant, 0)
        minutes.setdefault(tenant, 0)
        sessions[tenant] += count
        minutes[tenant] += total

    asset_counts = {str(tenant_id): 0 for tenant_id in tenants}
    for tenant_id, count in session.execute(
            select(Asset.tenant_id, func.count()).group_by(Asset.tenant_id)):
        if tenant_id in asset_counts:
            asset_counts[str(tenant_id)] = int(count)

    session.execute(delete(QuotaUsage).where(QuotaUsage.period == period))
    for tenant_id in sorted(sessions):
        session.add(QuotaUsage(tenant_id=tenant_id, period=period,
                               assets=asset_counts.get(tenant_id, 0),
                               sessions=sessions[tenant_id],
                               minutes=minutes[tenant_id], updated=stamp))
    session.commit()
    return {"period": period, "tenants": len(sessions),
            "sessions": sum(sessions.values()), "minutes": sum(minutes.values()),
            "rebuilt_at": stamp}


def quota_usage_view(session: Session, period: str) -> list[dict]:
    period_bounds(period)
    rows = session.execute(
        select(QuotaUsage, Tenant.code).join(Tenant, Tenant.id == QuotaUsage.tenant_id)
        .where(QuotaUsage.period == period).order_by(Tenant.code)).all()
    return [{"tenant_id": usage.tenant_id, "tenant_code": code,
             "period": usage.period, "assets": usage.assets,
             "sessions": usage.sessions, "minutes": usage.minutes,
             "updated": usage.updated} for usage, code in rows]



def _allowlist(entries: Any) -> list[str]:
    if not isinstance(entries, (list, tuple)) or not entries:
        raise PlatformError("invalid_allowlist", "来源白名单不能为空", 400)
    out: list[str] = []
    for item in entries:
        try:
            out.append(str(ipaddress.ip_network(str(item).strip(), strict=False)))
        except ValueError as exc:
            raise PlatformError("invalid_allowlist", f"非法的来源网段：{item}", 400) from exc
    return out


def source_ip(peer: str | None, forwarded: str, trusted_proxies: str) -> str:
    try:
        address = ipaddress.ip_address(str(peer or ""))
    except ValueError:
        return ""
    networks = []
    for cidr in (item.strip() for item in (trusted_proxies or "").split(",")):
        if cidr:
            networks.append(ipaddress.ip_network(cidr, strict=False))
    if not networks or not any(address in net for net in networks):
        return str(address)
    chain = [item.strip() for item in (forwarded or "").split(",") if item.strip()]
    for candidate in reversed(chain):
        try:
            hop = ipaddress.ip_address(candidate)
        except ValueError:
            continue
        if not any(hop in net for net in networks):
            return str(hop)
    return str(address)


def ip_allowed(address: str, networks: list[str]) -> bool:
    if not address:
        return False
    try:
        peer = ipaddress.ip_address(address)
    except ValueError:
        return False
    return any(peer in ipaddress.ip_network(cidr, strict=False) for cidr in networks)


def _service_user(session: Session, tenant: Tenant) -> User:
    username = f"svc-dcim-{tenant.code}"
    user = session.scalar(select(User).where(User.tenant_id == tenant.id,
                                             User.username == username))
    if user is not None:
        return user
    role = session.scalar(select(Role).where(Role.code == ROLE_OPERATOR))
    if role is None:
        raise PlatformError("unknown_role", "服务主体所需角色不存在")
    user = User(id=str(uuid.uuid4()), tenant_id=tenant.id, username=username,
                display_name=f"DCIM service account ({tenant.code})",
                password_hash=hash_password(secrets.token_urlsafe(48)),
                is_active=False, created=time.time())
    session.add(user)
    session.flush()
    session.add(UserRole(user_id=user.id, role_id=role.id))
    return user


def create_service_token(session: Session, *, tenant_code: str, label: str,
                         allowlist: list[str], actor: str,
                         expires_days: int | None = None,
                         now: float | None = None) -> dict:
    tenant = session.scalar(select(Tenant).where(Tenant.code == tenant_code))
    if tenant is None:
        raise PlatformError("tenant_not_found", "租户不存在", 404)
    if tenant.status != TENANT_ACTIVE:
        raise PlatformError("tenant_suspended", "租户已停用", 403)
    label = str(label or "").strip()
    if not label:
        raise PlatformError("invalid_label", "凭据名称不能为空", 400)
    if session.scalar(select(ServiceToken.id).where(ServiceToken.tenant_id == tenant.id,
                                                    ServiceToken.label == label)) is not None:
        raise PlatformError("token_label_exists", "该租户下凭据名称已存在", 409)
    if expires_days is not None and (not isinstance(expires_days, int) or not 1 <= expires_days <= 3650):
        raise PlatformError("invalid_expiry", "有效期天数必须在 1..3650", 400)
    networks = _allowlist(allowlist)
    user = _service_user(session, tenant)
    raw = secrets.token_urlsafe(32)
    stamp = time.time() if now is None else now
    token = ServiceToken(id=str(uuid.uuid4()), tenant_id=tenant.id, user_id=user.id,
                         label=label, prefix=raw[:8],
                         token_hash=hashlib.sha256(raw.encode()).hexdigest(),
                         allowlist_json=json_field(networks),
                         expires=stamp + expires_days * 86400 if expires_days else None,
                         created=stamp, created_by=actor)
    session.add(token)
    audit(session, actor, "service_token_created", now=now, tenant_id=tenant.id,
          actor_type="platform", detail={"id": token.id, "label": label,
                                         "allowlist": networks,
                                         "expires": token.expires})
    session.commit()
    result = token.public()
    result["token"] = raw
    return result


def list_service_tokens(session: Session, *, tenant_code: str = "") -> list[dict]:
    query = select(ServiceToken, Tenant.code).join(Tenant, Tenant.id == ServiceToken.tenant_id)
    if tenant_code:
        query = query.where(Tenant.code == tenant_code)
    return [{**token.public(), "tenant_code": code}
            for token, code in session.execute(query.order_by(ServiceToken.created)).all()]


def revoke_service_token(session: Session, token_id: str, *, actor: str,
                         now: float | None = None) -> dict:
    token = session.get(ServiceToken, str(token_id))
    if token is None:
        raise PlatformError("token_not_found", "凭据不存在", 404)
    if token.revoked is None:
        token.revoked = time.time() if now is None else now
        audit(session, actor, "service_token_revoked", now=now, tenant_id=token.tenant_id,
              actor_type="platform", detail={"id": token.id, "label": token.label})
        session.commit()
    return token.public()


def authenticate_service_token(session: Session, raw: str, peer: str | None,
                               forwarded: str = "", *, trusted_proxies: str = "") -> dict:
    if not raw or not isinstance(raw, str):
        raise PlatformError("authentication_required", "缺少服务凭据", 401)
    digest = hashlib.sha256(raw.encode()).hexdigest()
    token = session.scalar(select(ServiceToken).where(ServiceToken.token_hash == digest))
    if token is None:
        raise PlatformError("invalid_service_token", "服务凭据无效", 401)
    now = time.time()
    if token.revoked is not None:
        raise PlatformError("service_token_revoked", "服务凭据已撤销", 401)
    if token.expires is not None and token.expires <= now:
        raise PlatformError("service_token_expired", "服务凭据已过期", 401)
    address = source_ip(peer, forwarded, trusted_proxies)
    if not ip_allowed(address, parse_json(token.allowlist_json, [])):
        raise PlatformError("source_not_allowed", "来源地址不在凭据白名单内", 403)
    tenant = session.get(Tenant, token.tenant_id)
    user = session.get(User, token.user_id)
    if tenant is None or tenant.status != TENANT_ACTIVE or user is None or user.tenant_id != tenant.id:
        raise PlatformError("service_principal_invalid", "服务主体或租户不可用", 403)
    token.last_used = now
    session.commit()
    return {"user_id": user.id, "username": user.username, "tenant_id": tenant.id,
            "tenant_code": tenant.code, "token_id": token.id, "token_label": token.label,
            "token_prefix": token.prefix, "actor_type": "dcim_system"}
