"""Control-plane use cases: accounts, RBAC, assets, credentials, grants, audit."""
from __future__ import annotations

import json
import time
import uuid
from typing import Any

from sqlalchemy import and_, delete, func, select, update
from sqlalchemy.orm import Session

from .models import (AccessGrant, Asset, AuditLog, Capability, Credential,
                     DEFAULT_TENANT_CODE, DEFAULT_TENANT_ID, Permission, Role,
                     RolePermission, ROLE_ADMIN, ROLE_PLATFORM_ADMIN, Tenant, User,
                     UserRole, VendorProfile, json_field, parse_json)
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
