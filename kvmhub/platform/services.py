"""Control-plane use cases: accounts, RBAC, assets, credentials, grants, audit."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
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

from .models import (AccessGrant, Asset, AssetGroup, AssetGroupMember, AuditLog,
                     Capability, Credential, DEFAULT_TENANT_CODE, DEFAULT_TENANT_ID,
                     Permission, GrantSource, Role, RolePermission,
                     ROLE_ADMIN, ROLE_OPERATOR, ROLE_VIEWER, ROLE_PLATFORM_ADMIN,
                     TENANT_ACTIVE, TENANT_MODE_CONSUMER, TENANT_MODE_MANAGER,
                     TENANT_MODE_PERMISSIONS, TENANT_MODES, QuotaUsage, ServiceToken,
                     Tenant, User, UserRole, VendorProfile, json_field, parse_json,
                     roles_for_tenant_mode)
from .security import (CredentialCipher, hash_password, verify_password)
from ..sql_backend import open_store, parse_store_dsn

logger = logging.getLogger(__name__)

MAX_FAILED_ATTEMPTS = 5
LOCK_SECONDS = 900


class PlatformError(Exception):
    def __init__(self, code: str, message: str, status: int = 400,
                 *, retryable: bool = False):
        super().__init__(f"{code}: {message}")
        self.code, self.message, self.status = code, message, status
        self.retryable = retryable


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


def tenant_mode_permissions(session: Session, tenant_id: str | None) -> frozenset[str]:
    row = session.get(Tenant, tenant_id) if tenant_id else None
    mode = row.mode if row else TENANT_MODE_CONSUMER
    return frozenset(TENANT_MODE_PERMISSIONS.get(mode, TENANT_MODE_PERMISSIONS[TENANT_MODE_CONSUMER]))


def allowed_roles_for_tenant(session: Session, tenant_id: str) -> frozenset[str]:
    row = session.get(Tenant, tenant_id) if tenant_id else None
    return roles_for_tenant_mode(row.mode if row else None)


def assert_role_for_tenant(session: Session, tenant_id: str, role: str) -> None:
    if tenant_id and role not in allowed_roles_for_tenant(session, tenant_id):
        raise PlatformError("role_not_allowed",
                            f"该租户类型不支持此角色：{role}", 400)


def effective_permissions(session: Session, user_id: str,
                          tenant_id: str | None = None) -> set[str]:
    granted = permissions_of(session, user_id)
    if tenant_id is None:
        return granted
    return granted & set(tenant_mode_permissions(session, tenant_id))


def require(session: Session, user_id: str, code: str, *, tenant_id: str) -> None:
    if not tenant_id:
        raise ValueError("require() needs a tenant_id; use require_platform() for platform codes")
    if code.startswith("platform."):
        raise ValueError(f"{code} is a platform permission; use require_platform()")
    if code not in effective_permissions(session, user_id, tenant_id):
        raise PlatformError("permission_denied", f"缺少权限：{code}", 403)


def require_platform(session: Session, user_id: str, code: str) -> None:
    if not code.startswith("platform."):
        raise ValueError(f"{code} is not a platform permission; use require(tenant_id=...)")
    if code not in permissions_of(session, user_id):
        raise PlatformError("permission_denied", f"缺少权限：{code}", 403)


def create_user(session: Session, username: str, password: str, role: str,
                *, actor: str, display_name: str = "", now: float | None = None,
                tenant_id: str = DEFAULT_TENANT_ID) -> User:
    if not username or not username.strip():
        raise PlatformError("invalid_username", "用户名不能为空")
    if tenant_id is None and role != ROLE_PLATFORM_ADMIN:
        raise PlatformError("invalid_tenant", "只有平台管理员可以不属于任何租户", 400)
    if tenant_id is not None and role == ROLE_PLATFORM_ADMIN:
        raise PlatformError("invalid_role", "租户账号不能使用平台管理员角色", 400)
    if session.get(Tenant, tenant_id) is None:
        raise PlatformError("tenant_not_found", "租户不存在", 404)
    if session.scalar(select(User.id).where(User.tenant_id == tenant_id,
                                           User.username == username)) is not None:
        raise PlatformError("user_exists", "该租户下用户名已存在", 409)
    role_row = session.scalar(select(Role).where(Role.code == role))
    if role_row is None:
        raise PlatformError("unknown_role", f"未知角色：{role}")
    if tenant_id is not None:
        assert_role_for_tenant(session, tenant_id, role)
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
                    tenant_id: str | None = DEFAULT_TENANT_ID,
                    plane: Any | None = None) -> None:
    user = session.get(User, user_id)
    if user is None or user.tenant_id is None:
        raise PlatformError("user_not_found", "用户不存在", 404)
    if tenant_id is not None and user.tenant_id != tenant_id:
        raise PlatformError("user_not_found", "用户不存在", 404)
    session.execute(update(User).where(User.id == user_id).values(is_active=active))
    audit(session, actor, "user_activation_changed", tenant_id=user.tenant_id,
          detail={"user_id": user_id, "active": active})
    session.commit()
    if plane is not None and not active:
        plane.revoke_subject(user_id, trace="")


_ROLE_RANK = {ROLE_VIEWER: 0, ROLE_OPERATOR: 1, ROLE_ADMIN: 2}


def set_user_role(session: Session, user_id: str, role: str, *, actor: str,
                  tenant_id: str | None = None, plane: Any | None = None) -> User:
    if role not in (ROLE_ADMIN, ROLE_OPERATOR, ROLE_VIEWER):
        raise PlatformError("unknown_role", f"未知角色：{role}", 400)
    user = session.get(User, user_id)
    if user is None or user.tenant_id is None:
        raise PlatformError("user_not_found", "用户不存在", 404)
    if tenant_id is not None and user.tenant_id != tenant_id:
        raise PlatformError("user_not_found", "用户不存在", 404)
    role_row = session.scalar(select(Role).where(Role.code == role))
    if role_row is None:
        raise PlatformError("unknown_role", f"未知角色：{role}")
    assert_role_for_tenant(session, user.tenant_id, role)
    before = roles_of(session, user_id)
    before_rank = max((_ROLE_RANK.get(code, -1) for code in before), default=-1)
    session.execute(delete(UserRole).where(UserRole.user_id == user_id))
    session.add(UserRole(user_id=user_id, role_id=role_row.id))
    audit(session, actor, "user_role_changed", tenant_id=user.tenant_id,
          actor_type="platform",
          detail={"user_id": user_id, "before": before, "after": [role]})
    session.commit()
    if plane is not None and _ROLE_RANK.get(role, -1) < before_rank:
        plane.bump_subject_epoch(user_id, trace="")
    return user


def set_user_password(session: Session, user_id: str, password: str, *, actor: str,
                      tenant_id: str | None) -> None:
    if not password or not password.strip():
        raise PlatformError("invalid_password", "新密码不能为空", 400)
    user = session.get(User, user_id)
    if user is None or (tenant_id is not None and user.tenant_id != tenant_id):
        raise PlatformError("user_not_found", "用户不存在", 404)
    session.execute(update(User).where(User.id == user_id)
                    .values(password_hash=hash_password(password)))
    audit(session, actor, "user_password_reset", tenant_id=user.tenant_id,
          actor_type="platform" if tenant_id is None else "user",
          detail={"user_id": user_id, "username": user.username})
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




def save_vnc_secret(session: Session, cipher: CredentialCipher, *, asset_id: str,
                    username: str, password: str, actor: str,
                    now: float | None = None,
                    tenant_id: str | None = DEFAULT_TENANT_ID) -> Asset:
    if not cipher.available:
        raise PlatformError("credential_key_missing", "凭据主密钥未配置，无法写入 VNC 凭据", 503)
    if not username or not password:
        raise PlatformError("invalid_vnc_credential", "VNC 账号与口令均不能为空")
    asset = session.get(Asset, asset_id)
    if asset is None:
        raise PlatformError("asset_not_found", "资产不存在", 404)
    if tenant_id is not None and asset.tenant_id != tenant_id:
        raise PlatformError("cross_tenant_asset", "资产不属于当前租户", 403)
    stamp = time.time() if now is None else now
    asset.vnc_username_cipher = cipher.encrypt(username, aad=asset.id + ":vnc_username")
    asset.vnc_password_cipher = cipher.encrypt(password, aad=asset.id + ":vnc_password")
    asset.vnc_key_version = 1
    asset.updated = stamp
    audit(session, actor, "vnc_secret_saved", asset_id=asset.id,
          tenant_id=asset.tenant_id,
          detail={"key_version": 1, "credential_id_unchanged": True}, now=stamp)
    session.flush()
    return asset


def clear_vnc_secret(session: Session, *, asset_id: str, actor: str,
                     now: float | None = None,
                     tenant_id: str | None = DEFAULT_TENANT_ID) -> Asset:
    asset = session.get(Asset, asset_id)
    if asset is None:
        raise PlatformError("asset_not_found", "资产不存在", 404)
    if tenant_id is not None and asset.tenant_id != tenant_id:
        raise PlatformError("cross_tenant_asset", "资产不属于当前租户", 403)
    stamp = time.time() if now is None else now
    asset.vnc_username_cipher = None
    asset.vnc_password_cipher = None
    asset.vnc_key_version = 1
    asset.updated = stamp
    audit(session, actor, "vnc_secret_cleared", asset_id=asset.id,
          tenant_id=asset.tenant_id, now=stamp)
    session.flush()
    return asset


def has_vnc_secret(asset: Asset) -> bool:
    return bool(asset.vnc_username_cipher and asset.vnc_password_cipher)


def read_vnc_secret(session: Session, cipher: CredentialCipher, asset_id: str,
                    *, tenant_id: str | None = DEFAULT_TENANT_ID) -> dict:
    asset = session.get(Asset, asset_id)
    if asset is None:
        raise PlatformError("asset_not_found", "资产不存在", 404)
    if tenant_id is not None and asset.tenant_id != tenant_id:
        raise PlatformError("cross_tenant_asset", "资产不属于当前租户", 403)
    if not has_vnc_secret(asset):
        raise PlatformError("vnc_secret_not_found", "该资产未配置隐藏 VNC 凭据", 404)
    if not cipher.available:
        raise PlatformError("credential_key_missing", "凭据主密钥未配置", 503)
    return {
        "username": cipher.decrypt(asset.vnc_username_cipher, aad=asset.id + ":vnc_username"),
        "password": cipher.decrypt(asset.vnc_password_cipher, aad=asset.id + ":vnc_password"),
    }


def select_sync_secret(session: Session, cipher: CredentialCipher, asset: Asset,
                       *, tenant_id: str | None = DEFAULT_TENANT_ID) -> tuple[dict, str]:
    if has_vnc_secret(asset):
        return read_vnc_secret(session, cipher, asset.id, tenant_id=tenant_id), "vnc_hidden"
    if not asset.credential_id:
        raise PlatformError("credential_missing", "资产未绑定 BMC 凭据", 404)
    return read_credential(session, cipher, asset.credential_id, tenant_id=tenant_id), "bmc"


def _assert_owned_refs(session: Session, tenant_id: str, *,
                       credential: str | None, profile: str | None,
                       capability: str | None) -> None:
    refs = (
        (Credential, credential, "credential"),
        (VendorProfile, profile, "profile"),
        (Capability, capability, "capability"),
    )
    for model, ref_id, label in refs:
        if not ref_id:
            continue
        row = session.get(model, ref_id)
        if row is None:
            raise PlatformError(label + "_not_found", f"{label} 不存在", 400)
        owner = getattr(row, "tenant_id", None)
        if owner is not None and owner != tenant_id:
            raise PlatformError("cross_tenant_" + label,
                                f"{label} 不属于当前租户", 403)


def upsert_asset(session: Session, *, name: str, address: str, vendor: str = "",
                 model: str = "", firmware: str = "", fingerprint: str = "",
                 credential_id: str | None = None, profile_id: str | None = None,
                 capability_id: str | None = None, licence: str = "", notes: str = "",
                 public_ips=None, actor: str, now: float | None = None,
                 asset_id: str | None = None,
                 tenant_id: str = DEFAULT_TENANT_ID) -> Asset:
    from . import public_ip as public_ip_module
    stamp = time.time() if now is None else now
    if not name or not address:
        raise PlatformError("invalid_asset", "资产名称与地址不能为空")
    _assert_owned_refs(session, tenant_id, credential=credential_id,
                       profile=profile_id, capability=capability_id)
    existing = None
    if asset_id:
        candidate = session.get(Asset, asset_id)
        if candidate is not None and candidate.tenant_id == tenant_id:
            existing = candidate
    if existing is None:
        existing = session.scalar(select(Asset).where(Asset.tenant_id == tenant_id,
                                                      Asset.address == address))
    else:
        clash = session.scalar(select(Asset).where(Asset.tenant_id == tenant_id,
                                                   Asset.address == address,
                                                   Asset.id != existing.id))
        if clash is not None:
            raise PlatformError("asset_address_conflict",
                                "该 IPMI 地址已被本租户其它资产占用", 409)
    public_ip_module.assert_ipmi_available(session, tenant_id, address,
                                           existing.id if existing else None)
    if existing is None:
        enforce_asset_quota(session, tenant_id)
        existing = Asset(id=str(uuid.uuid4()), tenant_id=tenant_id, name=name,
                         address=address, created=stamp, updated=stamp)
        session.add(existing)
        session.flush()
        action = "asset_created"
    else:
        action = "asset_updated"
    existing.name = name
    existing.address = address
    existing.vendor, existing.model, existing.firmware = vendor, model, firmware
    existing.fingerprint = fingerprint
    existing.credential_id = credential_id
    existing.profile_id = profile_id
    existing.capability_id = capability_id
    existing.licence, existing.notes = licence, notes
    existing.updated = stamp
    if public_ips is not None:
        public_ip_module.upsert_public_ip(session, tenant_id=tenant_id,
                                          asset_id=existing.id, raw=public_ips,
                                          actor=actor, now=stamp)
    audit(session, actor, action, asset_id=existing.id, tenant_id=tenant_id,
          detail={"address": address, "vendor": vendor, "model": model,
                  "firmware": firmware, "profile_id": profile_id}, now=stamp)
    session.commit()
    return existing


_ENV_PIN_ADAPTERS = frozenset({"huawei-ibmc-vnc-tls", "huawei-ibmc-kvm-gateway"})


def asset_onboarding(session: Session, *, tenant_id: str = DEFAULT_TENANT_ID,
                     now: float | None = None) -> dict:
    stamp = time.time() if now is None else now
    rows = session.scalars(
        select(VendorProfile)
        .where((VendorProfile.tenant_id.is_(None)) | (VendorProfile.tenant_id == tenant_id))
        .order_by(VendorProfile.priority, VendorProfile.code)
    ).all()
    brands = []
    for row in rows:
        if row.status != "approved":
            continue
        if row.review_due and row.review_due < stamp:
            continue
        caps = session.scalars(
            select(Capability)
            .where((Capability.profile_id == row.id)
                   & (Capability.status == "verified")
                   & (Capability.expires > stamp)
                   & ((Capability.tenant_id.is_(None)) | (Capability.tenant_id == tenant_id)))
            .order_by(Capability.expires.desc())
        ).all()
        cap_views = [{"id": c.id, "model": c.model, "firmware": c.firmware,
                      "adapter": c.adapter, "status": c.status, "expires": c.expires}
                     for c in caps]
        env_pin = row.console_impl in _ENV_PIN_ADAPTERS
        brands.append({
            "profile_id": row.id,
            "code": row.code,
            "vendor": row.vendor,
            "model_pattern": row.model_pattern,
            "firmware_min": row.firmware_min,
            "firmware_max": row.firmware_max,
            "licence": row.licence,
            "console_impl": row.console_impl,
            "certificate_mode": "env_pin" if env_pin else "asset_fingerprint",
            "certificate_note": (
                "该品牌证书指纹由平台统一管理，资产无需填写；连接时按服务端 pin 校验。"
                if env_pin else
                "如该 BMC 使用自签证书，请填写证书 SHA-256 指纹；留空则不校验证书。"),
            "default_capability_id": cap_views[0]["id"] if cap_views else None,
            "capabilities": cap_views,
        })
    return {
        "brands": brands,
        "note": ("只能选择已完成适配并批准的品牌。未适配品牌请先在「品牌档案」页走"
                 "新品牌适配流程；草稿档案不会产生连接方案。"),
    }


def resolve_asset_defaults(session: Session, *, profile_id: str,
                            tenant_id: str = DEFAULT_TENANT_ID,
                            now: float | None = None) -> dict:
    stamp = time.time() if now is None else now
    profile = session.get(VendorProfile, profile_id)
    if profile is None or profile.tenant_id not in (None, tenant_id):
        raise PlatformError("profile_not_found", "品牌档案不存在", 400)
    if profile.status != "approved":
        raise PlatformError("profile_not_approved",
                            f"品牌档案 {profile.code} 尚未批准，请先走新品牌适配", 400)
    if profile.review_due and profile.review_due < stamp:
        raise PlatformError("profile_review_overdue", "品牌档案复核已到期，请带外重新审批", 400)
    capability = session.scalar(
        select(Capability)
        .where((Capability.profile_id == profile.id)
               & (Capability.status == "verified")
               & (Capability.expires > stamp)
               & ((Capability.tenant_id.is_(None)) | (Capability.tenant_id == tenant_id)))
        .order_by(Capability.expires.desc())
    )
    return {
        "vendor": profile.vendor,
        "model_pattern": profile.model_pattern,
        "licence": profile.licence,
        "console_impl": profile.console_impl,
        "capability_id": capability.id if capability else None,
    }


def assign_asset(session: Session, *, address: str, tenant_id: str | None, actor: str,
                 name: str = "", reassign: bool = False,
                 now: float | None = None, plane: Any | None = None) -> dict:
    from . import public_ip as public_ip_module
    stamp = time.time() if now is None else now
    addr = (address or "").strip()
    if not addr:
        raise PlatformError("invalid_asset", "请填写设备 IP 地址")
    resolved = public_ip_module.asset_by_public_ip(session, None, addr)
    if resolved is not None:
        addr = resolved.address
    elif public_ip_module.address_asset_ids(session, None, addr):
        raise PlatformError("asset_ambiguous", "该地址匹配多个设备或归属异常，请先修复地址登记", 409)
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
        public_ip_module.assert_ipmi_available(session, target, addr)
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
    public_ip_module.rehome_mapping(session, asset_id=asset.id, tenant_id=target,
                                    actor=actor, now=stamp)
    action = "unassigned" if target is None else ("moved" if origin_code else "assigned")
    old_grantees = [row[0] for row in session.execute(
        select(AccessGrant.user_id).where(AccessGrant.asset_id == asset.id)).all()]
    if plane is not None:
        plane.delete_grants_for_asset(asset.id, trace="")
        for uid in old_grantees:
            plane.bump_subject_epoch(uid, trace="")
    session.execute(delete(AccessGrant).where(AccessGrant.asset_id == asset.id))
    session.execute(delete(GrantSource).where(GrantSource.asset_id == asset.id))
    if old_grantees:
        audit(session, actor, "asset_grants_cleared", asset_id=asset.id, tenant_id=target,
              detail={"from": origin_code, "users": old_grantees}, now=stamp)
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


def _assert_grantor_authorized(session: Session, *, actor_user_id: str | None,
                               asset_id: str, tenant_id: str, stamp: float) -> None:
    if not actor_user_id:
        return
    grantor = session.get(User, actor_user_id)
    if grantor is None:
        raise PlatformError("grantor_not_found", "授权人账号不存在", 404)
    if grantor.tenant_id is None:
        return
    held = session.scalar(select(func.count()).select_from(AccessGrant).where(
        AccessGrant.user_id == actor_user_id, AccessGrant.asset_id == asset_id,
        AccessGrant.tenant_id == tenant_id, AccessGrant.expires > stamp))
    if not held:
        raise PlatformError("grantor_not_authorized", "授权人尚未获得该资产的一级授权", 403)


def grant_asset(session: Session, *, user_id: str, asset_id: str, actor: str,
                ttl_seconds: int = 86400 * 30, now: float | None = None,
                tenant_id: str = DEFAULT_TENANT_ID,
                actor_user_id: str | None = None, plane: Any | None = None) -> None:
    stamp = time.time() if now is None else now
    user = session.get(User, user_id)
    asset = session.get(Asset, asset_id)
    if user is None or user.tenant_id != tenant_id:
        raise PlatformError("grant_target_missing", "用户或资产不存在", 404)
    if asset is None or asset.tenant_id != tenant_id:
        raise PlatformError("grant_target_missing", "用户或资产不存在", 404)
    _assert_grantor_authorized(session, actor_user_id=actor_user_id, asset_id=asset_id,
                               tenant_id=tenant_id, stamp=stamp)
    if plane is not None:
        plane.write_grant(user_id, asset_id, stamp + ttl_seconds, trace="")
    grantor = session.get(User, actor_user_id) if actor_user_id else None
    level = 1 if grantor is None or grantor.tenant_id is None else 2
    session.merge(AccessGrant(tenant_id=tenant_id, user_id=user_id, asset_id=asset_id,
                              expires=stamp + ttl_seconds, granted_by=actor, created=stamp))
    hand = session.scalar(select(func.count()).select_from(GrantSource).where(
        GrantSource.user_id == user_id, GrantSource.asset_id == asset_id,
        GrantSource.group_id.is_(None)))
    if not hand:
        session.add(GrantSource(id=str(uuid.uuid4()), user_id=user_id, asset_id=asset_id,
                                group_id=None))
    audit(session, actor, "grant_created", asset_id=asset_id, tenant_id=tenant_id,
          detail={"user_id": user_id, "expires": stamp + ttl_seconds, "level": level},
          now=stamp)
    session.commit()


def revoke_grant(session: Session, *, user_id: str, asset_id: str, actor: str,
                 tenant_id: str = DEFAULT_TENANT_ID,
                 plane: Any | None = None) -> None:
    if plane is not None:
        plane.delete_grant(user_id, asset_id, trace="")
        plane.bump_subject_epoch(user_id, trace="")
    session.execute(delete(AccessGrant).where(AccessGrant.user_id == user_id,
                                              AccessGrant.asset_id == asset_id,
                                              AccessGrant.tenant_id == tenant_id))
    session.execute(delete(GrantSource).where(GrantSource.user_id == user_id,
                                              GrantSource.asset_id == asset_id))
    audit(session, actor, "grant_revoked", asset_id=asset_id, tenant_id=tenant_id,
          detail={"user_id": user_id})
    session.commit()



MAX_GROUP_EXPANSION = 500


def _group_in_tenant(session: Session, group_id: str, tenant_id: str) -> AssetGroup:
    group = session.get(AssetGroup, group_id)
    if group is None or group.tenant_id != tenant_id:
        raise PlatformError("group_not_found", "资产组不存在", 404)
    return group


def create_asset_group(session: Session, *, name: str, actor: str,
                       tenant_id: str, now: float | None = None) -> AssetGroup:
    label = (name or "").strip()
    if not label:
        raise PlatformError("invalid_group_name", "资产组名称不能为空")
    stamp = time.time() if now is None else now
    group = AssetGroup(id=str(uuid.uuid4()), tenant_id=tenant_id, name=label,
                       created=stamp, updated=stamp)
    session.add(group)
    audit(session, actor, "asset_group_created", tenant_id=tenant_id,
          detail={"group_id": group.id, "name": label}, now=stamp)
    session.commit()
    return group


def list_asset_groups(session: Session, tenant_id: str) -> list[dict]:
    rows = session.execute(
        select(AssetGroup, func.count(AssetGroupMember.asset_id))
        .outerjoin(AssetGroupMember, AssetGroupMember.group_id == AssetGroup.id)
        .where(AssetGroup.tenant_id == tenant_id)
        .group_by(AssetGroup.id).order_by(AssetGroup.name)).all()
    return [{**group.public(), "member_count": count} for group, count in rows]


def set_group_members(session: Session, *, group_id: str, asset_ids: list[str],
                      actor: str, tenant_id: str,
                      now: float | None = None) -> dict:
    stamp = time.time() if now is None else now
    group = _group_in_tenant(session, group_id, tenant_id)
    wanted = list(dict.fromkeys(asset_ids))
    if wanted:
        owned = set(session.scalars(select(Asset.id).where(
            Asset.id.in_(wanted), Asset.tenant_id == tenant_id)).all())
        if len(owned) != len(wanted):
            raise PlatformError("group_asset_foreign", "资产组只能包含本租户资产", 403)
    existing = set(session.scalars(select(AssetGroupMember.asset_id).where(
        AssetGroupMember.group_id == group_id)).all())
    target = set(wanted)
    for aid in existing - target:
        session.execute(delete(AssetGroupMember).where(
            AssetGroupMember.group_id == group_id, AssetGroupMember.asset_id == aid))
    for aid in target - existing:
        session.add(AssetGroupMember(group_id=group_id, asset_id=aid))
    group.updated = stamp
    audit(session, actor, "asset_group_members_changed", tenant_id=tenant_id,
          detail={"group_id": group_id, "added": sorted(target - existing),
                  "removed": sorted(existing - target)}, now=stamp)
    session.commit()
    return {"group": group.public(), "members": sorted(target)}


def delete_asset_group(session: Session, *, group_id: str, actor: str,
                       tenant_id: str) -> None:
    group = _group_in_tenant(session, group_id, tenant_id)
    session.execute(update(GrantSource).where(GrantSource.group_id == group_id)
                    .values(group_id=None))
    session.execute(delete(AssetGroupMember).where(AssetGroupMember.group_id == group_id))
    session.delete(group)
    audit(session, actor, "asset_group_deleted", tenant_id=tenant_id,
          detail={"group_id": group_id, "name": group.name})
    session.commit()


def grant_group(session: Session, *, group_id: str, user_id: str, actor: str,
                tenant_id: str, plane: Any | None = None,
                ttl_seconds: int = 86400 * 30,
                now: float | None = None) -> dict:
    stamp = time.time() if now is None else now
    group = _group_in_tenant(session, group_id, tenant_id)
    user = session.get(User, user_id)
    if user is None or user.tenant_id != tenant_id:
        raise PlatformError("grant_target_missing", "用户不存在", 404)
    member_ids = list(session.scalars(select(AssetGroupMember.asset_id).where(
        AssetGroupMember.group_id == group_id)).all())
    if len(member_ids) > MAX_GROUP_EXPANSION:
        raise PlatformError("group_expansion_too_large",
                            f"单次展开不能超过 {MAX_GROUP_EXPANSION} 台资产", 413)

    stale = [row[0] for row in session.execute(
        select(GrantSource.asset_id).where(GrantSource.user_id == user_id,
                                           GrantSource.group_id == group_id)).all()
        if row[0] not in set(member_ids)]
    for aid in stale:
        session.execute(delete(GrantSource).where(
            GrantSource.user_id == user_id, GrantSource.asset_id == aid,
            GrantSource.group_id == group_id))
        other_sources = session.scalar(select(func.count()).select_from(GrantSource).where(
            GrantSource.user_id == user_id, GrantSource.asset_id == aid))
        if not other_sources:
            if plane is not None:
                plane.delete_grant(user_id, aid, trace="")
            session.execute(delete(AccessGrant).where(
                AccessGrant.user_id == user_id, AccessGrant.asset_id == aid,
                AccessGrant.tenant_id == tenant_id))
            audit(session, actor, "group_grant_revoked", asset_id=aid, tenant_id=tenant_id,
                  detail={"user_id": user_id, "group_id": group_id}, now=stamp)

    granted = 0
    for aid in member_ids:
        expires = stamp + ttl_seconds
        if plane is not None:
            plane.write_grant(user_id, aid, expires, trace="")
        session.merge(AccessGrant(tenant_id=tenant_id, user_id=user_id, asset_id=aid,
                                  expires=expires, granted_by=actor, created=stamp))
        exists = session.scalar(select(func.count()).select_from(GrantSource).where(
            GrantSource.user_id == user_id, GrantSource.asset_id == aid,
            GrantSource.group_id == group_id))
        if not exists:
            session.add(GrantSource(id=str(uuid.uuid4()), user_id=user_id, asset_id=aid,
                                    group_id=group_id))
        audit(session, actor, "group_grant_expanded", asset_id=aid, tenant_id=tenant_id,
              detail={"user_id": user_id, "group_id": group_id, "expires": expires}, now=stamp)
        granted += 1
    session.commit()
    return {"group_id": group_id, "user_id": user_id, "granted": granted,
            "revoked_stale": len(stale)}


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
                  plan: str | None = None, mode: str | None = None,
                  quotas: dict | None = None,
                  actor: str, now: float | None = None) -> Tenant:
    row = session.get(Tenant, tenant_id)
    if row is None:
        raise PlatformError("tenant_not_found", "租户不存在", 404)
    before = {"name": row.name, "plan": row.plan, "mode": row.mode,
              "quotas": parse_json(row.quotas_json, {})}
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
    if mode is not None:
        if mode not in TENANT_MODES:
            raise PlatformError("invalid_tenant_mode",
                                f"租户模式只能是 {', '.join(TENANT_MODES)}", 400)
        row.mode = mode
    if quotas is not None:
        row.quotas_json = json_field(normalise_quotas(quotas))
    after = {"name": row.name, "plan": row.plan, "mode": row.mode,
             "quotas": parse_json(row.quotas_json, {})}
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
                  mode: str = TENANT_MODE_MANAGER, quotas: dict | None = None,
                  actor: str, now: float | None = None) -> Tenant:
    code = (code or "").strip()
    if not code or not code.replace("-", "").replace("_", "").isalnum():
        raise PlatformError("invalid_tenant_code", "租户码只能包含字母、数字、下划线与短横线", 400)
    if session.scalar(select(Tenant.id).where(Tenant.code == code)) is not None:
        raise PlatformError("tenant_exists", "租户码已存在", 409)
    if mode not in TENANT_MODES:
        raise PlatformError("invalid_tenant_mode",
                            f"租户模式只能是 {', '.join(TENANT_MODES)}", 400)
    stamp = time.time() if now is None else now
    row = Tenant(id=str(uuid.uuid4()), code=code, name=name or code, status="active",
                 plan=plan or "standard", mode=mode,
                 quotas_json=json_field(quotas or {}), created=stamp)
    session.add(row)
    audit(session, actor, "tenant_created", tenant_id=None, actor_type="platform",
          detail={"tenant_id": row.id, "code": code, "plan": row.plan,
                  "mode": mode}, now=stamp)
    session.commit()
    return row


def set_tenant_status(session: Session, tenant_id: str, status: str, *, actor: str,
                      now: float | None = None, plane: Any | None = None) -> Tenant:
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
    if plane is not None and status == "suspended":
        for uid in session.scalars(select(User.id).where(User.tenant_id == tenant_id)).all():
            plane.revoke_subject(uid, trace="")
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
        dsn = parse_store_dsn(plane_db)
        db = open_store(dsn, readonly=True)
    except Exception as exc:
        logger.error("data plane store unavailable for usage rebuild: %s", exc)
        raise PlatformError("data_plane_unavailable", "数据面库不可读", 503) from exc
    try:
        if dsn.dialect == "sqlite":
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
