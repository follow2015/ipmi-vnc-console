"""Control-plane use cases: accounts, RBAC, assets, credentials, grants, audit."""
from __future__ import annotations

import json
import time
import uuid
from typing import Any

from sqlalchemy import and_, delete, select, update
from sqlalchemy.orm import Session

from .models import (AccessGrant, Asset, AuditLog, Capability, Credential, Permission,
                     Role, RolePermission, ROLE_ADMIN, User, UserRole, VendorProfile,
                     json_field)
from .security import (CredentialCipher, hash_password, verify_password)

MAX_FAILED_ATTEMPTS = 5
LOCK_SECONDS = 900


class PlatformError(Exception):
    def __init__(self, code: str, message: str, status: int = 400):
        super().__init__(f"{code}: {message}")
        self.code, self.message, self.status = code, message, status


def audit(session: Session, actor: str, action: str, *, asset_id: str | None = None,
          detail: dict | None = None, trace: str = "", now: float | None = None) -> None:
    session.add(AuditLog(ts=time.time() if now is None else now, trace_id=trace,
                         actor=actor, action=action, asset_id=asset_id,
                         detail=json_field(detail or {})))


def authenticate(session: Session, username: str, password: str,
                 *, now: float | None = None) -> User:
    stamp = time.time() if now is None else now
    user = session.scalar(select(User).where(User.username == username))
    if user is None or not bool(user.is_active):
        raise PlatformError("authentication_failed", "用户名或口令不正确", 401)
    if float(user.locked_until or 0) > stamp:
        raise PlatformError("account_locked", "账号暂时锁定，请稍后再试", 423)
    if not verify_password(password, user.password_hash):
        user.failed_attempts = int(user.failed_attempts or 0) + 1
        if user.failed_attempts >= MAX_FAILED_ATTEMPTS:
            user.failed_attempts = 0
            user.locked_until = stamp + LOCK_SECONDS
        audit(session, username, "login_failed", detail={"attempts": user.failed_attempts}, now=stamp)
        session.commit()
        raise PlatformError("authentication_failed", "用户名或口令不正确", 401)
    user.failed_attempts = 0
    user.locked_until = 0.0
    user.last_login = stamp
    audit(session, username, "login_succeeded", now=stamp)
    session.commit()
    return user


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
                *, actor: str, display_name: str = "", now: float | None = None) -> User:
    if not username or not username.strip():
        raise PlatformError("invalid_username", "用户名不能为空")
    if session.scalar(select(User.id).where(User.username == username)) is not None:
        raise PlatformError("user_exists", "用户名已存在", 409)
    role_row = session.scalar(select(Role).where(Role.code == role))
    if role_row is None:
        raise PlatformError("unknown_role", f"未知角色：{role}")
    user = User(id=str(uuid.uuid4()), username=username.strip(), display_name=display_name,
                password_hash=hash_password(password), is_active=True,
                created=time.time() if now is None else now)
    session.add(user)
    session.flush()
    session.add(UserRole(user_id=user.id, role_id=role_row.id))
    audit(session, actor, "user_created", detail={"username": user.username, "role": role}, now=now)
    session.commit()
    return user


def list_users(session: Session) -> list[dict]:
    out = []
    for user in session.scalars(select(User).order_by(User.created)).all():
        item = user.public()
        item["roles"] = [r[0] for r in session.execute(
            select(Role.code).join(UserRole, UserRole.role_id == Role.id)
            .where(UserRole.user_id == user.id)).all()]
        out.append(item)
    return out


def set_user_active(session: Session, user_id: str, active: bool, *, actor: str) -> None:
    user = session.get(User, user_id)
    if user is None:
        raise PlatformError("user_not_found", "用户不存在", 404)
    session.execute(update(User).where(User.id == user_id).values(is_active=active))
    audit(session, actor, "user_activation_changed", detail={"user_id": user_id, "active": active})
    session.commit()


def save_credential(session: Session, cipher: CredentialCipher, *, label: str,
                    username: str, password: str, actor: str,
                    now: float | None = None) -> Credential:
    if not cipher.available:
        raise PlatformError("credential_key_missing", "凭据主密钥未配置，无法写入 BMC 账号", 503)
    if not label or not username or not password:
        raise PlatformError("invalid_credential", "标签、账号与口令均不能为空")
    cred = Credential(id=str(uuid.uuid4()), label=label,
                      username_cipher=b"", password_cipher=b"",
                      created_by=actor, created=time.time() if now is None else now)
    cred.username_cipher = cipher.encrypt(username, aad=cred.id + ":username")
    cred.password_cipher = cipher.encrypt(password, aad=cred.id + ":password")
    session.add(cred)
    audit(session, actor, "credential_created", detail={"credential_id": cred.id, "label": label}, now=now)
    session.commit()
    return cred


def read_credential(session: Session, cipher: CredentialCipher, credential_id: str) -> dict:
    cred = session.get(Credential, credential_id)
    if cred is None:
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
                 actor: str, now: float | None = None) -> Asset:
    stamp = time.time() if now is None else now
    if not name or not address:
        raise PlatformError("invalid_asset", "资产名称与地址不能为空")
    existing = session.scalar(select(Asset).where(Asset.address == address))
    if existing is None:
        existing = Asset(id=str(uuid.uuid4()), name=name, address=address,
                         created=stamp, updated=stamp)
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
    audit(session, actor, action, asset_id=existing.id,
          detail={"address": address, "vendor": vendor, "model": model,
                  "firmware": firmware, "profile_id": profile_id}, now=stamp)
    session.commit()
    return existing


def assets_for_user(session: Session, user_id: str, *, now: float | None = None) -> list[dict]:
    stamp = time.time() if now is None else now
    rows = session.execute(
        select(Asset, AccessGrant.expires)
        .join(AccessGrant, AccessGrant.asset_id == Asset.id)
        .where(AccessGrant.user_id == user_id, AccessGrant.expires > stamp)
        .order_by(Asset.name)).all()
    return [{**asset.public(), "grant_expires": expires} for asset, expires in rows]


def all_assets(session: Session, user_id: str, *, now: float | None = None) -> list[dict]:
    stamp = time.time() if now is None else now
    rows = session.execute(
        select(Asset, AccessGrant.expires)
        .outerjoin(AccessGrant, and_(AccessGrant.asset_id == Asset.id,
                                     AccessGrant.user_id == user_id,
                                     AccessGrant.expires > stamp))
        .order_by(Asset.name)).all()
    return [{**asset.public(), "grant_expires": expires} for asset, expires in rows]


def grant_asset(session: Session, *, user_id: str, asset_id: str, actor: str,
                ttl_seconds: int = 86400 * 30, now: float | None = None) -> None:
    stamp = time.time() if now is None else now
    if session.get(User, user_id) is None or session.get(Asset, asset_id) is None:
        raise PlatformError("grant_target_missing", "用户或资产不存在", 404)
    session.merge(AccessGrant(user_id=user_id, asset_id=asset_id,
                              expires=stamp + ttl_seconds, granted_by=actor, created=stamp))
    audit(session, actor, "grant_created", asset_id=asset_id,
          detail={"user_id": user_id, "expires": stamp + ttl_seconds}, now=stamp)
    session.commit()


def revoke_grant(session: Session, *, user_id: str, asset_id: str, actor: str) -> None:
    session.execute(delete(AccessGrant).where(AccessGrant.user_id == user_id,
                                              AccessGrant.asset_id == asset_id))
    audit(session, actor, "grant_revoked", asset_id=asset_id, detail={"user_id": user_id})
    session.commit()


def capability_draft(session: Session, profile: VendorProfile, *, detection: dict,
                     actor: str, now: float | None = None) -> Capability:
    stamp = time.time() if now is None else now
    row = Capability(id=str(uuid.uuid4()), vendor=profile.vendor,
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
    audit(session, actor, "capability_draft_created",
          detail={"profile_id": profile.id, "capability_id": row.id,
                  "detection": {k: detection.get(k) for k in ("vendor", "model", "firmware")}}, now=stamp)
    session.commit()
    return row


def recent_audit(session: Session, limit: int = 100) -> list[dict]:
    rows = session.scalars(select(AuditLog).order_by(AuditLog.id.desc()).limit(min(limit, 500))).all()
    return [{"id": r.id, "ts": r.ts, "trace_id": r.trace_id, "actor": r.actor,
             "action": r.action, "asset_id": r.asset_id,
             "detail": json.loads(r.detail) if r.detail else {}} for r in rows]
