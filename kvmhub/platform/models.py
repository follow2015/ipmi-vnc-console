"""SQLAlchemy 2.0 models for the production control plane."""
from __future__ import annotations

import json
from typing import Any

from sqlalchemy import Boolean, Float, ForeignKey, Index, Integer, LargeBinary, String, Text, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

PROFILE_DRAFT = "draft"
PROFILE_APPROVED = "approved"
PROFILE_SUSPENDED = "suspended"
PROFILE_RETIRED = "retired"

CAPABILITY_DRAFT = "draft"
CAPABILITY_VERIFIED = "verified"
CAPABILITY_STATUSES = (CAPABILITY_DRAFT, CAPABILITY_VERIFIED, "suspended", "retired")
PROFILE_STATUSES = (PROFILE_DRAFT, PROFILE_APPROVED, PROFILE_SUSPENDED, PROFILE_RETIRED)

ROLE_ADMIN = "admin"
ROLE_OPERATOR = "operator"
ROLE_VIEWER = "viewer"
ROLE_PLATFORM_ADMIN = "platform_admin"

DEFAULT_TENANT_ID = "00000000-0000-0000-0000-000000000001"
DEFAULT_TENANT_CODE = "default"
TENANT_ACTIVE = "active"
TENANT_SUSPENDED = "suspended"

TENANT_MODE_CONSUMER = "consumer"
TENANT_MODE_MANAGER = "manager"
TENANT_MODES = (TENANT_MODE_CONSUMER, TENANT_MODE_MANAGER)

PERMISSIONS = (
    "asset.read", "asset.write", "console.open", "console.close",
    "credential.write", "vendor.read", "vendor.approve",
    "user.read", "user.write", "grant.write", "audit.read",
    "session.read", "session.revoke",
)
ROLE_PERMISSIONS = {
    ROLE_ADMIN: PERMISSIONS,
    ROLE_OPERATOR: ("asset.read", "asset.write", "console.open", "console.close",
                    "credential.write", "vendor.read", "audit.read", "session.read"),
    ROLE_VIEWER: ("asset.read", "vendor.read", "audit.read"),
}

PLATFORM_PERMISSIONS = (
    "platform.tenant.read", "platform.tenant.write",
    "platform.user.read", "platform.user.write",
    "platform.session.read", "platform.session.revoke",
    "platform.audit.read", "platform.asset.read", "platform.asset.write",
    "platform.worker.read", "platform.worker.manage",
    "platform.vendor.read",
)
ROLE_PERMISSIONS[ROLE_PLATFORM_ADMIN] = PLATFORM_PERMISSIONS

TENANT_MODE_PERMISSIONS: dict[str, tuple[str, ...]] = {
    TENANT_MODE_CONSUMER: (
        "asset.read", "console.open", "console.close",
        "user.read", "user.write", "grant.write", "audit.read",
    ),
    TENANT_MODE_MANAGER: PERMISSIONS,
}


class Base(DeclarativeBase):
    pass


def json_field(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def parse_json(raw: str | None, default: Any) -> Any:
    if not raw:
        return default
    try:
        return json.loads(raw)
    except (ValueError, TypeError):
        return default


class Role(Base):
    __tablename__ = "kvm_role"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    code: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    created: Mapped[float] = mapped_column(Float, nullable=False)


class Permission(Base):
    __tablename__ = "kvm_permission"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    code: Mapped[str] = mapped_column(String(96), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(128), nullable=False)


class RolePermission(Base):
    __tablename__ = "kvm_role_permission"
    role_id: Mapped[str] = mapped_column(String(36), ForeignKey("kvm_role.id"), primary_key=True)
    permission_id: Mapped[str] = mapped_column(String(36), ForeignKey("kvm_permission.id"), primary_key=True)


class UserRole(Base):
    __tablename__ = "kvm_user_role"
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("kvm_user.id"), primary_key=True)
    role_id: Mapped[str] = mapped_column(String(36), ForeignKey("kvm_role.id"), primary_key=True)


class Tenant(Base):
    __tablename__ = "kvm_tenant"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    code: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(128), default="")
    status: Mapped[str] = mapped_column(String(32), default=TENANT_ACTIVE)
    plan: Mapped[str] = mapped_column(String(64), default="standard")
    mode: Mapped[str] = mapped_column(String(32), default=TENANT_MODE_MANAGER,
                                      nullable=False, server_default=TENANT_MODE_MANAGER)
    quotas_json: Mapped[str] = mapped_column(Text, default="{}")
    created: Mapped[float] = mapped_column(Float, nullable=False)

    def public(self) -> dict:
        return {"id": self.id, "code": self.code, "name": self.name,
                "status": self.status, "plan": self.plan, "mode": self.mode,
                "quotas": parse_json(self.quotas_json, {}), "created": self.created}


class User(Base):
    __tablename__ = "kvm_user"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    username: Mapped[str] = mapped_column(String(128), nullable=False)
    display_name: Mapped[str] = mapped_column(String(128), default="")
    password_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    failed_attempts: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[float] = mapped_column(Float, default=0.0)
    created: Mapped[float] = mapped_column(Float, nullable=False)
    last_login: Mapped[float | None] = mapped_column(Float, nullable=True)
    __table_args__ = (UniqueConstraint("tenant_id", "username", name="uq_kvm_user_tenant_username"),)

    def public(self) -> dict:
        return {"id": self.id, "tenant_id": self.tenant_id, "username": self.username,
                "display_name": self.display_name, "is_active": bool(self.is_active),
                "created": self.created, "last_login": self.last_login}


class VendorProfile(Base):
    __tablename__ = "kvm_vendor_profile"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    code: Mapped[str] = mapped_column(String(96), unique=True, nullable=False)
    vendor: Mapped[str] = mapped_column(String(128), nullable=False)
    vendor_aliases: Mapped[str] = mapped_column(Text, default="[]")
    model_pattern: Mapped[str] = mapped_column(String(256), default="")
    firmware_min: Mapped[str] = mapped_column(String(64), default="")
    firmware_max: Mapped[str] = mapped_column(String(64), default="")
    rfb_version: Mapped[str] = mapped_column(String(64), default="")
    message_profile: Mapped[str] = mapped_column(String(64), default="standard")
    asset_paths: Mapped[str] = mapped_column(Text, default="[]")
    login_path: Mapped[str] = mapped_column(String(128), default="")
    logout_path: Mapped[str] = mapped_column(String(128), default="")
    console_impl: Mapped[str] = mapped_column(String(128), default="")
    protocol: Mapped[str] = mapped_column(String(96), default="", nullable=False)
    licence: Mapped[str] = mapped_column(String(128), default="")
    concurrency_limit: Mapped[int] = mapped_column(Integer, default=1)
    input_shaping: Mapped[str] = mapped_column(Text, default="{}")
    priority: Mapped[int] = mapped_column(Integer, default=100)
    status: Mapped[str] = mapped_column(String(32), default=PROFILE_DRAFT)
    evidence: Mapped[str] = mapped_column(Text, default="")
    approver: Mapped[str] = mapped_column(String(128), default="")
    approved_at: Mapped[float] = mapped_column(Float, default=0.0)
    review_due: Mapped[float] = mapped_column(Float, default=0.0)
    revision: Mapped[int] = mapped_column(Integer, default=0)
    created: Mapped[float] = mapped_column(Float, nullable=False)

    def public(self) -> dict:
        return {"id": self.id, "tenant_id": self.tenant_id, "code": self.code,
                "vendor": self.vendor,
                "vendor_aliases": parse_json(self.vendor_aliases, []),
                "model_pattern": self.model_pattern, "firmware_min": self.firmware_min,
                "firmware_max": self.firmware_max, "rfb_version": self.rfb_version,
                "message_profile": self.message_profile,
                "asset_paths": parse_json(self.asset_paths, []),
                "login_path": self.login_path, "logout_path": self.logout_path,
                "console_impl": self.console_impl, "licence": self.licence,
                "protocol": getattr(self, "protocol", "") or "",
                "concurrency_limit": self.concurrency_limit,
                "input_shaping": parse_json(self.input_shaping, {}),
                "priority": self.priority, "status": self.status,
                "evidence": self.evidence, "approver": self.approver,
                "approved_at": self.approved_at, "review_due": self.review_due,
                "revision": self.revision}


class Capability(Base):
    __tablename__ = "kvm_capability"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    vendor: Mapped[str] = mapped_column(String(128), nullable=False)
    model: Mapped[str] = mapped_column(String(128), nullable=False)
    firmware: Mapped[str] = mapped_column(String(64), nullable=False)
    adapter: Mapped[str] = mapped_column(String(128), nullable=False)
    profile_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("kvm_vendor_profile.id"), nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="draft")
    expires: Mapped[float] = mapped_column(Float, default=0.0)
    evidence: Mapped[str] = mapped_column(Text, default="")
    approver: Mapped[str] = mapped_column(String(128), default="")
    console_impl: Mapped[str] = mapped_column(String(128), default="")
    licence: Mapped[str] = mapped_column(String(128), default="")
    models: Mapped[str] = mapped_column(Text, default="[]")
    firmware_min: Mapped[str] = mapped_column(String(64), default="")
    firmware_max: Mapped[str] = mapped_column(String(64), default="")
    protocol_versions: Mapped[str] = mapped_column(Text, default="[]")
    approved_at: Mapped[float] = mapped_column(Float, default=0.0)
    effective_from: Mapped[float] = mapped_column(Float, default=0.0)
    review_due: Mapped[float] = mapped_column(Float, default=0.0)
    status_reason: Mapped[str] = mapped_column(Text, default="")
    revision: Mapped[int] = mapped_column(Integer, default=0)
    created: Mapped[float] = mapped_column(Float, nullable=False)


class Credential(Base):
    __tablename__ = "kvm_credential"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    label: Mapped[str] = mapped_column(String(128), nullable=False)
    username_cipher: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    password_cipher: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    key_version: Mapped[int] = mapped_column(Integer, default=1)
    created_by: Mapped[str] = mapped_column(String(128), default="")
    created: Mapped[float] = mapped_column(Float, nullable=False)
    rotated_at: Mapped[float | None] = mapped_column(Float, nullable=True)

    def public(self) -> dict:
        return {"id": self.id, "label": self.label, "key_version": self.key_version,
                "created": self.created, "rotated_at": self.rotated_at}


class Asset(Base):
    __tablename__ = "kvm_asset"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    address: Mapped[str] = mapped_column(String(256), nullable=False)
    vendor: Mapped[str] = mapped_column(String(128), default="")
    model: Mapped[str] = mapped_column(String(128), default="")
    firmware: Mapped[str] = mapped_column(String(64), default="")
    fingerprint: Mapped[str] = mapped_column(String(128), default="")
    credential_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("kvm_credential.id"), nullable=True)
    profile_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("kvm_vendor_profile.id"), nullable=True)
    capability_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("kvm_capability.id"), nullable=True)
    licence: Mapped[str] = mapped_column(String(128), default="")
    status: Mapped[str] = mapped_column(String(32), default="discovered")
    notes: Mapped[str] = mapped_column(Text, default="")
    created: Mapped[float] = mapped_column(Float, nullable=False)
    updated: Mapped[float] = mapped_column(Float, nullable=False)
    __table_args__ = (Index("ix_kvm_asset_tenant_address", "tenant_id", "address"),)

    def public(self) -> dict:
        return {"id": self.id, "tenant_id": self.tenant_id, "name": self.name,
                "address": self.address,
                "vendor": self.vendor, "model": self.model, "firmware": self.firmware,
                "fingerprint_prefix": self.fingerprint[:12],
                "profile_id": self.profile_id, "capability_id": self.capability_id,
                "licence": self.licence, "status": self.status, "notes": self.notes,
                "created": self.created, "updated": self.updated}


class AccessGrant(Base):
    __tablename__ = "kvm_access_grant"
    tenant_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("kvm_user.id"), primary_key=True)
    asset_id: Mapped[str] = mapped_column(String(36), ForeignKey("kvm_asset.id"), primary_key=True)
    expires: Mapped[float] = mapped_column(Float, nullable=False)
    granted_by: Mapped[str] = mapped_column(String(128), default="")
    created: Mapped[float] = mapped_column(Float, nullable=False)


class AssetGroup(Base):
    __tablename__ = "kvm_asset_group"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    created: Mapped[float] = mapped_column(Float, nullable=False)
    updated: Mapped[float] = mapped_column(Float, nullable=False)

    def public(self) -> dict:
        return {"id": self.id, "tenant_id": self.tenant_id, "name": self.name,
                "created": self.created, "updated": self.updated}


class AssetGroupMember(Base):
    __tablename__ = "kvm_asset_group_member"
    group_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("kvm_asset_group.id", ondelete="CASCADE"), primary_key=True)
    asset_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("kvm_asset.id", ondelete="CASCADE"), primary_key=True)


class GrantSource(Base):
    __tablename__ = "kvm_grant_source"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    user_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    asset_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    group_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("kvm_asset_group.id", ondelete="SET NULL"), nullable=True)
    __table_args__ = (UniqueConstraint("user_id", "asset_id", "group_id",
                                       name="uq_grant_source"),)


class AuditLog(Base):
    __tablename__ = "kvm_audit_log"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ts: Mapped[float] = mapped_column(Float, nullable=False)
    tenant_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    trace_id: Mapped[str] = mapped_column(String(64), default="")
    actor: Mapped[str] = mapped_column(String(128), nullable=False)
    actor_type: Mapped[str] = mapped_column(String(16), default="user")
    actor_tenant: Mapped[str | None] = mapped_column(String(36), nullable=True)
    action: Mapped[str] = mapped_column(String(96), nullable=False)
    asset_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    detail: Mapped[str] = mapped_column(Text, default="{}")
    __table_args__ = (Index("ix_kvm_audit_ts", "ts"),
                      Index("ix_kvm_audit_tenant_ts", "tenant_id", "ts"),
                      UniqueConstraint("id", name="uq_kvm_audit_id"))


class QuotaUsage(Base):
    __tablename__ = "kvm_quota_usage"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(36), ForeignKey("kvm_tenant.id"),
                                           nullable=False, index=True)
    period: Mapped[str] = mapped_column(String(7), nullable=False)
    assets: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    sessions: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    minutes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    updated: Mapped[float] = mapped_column(Float(precision=53), nullable=False)
    __table_args__ = (UniqueConstraint("tenant_id", "period", name="uq_kvm_quota_usage"),)


class ServiceToken(Base):
    __tablename__ = "kvm_service_token"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), ForeignKey("kvm_tenant.id"),
                                           nullable=False, index=True)
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("kvm_user.id"), nullable=False)
    label: Mapped[str] = mapped_column(String(128), nullable=False)
    prefix: Mapped[str] = mapped_column(String(16), nullable=False)
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    allowlist_json: Mapped[str] = mapped_column(Text, default="[]")
    expires: Mapped[float | None] = mapped_column(Float, nullable=True)
    created: Mapped[float] = mapped_column(Float, nullable=False)
    revoked: Mapped[float | None] = mapped_column(Float, nullable=True)
    last_used: Mapped[float | None] = mapped_column(Float, nullable=True)
    created_by: Mapped[str] = mapped_column(String(128), default="")
    __table_args__ = (UniqueConstraint("tenant_id", "label", name="uq_kvm_service_token_label"),)

    def public(self) -> dict:
        return {"id": self.id, "tenant_id": self.tenant_id, "user_id": self.user_id,
                "label": self.label, "prefix": self.prefix,
                "allowlist": parse_json(self.allowlist_json, []),
                "expires": self.expires, "created": self.created,
                "revoked": self.revoked, "last_used": self.last_used,
                "created_by": self.created_by}
