"""Approved brand profile -> data-plane assembly."""
from __future__ import annotations

import hashlib
import time

from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import capability as poc_capability
from ..common import (ATEN_JAVA_ADAPTER_ID, HUAWEI_IBMC_KVM_GATEWAY_ID, HUAWEI_IBMC_VNC_ADAPTER_ID,
                      IDRAC8_ADAPTER_ID, IDRAC_VNC_ADAPTER_ID, PASSTHROUGH_ADAPTER_ID)
from . import public_ip, services, vendor_registry
from .models import (CAPABILITY_VERIFIED, DEFAULT_TENANT_ID, PROFILE_APPROVED,
                     TENANT_ACTIVE, Asset, Capability, Tenant, VendorProfile,
                     parse_json)


class ConnectionRefused(ValueError):

    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


def _stable_id(profile: VendorProfile, vendor: str, model: str, firmware: str) -> str:
    raw = "|".join((profile.code, vendor, model, firmware)).encode("utf-8")
    return "auto-" + hashlib.sha256(raw).hexdigest()[:16]


def capability_entry(profile: VendorProfile, *, detection: dict | None = None,
                     asset: Asset | None = None) -> dict:
    if profile.status != PROFILE_APPROVED:
        raise ConnectionRefused("profile_not_approved",
                                f"品牌档案 {profile.code} 未审批，不能生成连接配置")
    impl = str(profile.console_impl or "passthrough").strip()
    if impl not in ("passthrough", IDRAC8_ADAPTER_ID, IDRAC_VNC_ADAPTER_ID,
                    HUAWEI_IBMC_VNC_ADAPTER_ID, HUAWEI_IBMC_KVM_GATEWAY_ID, ATEN_JAVA_ADAPTER_ID):
        raise ConnectionRefused("adapter_unavailable",
                                f"档案声明的适配器 {profile.console_impl} 尚未接入数据面")

    found = detection or {}
    raw = found.get("raw") or {}
    vendor = str(raw.get("Manufacturer") or (asset.vendor if asset else "") or profile.vendor).strip()
    model = str(found.get("model") or (asset.model if asset else "") or "").strip()
    firmware = str(found.get("firmware") or (asset.firmware if asset else "") or "").strip()
    if not vendor or not model:
        raise ConnectionRefused("detection_incomplete",
                                "缺少厂商或型号，无法生成能力声明；请重新上传 Redfish 探测结果")

    rfb_version = str(profile.rfb_version or "").strip()
    versions = [rfb_version] if rfb_version else []
    if poc_capability.parse_protocol_versions(versions) is None:
        raise ConnectionRefused("protocol_version_invalid",
                                f"RFB 版本声明不合法：{rfb_version!r}")

    shaping = parse_json(profile.input_shaping, {})
    try:
        poc_capability.parse_input_shaping(shaping)
        logout_path = poc_capability.parse_logout_path(profile.logout_path or None)
    except ValueError as exc:
        raise ConnectionRefused("capability_field_invalid", str(exc)) from exc

    entry = {
        "id": _stable_id(profile, vendor, model, firmware),
        "vendor": vendor,
        "model": model,
        "firmware": firmware,
        "adapter": {"passthrough": PASSTHROUGH_ADAPTER_ID,
                    IDRAC8_ADAPTER_ID: IDRAC8_ADAPTER_ID,
                    IDRAC_VNC_ADAPTER_ID: IDRAC_VNC_ADAPTER_ID,
                    HUAWEI_IBMC_VNC_ADAPTER_ID: HUAWEI_IBMC_VNC_ADAPTER_ID,
                    HUAWEI_IBMC_KVM_GATEWAY_ID: HUAWEI_IBMC_KVM_GATEWAY_ID,
                    ATEN_JAVA_ADAPTER_ID: ATEN_JAVA_ADAPTER_ID}[impl],
        "models": [model],
        "firmware_min": str(profile.firmware_min or "").strip(),
        "firmware_max": str(profile.firmware_max or "").strip(),
        "protocol_versions": versions,
        "input_shaping": shaping,
        "logout_path": logout_path or "",
        "console_impl": profile.console_impl,
        "licence": profile.licence,
        "concurrency_limit": int(profile.concurrency_limit or 1),
        "evidence": profile.evidence,
    }
    if not poc_capability.window_parses(entry):
        raise ConnectionRefused("firmware_window_invalid", "固件窗口边界无法排序")
    return entry


def assembly(session: Session, *, asset_id: str, user_id: str, actor: str,
             now: float | None = None,
             tenant_id: str = DEFAULT_TENANT_ID) -> dict:
    stamp = time.time() if now is None else now
    tenant = session.get(Tenant, tenant_id)
    if tenant is None or tenant.status != TENANT_ACTIVE:
        raise ConnectionRefused("tenant_suspended", "租户已停用，无法开启新的控制台")

    try:
        services.require(session, user_id, "console.open", tenant_id=tenant_id)
    except services.PlatformError:
        raise ConnectionRefused("not_permitted", "没有开启控制台的权限") from None

    asset = session.get(Asset, asset_id)
    if asset is None or asset.tenant_id != tenant_id:
        raise ConnectionRefused("asset_not_found", "资产不存在")

    checks: dict[str, str] = {}
    profile = session.get(VendorProfile, asset.profile_id) if asset.profile_id else None
    if profile is not None and profile.tenant_id not in (None, tenant_id):
        profile = None
    if profile is None:
        raise ConnectionRefused("profile_missing", "资产未绑定品牌档案；请先做 Redfish 自动匹配")
    if profile.status != PROFILE_APPROVED:
        raise ConnectionRefused("profile_not_approved", f"品牌档案 {profile.code} 仍是 {profile.status}")
    if profile.review_due and profile.review_due < stamp:
        raise ConnectionRefused("profile_review_overdue", "品牌档案复核已到期，请带外重新审批")
    checks["profile"] = "approved"

    capability = session.get(Capability, asset.capability_id) if asset.capability_id else None
    if capability is not None and capability.tenant_id not in (None, tenant_id):
        capability = None
    if capability is None or capability.status != CAPABILITY_VERIFIED:
        raise ConnectionRefused("capability_not_verified", "兼容矩阵行尚未带外验证")
    if not capability.expires or capability.expires <= stamp:
        raise ConnectionRefused("capability_expired", "兼容矩阵行已过期")
    if capability.profile_id and capability.profile_id != profile.id:
        raise ConnectionRefused("profile_capability_mismatch", "兼容矩阵行与品牌档案不一致")
    checks["capability"] = "verified"

    if not asset.credential_id:
        raise ConnectionRefused("credential_missing", "资产未绑定 BMC 凭据")
    checks["credential"] = "by_id_only"

    detection = {"vendor": asset.vendor, "model": asset.model,
                 "firmware": asset.firmware, "raw": {"Manufacturer": asset.vendor}}
    entry = capability_entry(profile, detection=detection, asset=asset)
    plan = vendor_registry.connection_plan(profile)
    services.audit(session, actor, "console_assembly_built", asset_id=asset_id,
                   tenant_id=tenant_id,
                   detail={"profile": profile.code, "capability": capability.id,
                           "capability_entry": entry["id"], "rfb_version": profile.rfb_version},
                   now=stamp)
    return {
        "ready": True,
        "delivery": "worker_bridge",
        "tenant_id": tenant_id,
        "asset_id": asset.id,
        "address": asset.address,
        "display_address": (public_ip.public_ips_for_asset(session, asset.id) or [None])[0],
        "profile": {"id": profile.id, "code": profile.code, "status": profile.status,
                    "rfb_version": profile.rfb_version, "message_profile": profile.message_profile},
        "capability_id": capability.id,
        "credential_id": asset.credential_id,
        "plan": plan,
        "data_plane": {"adapter": entry["adapter"], "capability_entry": entry},
        "checks": checks,
        "note": "凭据仅按 id 引用；票据由 /api/v2/consoles/open 签发，装配包由 Worker 一次性取用。",
    }


def approved_profile(session: Session, code: str) -> VendorProfile | None:
    return session.scalar(select(VendorProfile).where(VendorProfile.code == code))
