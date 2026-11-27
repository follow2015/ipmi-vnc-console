"""Approved brand profile -> data-plane assembly."""
from __future__ import annotations

import hashlib
import time

from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import capability as poc_capability
from ..driver_specs import (CONSOLE_DRIVERS, RFB_RELAY_ADAPTER_ID,
                            parse_access_params, relay_preset, resolve_adapter)
from ..video import client_v2
from . import governance, public_ip, services, vendor_registry
from .models import (DEFAULT_TENANT_ID, PROFILE_APPROVED,
                     TENANT_ACTIVE, Asset, AssetConnection, Capability, DeviceAdmission,
                     ExecutionDomain, PlaneProjection, Tenant, VendorProfile, parse_json)


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
        raise ConnectionRefused(governance.PROFILE_NOT_APPROVED,
                                f"品牌档案 {profile.code} 未审批，不能生成连接配置")
    raw_impl = str(profile.console_impl or "passthrough").strip()
    impl = resolve_adapter(raw_impl)
    if impl not in CONSOLE_DRIVERS:
        raise ConnectionRefused("adapter_unavailable",
                                f"档案声明的适配器 {profile.console_impl} 尚未接入数据面")
    try:
        supplied = parse_access_params(parse_json(profile.access_params, {}))
    except ValueError as exc:
        raise ConnectionRefused("capability_field_invalid", str(exc)) from exc
    access_params = {**relay_preset(raw_impl), **supplied}
    if impl == RFB_RELAY_ADAPTER_ID and not access_params.get("port"):
        raise ConnectionRefused(
            "access_params_missing",
            f"品牌档案 {profile.code} 未声明 VNC 端口；请在档案的 access_params 中补 port")

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
        "adapter": CONSOLE_DRIVERS[impl],
        "models": [model],
        "firmware_min": str(profile.firmware_min or "").strip(),
        "firmware_max": str(profile.firmware_max or "").strip(),
        "protocol_versions": versions,
        "input_shaping": shaping,
        "logout_path": logout_path or "",
        "console_impl": raw_impl,
        "access_params": access_params,
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
    services.observe_clock(session, now=stamp, actor=actor, reason="console_open")
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
    refusal = governance.profile_refusal(profile.status, profile.review_due, stamp)
    if refusal == governance.PROFILE_NOT_APPROVED:
        raise ConnectionRefused(refusal, f"品牌档案 {profile.code} 仍是 {profile.status}")
    if refusal == governance.PROFILE_REVIEW_OVERDUE:
        raise ConnectionRefused(refusal, "品牌档案复核已到期，请带外重新审批")
    checks["profile"] = "approved"

    capability = session.get(Capability, asset.capability_id) if asset.capability_id else None
    if capability is not None and capability.tenant_id not in (None, tenant_id):
        capability = None
    if capability is None:
        raise ConnectionRefused(governance.CAPABILITY_NOT_VERIFIED, "兼容矩阵行尚未带外验证")
    refusal = governance.capability_refusal(capability.status, capability.expires, stamp)
    if refusal == governance.CAPABILITY_NOT_VERIFIED:
        raise ConnectionRefused(refusal, "兼容矩阵行尚未带外验证")
    if refusal == governance.CAPABILITY_EXPIRED:
        raise ConnectionRefused(refusal, "兼容矩阵行已过期")
    if capability.profile_id and capability.profile_id != profile.id:
        raise ConnectionRefused("profile_capability_mismatch", "兼容矩阵行与品牌档案不一致")
    checks["capability"] = "verified"

    if not asset.credential_id:
        raise ConnectionRefused("credential_missing", "资产未绑定 BMC 凭据")
    checks["credential"] = "by_id_only"

    conn = session.scalar(select(AssetConnection).where(
        AssetConnection.asset_id == asset.id).order_by(
            AssetConnection.revision.desc()).limit(1))
    admission = session.scalar(select(DeviceAdmission).where(
        DeviceAdmission.asset_id == asset.id).order_by(
            DeviceAdmission.revision.desc()).limit(1))
    projection = None
    if admission is not None and admission.domain_id:
        projection = session.scalar(select(PlaneProjection).where(
            PlaneProjection.asset_id == asset.id,
            PlaneProjection.domain_id == admission.domain_id))
    if projection is None:
        projection = session.scalar(select(PlaneProjection).where(
            PlaneProjection.asset_id == asset.id).order_by(PlaneProjection.domain_id))
    domains = {row.domain_id: row for row in session.scalars(
        select(ExecutionDomain)).all()}
    domain_row = domains.get(projection.domain_id) if projection else None
    lane_opt_in = bool(getattr(profile, "recipe_id", "") and capability.bundle_revision)
    stored_versions = parse_json(conn.source_versions_json, {}) if conn is not None else {}
    if not isinstance(stored_versions, dict):
        stored_versions = {}
    contract_stale = bool(lane_opt_in and stored_versions.get("protocol_contract")
                          != client_v2.protocol_contract())
    snapshot_ready = bool(conn and admission and projection and domain_row
                          and admission.state == "approved"
                          and projection.applied_revision == conn.revision
                          and projection.applied_digest == conn.digest
                          and domain_row.generation == projection.generation
                          and domain_row.policy_fingerprint == projection.policy_fingerprint
                          and domain_row.health == "healthy")
    g0 = {
        "ready": snapshot_ready and not contract_stale,
        "connection_revision": conn.revision if conn else 0,
        "admission_revision": admission.revision if admission else 0,
        "digest": conn.digest if conn else "",
        "domain_id": projection.domain_id if projection else "",
        "generation": projection.generation if projection else "",
        "policy_fingerprint": projection.policy_fingerprint if projection else "",
        "reason": ("contract_stale" if contract_stale
                   else "" if snapshot_ready else "snapshot_pending"),
    }
    checks["g0_snapshot"] = "ready" if g0["ready"] else "pending"
    if contract_stale:
        raise ConnectionRefused(
            "pipeline_version_unavailable",
            "控制台线格式契约已更新，该资产的 G0 快照仍绑定旧契约；"
            "请执行 tools/platform_admin.py refresh-lane-contract 并确认投影后重试")
    if lane_opt_in:
        checks["client_build"] = ("matches"
                                  if capability.bundle_revision == client_v2.client_build()
                                  else "diverges")

    detection = {"vendor": asset.vendor, "model": asset.model,
                 "firmware": asset.firmware, "raw": {"Manufacturer": asset.vendor}}
    from . import overlays
    overlay = overlays.check_asset(session, asset, now=stamp)
    if overlay:
        detection = {**overlay['identity'], 'raw': {'Manufacturer': overlay['identity']['vendor']}}
    entry = capability_entry(profile, detection=detection, asset=asset)
    if overlay:
        if not g0['ready']:
            raise ConnectionRefused('connection_config_pending', '覆盖层配置尚未确认')
        entry['concurrency_limit'] = min(entry['concurrency_limit'], overlay['concurrency'])
        checks['overlay'] = 'verified_subset'
    plan = vendor_registry.connection_plan(profile)
    services.audit(session, actor, "console_assembly_built", asset_id=asset_id,
                   tenant_id=tenant_id,
                   detail={"profile": profile.code, "capability": capability.id,
                           "capability_entry": entry["id"], "rfb_version": profile.rfb_version},
                   now=stamp)
    return {
        "ready": True,
        "overlay": overlay['material'] if overlay else None,
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
        "worker_requirements": (
            {"lane": "transcode-v1",
             "versions": {"recipe_id": profile.recipe_id,
                          "recipe_revision": str(profile.recipe_revision or 0),
                          "protocol_contract": client_v2.protocol_contract(),
                          "schema_version": profile.config_schema_version}}
            if (g0["ready"] and lane_opt_in) else {}),
        "client_contract": client_v2.protocol_contract() if g0["ready"] else "",
        "client_bundle": capability.bundle_revision
        if g0["ready"] and capability.bundle_revision else "",
        "data_plane": {"adapter": entry["adapter"], "capability_entry": entry,
                       "access_params": entry.get("access_params") or {}},
        "g0": g0,
        "checks": checks,
        "note": "凭据仅按 id 引用；票据由 /api/v2/consoles/open 签发，装配包由 Worker 一次性取用。",
    }


def approved_profile(session: Session, code: str) -> VendorProfile | None:
    return session.scalar(select(VendorProfile).where(VendorProfile.code == code))
