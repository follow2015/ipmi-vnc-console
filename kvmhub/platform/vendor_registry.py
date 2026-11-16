"""Brand detection -> vendor profile -> connection plan."""
from __future__ import annotations

import re
import time
import uuid
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import (PROFILE_APPROVED, PROFILE_DRAFT, VendorProfile, json_field, parse_json)

VENDOR_ALIASES: dict[str, tuple[str, ...]] = {
    "supermicro": ("supermicro", "supermicro computer", "supermicro (inspur oem)",
                   "smci", "american megatrends", "ami", "insur", "inspur"),
    "lenovo": ("lenovo", "ibm", "ibm corporation"),
    "dell": ("dell", "dell inc.", "dell emc", "idrac"),
    "hpe": ("hpe", "hewlett packard enterprise", "hp", "ilo"),
    "huawei": ("huawei", "huawei technologies", "ibmc"),
    "inspur": ("inspur", "inspur electronic information", "浪潮"),
}

BUILTIN_PROFILES = (
    {"code": "smci-x10-ast2100-rfb003008", "vendor": "supermicro",
     "vendor_aliases": ["supermicro", "supermicro (inspur oem)", "smci", "inspur"],
     "model_pattern": r"(?i)X10DRT|X10|SA5248M4", "firmware_min": "", "firmware_max": "",
     "rfb_version": "RFB 003.008", "message_profile": "insyde",
     "asset_paths": ["/novnc/include/*.js", "/js/*.js", "/css/*.css",
                     "/images/**/*.png", "/images/**/*.gif", "/images/**/*.jpg",
                     "/images/**/*.svg", "/favicon.ico"],
     "login_path": "/cgi/login.cgi",
     "logout_path": "/cgi/logout.cgi", "console_impl": "passthrough",
     "licence": "IKVM HTML5", "concurrency_limit": 1,
     "evidence": "docs/implementation/evidence/real-bmc-passthrough-e2e-20261112.json",
     "priority": 100},
    {"code": "smci-ast2600-rfb055008", "vendor": "supermicro",
     "vendor_aliases": ["supermicro", "supermicro (inspur oem)", "smci"],
     "model_pattern": r"(?i)AST2600|X12|X13|H12|H13", "firmware_min": "", "firmware_max": "",
     "rfb_version": "RFB 055.008", "message_profile": "smc",
     "asset_paths": ["/novnc/include/*.js", "/js/*.js", "/css/*.css",
                     "/images/**/*.png", "/images/**/*.gif", "/images/**/*.jpg",
                     "/images/**/*.svg", "/favicon.ico"],
     "login_path": "/cgi/login.cgi",
     "logout_path": "/cgi/logout.cgi", "console_impl": "passthrough",
     "licence": "IKVM HTML5", "concurrency_limit": 1,
     "evidence": "docs/implementation/evidence/real-bmc-capslock-d-20261115.json",
     "priority": 100},
)


class UnknownVendor(ValueError):
    def __init__(self, detection: dict, message: str = "no approved vendor profile matches"):
        super().__init__(message)
        self.detection = detection


def normalize_vendor(raw: str | None) -> str:
    if not isinstance(raw, str):
        return ""
    text = re.sub(r"[\s_,.;()\[\]]+", " ", raw.strip().lower()).strip()
    text = re.sub(r"\b(inc|incorporated|corp|corporation|ltd|co|company|technologies|technology)\b", "", text)
    text = re.sub(r"\s+", " ", text).strip()
    for canonical, aliases in VENDOR_ALIASES.items():
        if text == canonical or text in aliases or any(a in text for a in aliases if len(a) > 4):
            return canonical
    return text


def _version_key(raw: str) -> tuple[int, ...]:
    parts = re.findall(r"\d+", raw or "")
    return tuple(int(p) for p in parts[:4]) or (0,)


def firmware_in_window(version: str, low: str, high: str) -> bool:
    if not version:
        return not low and not high
    value = _version_key(version)
    if low and value < _version_key(low):
        return False
    if high and value > _version_key(high):
        return False
    return True


def detect_from_redfish(inventory: dict) -> dict:
    if not isinstance(inventory, dict):
        return {"vendor": "", "model": "", "firmware": "", "raw": {}}
    resources = inventory.get("resources") or {}
    for group in ("Managers", "Systems", "Chassis"):
        items = resources.get(group) or []
        if not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, dict):
                continue
            vendor = normalize_vendor(item.get("Manufacturer"))
            model = str(item.get("Model") or "")
            firmware = str(item.get("FirmwareVersion") or "")
            if vendor or model or firmware:
                return {"vendor": vendor, "model": model, "firmware": firmware,
                        "raw": {k: item.get(k) for k in ("Id", "Name", "Manufacturer",
                                                         "Model", "FirmwareVersion")},
                        "source": group}
    return {"vendor": "", "model": "", "firmware": "", "raw": {}, "source": None}


def seed_builtin_profiles(session: Session, *, now: float | None = None) -> int:
    stamp = time.time() if now is None else now
    existing = {row.code for row in session.scalars(select(VendorProfile)).all()}
    added = 0
    for item in BUILTIN_PROFILES:
        if item["code"] in existing:
            continue
        session.add(VendorProfile(
            id=str(uuid.uuid4()), code=item["code"], vendor=item["vendor"],
            vendor_aliases=json_field(item["vendor_aliases"]),
            model_pattern=item["model_pattern"], firmware_min=item["firmware_min"],
            firmware_max=item["firmware_max"], rfb_version=item["rfb_version"],
            message_profile=item["message_profile"], asset_paths=json_field(item["asset_paths"]),
            login_path=item["login_path"], logout_path=item["logout_path"],
            console_impl=item["console_impl"], licence=item["licence"],
            concurrency_limit=item["concurrency_limit"], evidence=item["evidence"],
            priority=item["priority"], status=PROFILE_DRAFT, created=stamp))
        added += 1
    session.commit()
    return added


@dataclass
class Match:
    profile: VendorProfile | None
    candidates: list[dict] = field(default_factory=list)
    usable: bool = False
    reason: str = ""

    def as_dict(self) -> dict:
        return {"matched": self.profile is not None,
                "profile": self.profile.public() if self.profile else None,
                "usable": self.usable, "reason": self.reason, "candidates": self.candidates}


def identify(session: Session, detection: dict) -> Match:
    vendor = normalize_vendor(detection.get("vendor") or detection.get("Manufacturer"))
    model = str(detection.get("model") or "")
    firmware = str(detection.get("firmware") or "")
    if not vendor:
        return Match(None, reason="vendor_not_detected")

    scored: list[tuple[int, VendorProfile, list[str]]] = []
    for profile in session.scalars(select(VendorProfile)).all():
        reasons: list[str] = []
        aliases = [normalize_vendor(a) for a in parse_json(profile.vendor_aliases, [])]
        aliases.append(normalize_vendor(profile.vendor))
        if not any(a and (a == vendor or a in vendor or vendor in a) for a in aliases):
            continue
        reasons.append("vendor_alias")
        pattern = profile.model_pattern
        if pattern:
            try:
                if not re.search(pattern, model):
                    continue
                reasons.append("model_pattern")
            except re.error:
                reasons.append("model_pattern_invalid")
                continue
        else:
            reasons.append("model_open")
        if not firmware_in_window(firmware, profile.firmware_min, profile.firmware_max):
            continue
        reasons.append("firmware_window")
        score = len(reasons) * 1000 + (1000 if profile.status == PROFILE_APPROVED else 0) - int(profile.priority)
        scored.append((score, profile, reasons))

    if not scored:
        return Match(None, reason="unknown_vendor")
    scored.sort(key=lambda item: (-item[0], item[1].code))
    candidates = [{"id": p.id, "code": p.code, "status": p.status,
                   "rfb_version": p.rfb_version, "reasons": why}
                  for _, p, why in scored]
    best = scored[0][1]
    usable = best.status == PROFILE_APPROVED
    reason = "approved_match" if usable else "matched_but_not_approved"
    return Match(best, candidates, usable, reason)


def connection_plan(profile: VendorProfile) -> dict:
    if profile.status != PROFILE_APPROVED:
        raise UnknownVendor({"profile": profile.code}, "profile is not approved; no connection plan")
    return {"rfb_version": profile.rfb_version,
            "message_profile": profile.message_profile,
            "asset_paths": parse_json(profile.asset_paths, []),
            "login_path": profile.login_path,
            "logout_path": profile.logout_path,
            "console_impl": profile.console_impl,
            "input_shaping": parse_json(profile.input_shaping, {}),
            "concurrency_limit": int(profile.concurrency_limit or 1),
            "licence": profile.licence}
