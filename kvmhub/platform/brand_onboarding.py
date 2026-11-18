"""Out-of-band onboarding for a new brand/firmware family."""
from __future__ import annotations

import hashlib
import json
import re
import time
import uuid
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import services
from .data_plane import _template_regex
from ..capability import parse_logout_path
from .models import PROFILE_DRAFT, VendorProfile, json_field

MESSAGE_PROFILES = frozenset({"standard", "insyde", "smc"})
CONSOLE_IMPLS = frozenset({"passthrough"})
RFB_GREETING = re.compile(r"^RFB \d{3}\.\d{3}$")
CODE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,95}$")

_SPEC_FIELDS = frozenset({
    "code", "vendor", "vendor_aliases", "model_pattern", "firmware_min",
    "firmware_max", "rfb_version", "message_profile", "asset_paths",
    "login_path", "logout_path", "console_impl", "licence",
    "concurrency_limit", "input_shaping", "priority",
})


class SpecError(ValueError):
    pass


def _text(spec: dict, name: str, *, required: bool = False) -> str:
    value = spec.get(name, "")
    if value is None:
        value = ""
    if not isinstance(value, str):
        raise SpecError(f"{name} must be a string")
    value = value.strip()
    if required and not value:
        raise SpecError(f"{name} is required")
    return value


def _list(spec: dict, name: str) -> list[str]:
    value = spec.get(name, [])
    if value is None:
        return []
    if not isinstance(value, list):
        raise SpecError(f"{name} must be a list of strings")
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise SpecError(f"{name} must contain non-empty strings")
    return [item.strip() for item in value]


def _int(spec: dict, name: str, default: int, *, minimum: int = 0) -> int:
    value = spec.get(name, default)
    if isinstance(value, bool) or not isinstance(value, int):
        raise SpecError(f"{name} must be an integer")
    if value < minimum:
        raise SpecError(f"{name} must be >= {minimum}")
    return value


def validate_spec(spec: dict, *, evidence: str) -> dict:
    if not isinstance(spec, dict):
        raise SpecError("brand spec must be a JSON object")
    unknown = sorted(set(spec) - _SPEC_FIELDS)
    if unknown:
        raise SpecError("unknown spec fields: " + ", ".join(unknown))

    code = _text(spec, "code", required=True)
    if not CODE.match(code):
        raise SpecError("code must be 3-96 lowercase letters, digits, '.', '_' or '-'")
    vendor = _text(spec, "vendor", required=True)
    rfb_version = _text(spec, "rfb_version", required=True)
    if not RFB_GREETING.match(rfb_version):
        raise SpecError("rfb_version must look like 'RFB 003.008'")

    model_pattern = _text(spec, "model_pattern", required=True)
    if len(model_pattern) > 256:
        raise SpecError("model_pattern must be at most 256 characters")
    try:
        re.compile(model_pattern)
    except re.error as exc:
        raise SpecError(f"model_pattern is not a valid regex: {exc}") from exc

    console_impl = _text(spec, "console_impl") or "passthrough"
    if console_impl not in CONSOLE_IMPLS:
        raise SpecError("unsupported console_impl: " + console_impl)
    message_profile = _text(spec, "message_profile") or "standard"
    if message_profile not in MESSAGE_PROFILES:
        raise SpecError("unsupported message_profile: " + message_profile)

    shaping = spec.get("input_shaping", {})
    if shaping is None:
        shaping = {}
    if not isinstance(shaping, dict):
        raise SpecError("input_shaping must be a JSON object")
    try:
        json.dumps(shaping)
    except (TypeError, ValueError) as exc:
        raise SpecError("input_shaping is not serialisable") from exc

    aliases = _list(spec, "vendor_aliases")
    if vendor not in aliases:
        aliases.insert(0, vendor)

    path = Path(evidence)
    if not path.exists() or not path.is_file():
        raise SpecError("--evidence must point at an existing measured evidence file")
    try:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as exc:
        raise SpecError(f"evidence file is not readable: {exc}") from exc

    login_path = _text(spec, "login_path")
    logout_path = _text(spec, "logout_path")
    for name, value in (("login_path", login_path), ("logout_path", logout_path)):
        if value:
            try:
                parse_logout_path(value)
            except ValueError as exc:
                raise SpecError(f"{name} is not a valid BMC path: {exc}") from exc
    asset_paths = _list(spec, "asset_paths")
    for template in asset_paths:
        try:
            _template_regex(template)
        except Exception as exc:
            raise SpecError(f"asset_paths entry is not a safe template: {template}") from exc

    return {
        "code": code,
        "vendor": vendor,
        "vendor_aliases": aliases,
        "model_pattern": model_pattern,
        "firmware_min": _text(spec, "firmware_min"),
        "firmware_max": _text(spec, "firmware_max"),
        "rfb_version": rfb_version,
        "message_profile": message_profile,
        "asset_paths": asset_paths,
        "login_path": login_path,
        "logout_path": logout_path,
        "console_impl": console_impl,
        "licence": _text(spec, "licence"),
        "concurrency_limit": _int(spec, "concurrency_limit", 1, minimum=1),
        "input_shaping": shaping,
        "priority": _int(spec, "priority", 100),
        "evidence": str(evidence),
        "evidence_sha256": digest,
    }


def profile_matches_spec(profile: VendorProfile, spec: dict, *, evidence: str) -> bool:
    fields = validate_spec(spec, evidence=evidence)
    stable = all((getattr(profile, name) == fields[name]) for name in (
        "code", "vendor", "model_pattern", "firmware_min", "firmware_max",
        "rfb_version", "message_profile", "console_impl", "concurrency_limit",
        "priority", "login_path", "logout_path", "licence"))
    return stable and all((
        json.loads(profile.vendor_aliases or "[]") == fields["vendor_aliases"],
        json.loads(profile.asset_paths or "[]") == fields["asset_paths"],
        json.loads(profile.input_shaping or "{}") == fields["input_shaping"],
    ))


def create_draft_profile(session: Session, *, spec: dict, evidence: str,
                         actor: str, now: float | None = None) -> VendorProfile:
    fields = validate_spec(spec, evidence=evidence)
    existing = session.scalar(select(VendorProfile).where(VendorProfile.code == fields["code"]))
    if existing is not None:
        raise SpecError("profile_code_exists")

    stamp = time.time() if now is None else now
    row = VendorProfile(
        id=str(uuid.uuid4()), tenant_id=None,
        code=fields["code"], vendor=fields["vendor"],
        vendor_aliases=json_field(fields["vendor_aliases"]),
        model_pattern=fields["model_pattern"],
        firmware_min=fields["firmware_min"], firmware_max=fields["firmware_max"],
        rfb_version=fields["rfb_version"], message_profile=fields["message_profile"],
        asset_paths=json_field(fields["asset_paths"]),
        login_path=fields["login_path"], logout_path=fields["logout_path"],
        console_impl=fields["console_impl"], licence=fields["licence"],
        concurrency_limit=fields["concurrency_limit"],
        input_shaping=json_field(fields["input_shaping"]),
        priority=fields["priority"], status=PROFILE_DRAFT,
        evidence=fields["evidence"], created=stamp)
    session.add(row)
    session.flush()
    services.audit(session, actor, "vendor_profile_draft_created",
                   detail={"profile_id": row.id, "code": row.code,
                           "vendor": row.vendor, "evidence": fields["evidence"],
                           "evidence_sha256": fields["evidence_sha256"],
                           "rfb_version": row.rfb_version},
                   now=stamp)
    return row
