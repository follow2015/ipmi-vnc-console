"""Translate an approved brand assembly into Worker-side connection settings."""
from __future__ import annotations

import re

from .. import capability as poc_capability
from ..common import PASSTHROUGH_ADAPTER_ID, Problem

DEFAULT_ASSET_PATHS = (
    "/novnc/include/*.js",
    "/js/*.js",
    "/css/*.css",
    "/images/**/*.png",
    "/images/**/*.gif",
    "/images/**/*.jpg",
    "/images/**/*.svg",
    "/favicon.ico",
)

MESSAGE_PROFILE_BY_VERSION = {"RFB 003.008": "insyde", "RFB 055.008": "smc"}

_SEGMENT = r"[A-Za-z0-9_-][A-Za-z0-9_.-]{0,79}"
_SINGLE_STAR = r"[A-Za-z0-9_-][A-Za-z0-9_.-]{0,63}"
_FORBIDDEN_ASSET_PREFIXES = ("/cgi/", "/_platform/", "/internal/", "/api/")


def parse_endpoint_path(raw, field: str) -> str | None:
    if raw is None or raw == "":
        return None
    if not isinstance(raw, str):
        raise Problem("invalid_target_policy", 502)
    value = raw.strip()
    if not value:
        return None
    if (len(value) > 128 or not value.startswith("/") or "?" in value or "#" in value
            or "//" in value or any(part in (".", "..") for part in value.split("/"))):
        raise Problem("invalid_target_policy", 502)
    return value


def _template_regex(template: str) -> str:
    if not isinstance(template, str) or not template.startswith("/") or len(template) > 160:
        raise Problem("invalid_target_policy", 502)
    if any(char in template for char in ("?", "#", "\\", "..")) or "//" in template:
        raise Problem("invalid_target_policy", 502)
    if any(template.startswith(prefix) for prefix in _FORBIDDEN_ASSET_PREFIXES):
        raise Problem("invalid_target_policy", 502)
    parts = template.split("/")
    if parts[0] != "":
        raise Problem("invalid_target_policy", 502)
    tokens = parts[1:]
    if not tokens or any(part == "" for part in tokens):
        raise Problem("invalid_target_policy", 502)
    regex = ""
    for index, part in enumerate(tokens):
        last = index == len(tokens) - 1
        if part == "**":
            regex += f"(?:{_SEGMENT}/)*"
            continue
        if "*" in part:
            if part.count("*") != 1:
                raise Problem("invalid_target_policy", 502)
            head, tail = part.split("*", 1)
            if not re.fullmatch(r"[A-Za-z0-9_.-]*", head + tail):
                raise Problem("invalid_target_policy", 502)
            if head.startswith(".") or tail.endswith(".") or ".." in head + tail:
                raise Problem("invalid_target_policy", 502)
            piece = re.escape(head) + _SINGLE_STAR + re.escape(tail)
        else:
            if not re.fullmatch(r"[A-Za-z0-9_.-]+", part):
                raise Problem("invalid_target_policy", 502)
            piece = re.escape(part)
        regex += piece + ("" if last else "/")
    return "/" + regex


def compile_asset_paths(templates) -> re.Pattern[str]:
    if templates is None:
        templates = DEFAULT_ASSET_PATHS
    if not isinstance(templates, (list, tuple)) or not templates or len(templates) > 32:
        raise Problem("invalid_target_policy", 502)
    branches = [_template_regex(item) for item in templates]
    return re.compile("(?:" + "|".join(branches) + ")")


def verify_tenant(assembly: dict | None, tenant_id: str) -> None:
    declared = str((assembly or {}).get("tenant_id") or "")
    if declared and declared != tenant_id:
        raise Problem("invalid_target_policy", 502)


def assembled_info(info: dict, assembly: dict | None) -> dict:
    if assembly is None:
        return info
    if not isinstance(assembly, dict):
        raise Problem("invalid_target_policy", 502)
    data_plane = assembly.get("data_plane") or {}
    entry = data_plane.get("capability_entry") or {}
    plan = assembly.get("plan") or {}
    if data_plane.get("adapter") not in (None, PASSTHROUGH_ADAPTER_ID):
        raise Problem("invalid_target_policy", 502)
    if entry.get("adapter") and entry["adapter"] != PASSTHROUGH_ADAPTER_ID:
        raise Problem("invalid_target_policy", 502)

    declared = poc_capability.parse_protocol_versions(entry.get("protocol_versions"))
    if declared is None:
        raise Problem("invalid_target_policy", 502)
    rfb_version = str(plan.get("rfb_version") or "").strip()
    if rfb_version and rfb_version not in declared:
        raise Problem("invalid_target_policy", 502)
    message_profile = str(plan.get("message_profile") or "").strip()
    if rfb_version and message_profile:
        expected = MESSAGE_PROFILE_BY_VERSION.get(rfb_version)
        if expected and expected != message_profile:
            raise Problem("invalid_target_policy", 502)

    try:
        shaping = poc_capability.parse_input_shaping(entry.get("input_shaping") or {})
    except ValueError as exc:
        raise Problem("invalid_target_policy", 502) from exc
    try:
        logout_path = poc_capability.parse_logout_path(plan.get("logout_path") or entry.get("logout_path"))
        login_path = parse_endpoint_path(plan.get("login_path"), "login_path")
    except ValueError as exc:
        raise Problem("invalid_target_policy", 502) from exc
    asset_pattern = compile_asset_paths(plan.get("asset_paths"))

    result = dict(info)
    result.update({
        "protocol_versions": tuple(declared),
        "input_shaping": shaping or info.get("input_shaping"),
        "logout_path": logout_path or info.get("logout_path"),
        "login_path": login_path,
        "asset_pattern": asset_pattern,
        "message_profile": message_profile,
        "rfb_version": rfb_version,
        "assembly_id": assembly.get("assembly_id"),
        "assembly_profile": (assembly.get("profile") or {}).get("code"),
    })
    return result
