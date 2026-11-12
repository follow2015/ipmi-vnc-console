"""Compatibility-matrix policy: who may be exchanged, and under what terms."""
import json
import re

STATUSES = ("draft", "verified", "suspended", "retired")

TRANSITIONS = {
    "draft": frozenset({"verified", "retired"}),
    "verified": frozenset({"verified", "suspended", "retired"}),
    "suspended": frozenset({"verified", "retired"}),
    "retired": frozenset(),
}

APPROVAL_INPUTS = ("approver", "evidence", "licence", "console_impl")

_VERSION = re.compile(r"^[0-9]{1,6}(?:\.[0-9]{1,6}){0,3}$")
_RFB_GREETING = re.compile(r"RFB \d{3}\.\d{3}")


def transition_allowed(source: str, target: str) -> bool:
    return target in TRANSITIONS.get(source, frozenset())


def version_key(value) -> tuple | None:
    text = str(value or "").strip()
    if not _VERSION.fullmatch(text):
        return None
    parts = [int(part) for part in text.split(".")]
    return tuple(parts + [0] * (4 - len(parts)))


def firmware_in_range(entry, firmware: str) -> bool:
    low = str(entry.get("firmware_min") or "").strip()
    high = str(entry.get("firmware_max") or "").strip()
    value = str(firmware or "").strip()
    if low or high:
        target = version_key(value)
        lower = version_key(low) if low else (0, 0, 0, 0)
        upper = version_key(high) if high else None
        if target is None or lower is None or (high and upper is None):
            return False
        return target >= lower and (upper is None or target <= upper)
    exact = str(entry.get("firmware") or "").strip()
    return bool(exact) and exact == value


def models_in_family(entry, model: str) -> bool:
    raw = entry.get("models") or "[]"
    listed = ()
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
        except ValueError:
            parsed = ()
        if isinstance(parsed, list):
            listed = tuple(item for item in parsed if isinstance(item, str) and item)
    elif isinstance(raw, (list, tuple)):
        listed = tuple(item for item in raw if isinstance(item, str) and item)
    if listed:
        return str(model or "") in listed
    return bool(entry.get("model")) and entry.get("model") == model


def parse_protocol_versions(raw) -> tuple[str, ...] | None:
    if raw is None or raw == "":
        return ()
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
        except ValueError:
            return None
    elif isinstance(raw, (list, tuple)):
        parsed = list(raw)
    else:
        return None
    if not isinstance(parsed, list) or any(
            not isinstance(v, str) or not _RFB_GREETING.fullmatch(v) for v in parsed):
        return None
    if len(set(parsed)) != len(parsed):
        return None
    return tuple(parsed)


def window_parses(entry) -> bool:
    low = str(entry.get("firmware_min") or "").strip()
    high = str(entry.get("firmware_max") or "").strip()
    if not low and not high:
        return True
    lower = version_key(low) if low else (0, 0, 0, 0)
    upper = version_key(high) if high else None
    if lower is None or (high and upper is None):
        return False
    return upper is None or lower <= upper


def approval_gaps(entry) -> tuple:
    return tuple(field for field in APPROVAL_INPUTS
                 if not str(entry.get(field) or "").strip())


def evaluate(entry, asset, now: float) -> str | None:
    if not entry:
        return "missing_entry"
    if entry.get("status") != "verified":
        return "not_verified"
    if approval_gaps(entry):
        return "unapproved"
    if float(entry.get("effective_from") or 0) > now:
        return "not_yet_effective"
    if float(entry.get("expires") or 0) <= now:
        return "expired"
    if float(entry.get("review_due") or 0) <= now:
        return "review_overdue"
    if entry.get("vendor") != asset.get("vendor"):
        return "identity_mismatch"
    if not models_in_family(entry, asset.get("model")):
        return "identity_mismatch"
    if not firmware_in_range(entry, asset.get("firmware")):
        return "firmware_out_of_range"
    if int(entry.get("concurrency_limit") or 0) < 1:
        return "no_capacity"
    return None
