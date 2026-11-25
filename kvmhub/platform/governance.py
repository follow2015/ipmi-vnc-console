"""Out-of-band command composition for the brand workbench."""
from __future__ import annotations

import shlex

from .models import CAPABILITY_VERIFIED, PROFILE_APPROVED

CLI = "tools/platform_admin.py"

EVIDENCE_PLACEHOLDER = "/path/to/measured-evidence.json"
APPROVER_PLACEHOLDER = "your-name"

DUE_SOON_SECONDS = 14 * 86400


def _command(verb: str, **flags) -> str:
    parts = [CLI, verb]
    for name, value in flags.items():
        flag = "--" + name.replace("_", "-")
        if value is None or value is False or value == "":
            continue
        if value is True:
            parts.append(flag)
            continue
        parts.append(f"{flag} {shlex.quote(str(value))}")
    return " ".join(parts)


def approve_profile_command(profile_id: str, *, approver: str = APPROVER_PLACEHOLDER,
                            evidence: str = EVIDENCE_PLACEHOLDER,
                            review_days: int = 180, renew: bool = False) -> str:
    return _command("approve-profile", id=profile_id, approver=approver,
                    evidence=evidence, review_days=review_days,
                    renew=True if renew else None)


def approve_capability_command(capability_id: str, *,
                               approver: str = APPROVER_PLACEHOLDER,
                               evidence: str = EVIDENCE_PLACEHOLDER,
                               review_days: int = 180, valid_days: int = 365) -> str:
    return _command("approve-capability", id=capability_id, approver=approver,
                    evidence=evidence, review_days=review_days,
                    valid_days=valid_days)


def profile_state(status: str, review_due: float | None, now: float) -> str:
    if status != PROFILE_APPROVED:
        return "draft" if status == "draft" else status
    due = float(review_due or 0)
    if not due:
        return "approved"
    if due <= now:
        return "overdue"
    return "due_soon" if due - now <= DUE_SOON_SECONDS else "approved"


def capability_state(status: str, expires: float | None, review_due: float | None,
                     now: float) -> str:
    if status != CAPABILITY_VERIFIED:
        return "draft" if status == "draft" else status
    expiry = float(expires or 0)
    if not expiry or expiry <= now:
        return "expired"
    if float(review_due or 0) and float(review_due) <= now:
        return "review_overdue"
    return "expiring" if expiry - now <= DUE_SOON_SECONDS else "verified"


PROFILE_NOT_APPROVED = "profile_not_approved"
PROFILE_REVIEW_OVERDUE = "profile_review_overdue"
CAPABILITY_NOT_VERIFIED = "capability_not_verified"
CAPABILITY_EXPIRED = "capability_expired"


def profile_refusal(status: str | None, review_due: float | None, now: float) -> str | None:
    if status != PROFILE_APPROVED:
        return PROFILE_NOT_APPROVED
    due = float(review_due or 0)
    if due and due <= now:
        return PROFILE_REVIEW_OVERDUE
    return None


def capability_refusal(status: str | None, expires: float | None, now: float) -> str | None:
    if status != CAPABILITY_VERIFIED:
        return CAPABILITY_NOT_VERIFIED
    expiry = float(expires or 0)
    if not expiry or expiry <= now:
        return CAPABILITY_EXPIRED
    return None


PROFILE_ACTIONABLE = ("draft", "overdue", "due_soon")
CAPABILITY_ACTIONABLE = ("draft", "expired", "review_overdue", "expiring")
PROFILE_RENEWAL = ("overdue", "due_soon")


def profile_view(row: dict, *, now: float, approver: str) -> dict:
    state = profile_state(row.get("status", ""), row.get("review_due"), now)
    command = None
    if state in PROFILE_ACTIONABLE:
        command = approve_profile_command(row["id"], approver=approver,
                                          renew=state in PROFILE_RENEWAL)
    return {**row,
            "scope": "global" if row.get("tenant_id") is None else "tenant",
            "state": state,
            "approve_command": command}


def capability_view(row: dict, *, now: float, approver: str) -> dict:
    state = capability_state(row.get("status", ""), row.get("expires"),
                             row.get("review_due"), now)
    return {**row,
            "scope": "global" if row.get("tenant_id") is None else "tenant",
            "state": state,
            "approve_command": (approve_capability_command(row["id"], approver=approver)
                                if state in CAPABILITY_ACTIONABLE else None)}
