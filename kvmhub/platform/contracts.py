"""Response contracts for the control-plane OpenAPI document."""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class Contract(BaseModel):
    model_config = ConfigDict(extra="allow")


class ApiError(Contract):
    error: str
    message: str
    trace_id: str


class OkResult(Contract):
    ok: bool


class Healthz(Contract):
    status: str
    env: str


class Readyz(Contract):
    status: str
    checks: dict[str, bool]


class UserPublic(Contract):
    id: str
    username: str
    display_name: str
    is_active: bool
    created: float
    last_login: float | None = None
    roles: list[str] = Field(default_factory=list)


class LoginResult(Contract):
    user: UserPublic
    roles: list[str]
    csrf: str


class Me(Contract):
    user_id: str
    username: str
    roles: list[str]
    permissions: list[str]
    csrf: str


class AssetOccupancy(Contract):
    busy: bool
    owned: bool
    user_id: str | None = None
    username: str | None = None
    session_id: str | None = None
    status: str
    cleanup: str
    hard_until: float
    remaining_seconds: int
    queue: str


class Asset(Contract):
    id: str
    name: str
    address: str
    vendor: str
    model: str
    firmware: str
    fingerprint_prefix: str
    profile_id: str | None = None
    capability_id: str | None = None
    licence: str
    status: str
    notes: str
    grant_expires: float | None = None
    occupancy: AssetOccupancy | None = None
    occupancy_available: bool = False


class CredentialCreated(Contract):
    id: str
    label: str
    key_version: int
    created: float
    rotated_at: float | None = None


class VendorProfile(Contract):
    id: str
    code: str
    vendor: str
    vendor_aliases: list[str]
    model_pattern: str
    rfb_version: str
    message_profile: str
    asset_paths: list[str]
    login_path: str
    logout_path: str
    console_impl: str
    licence: str
    status: str
    evidence: str
    approver: str
    review_due: float
    priority: int


class TextWarning(Contract):
    level: str
    char: str
    message: str
    index: int


class TextStroke(Contract):
    index: int
    char: str
    usage: int
    shift: bool
    reliability: str


class TextPlan(Contract):
    counts: dict[str, int]
    warnings: list[TextWarning]
    has_broken: bool
    strokes: list[TextStroke]


class TextInputMatrix(Contract):
    levels: dict[str, list[str]]
    known_broken_notes: dict[str, str]
    max_chars: int
    note: str


class Detection(Contract):
    vendor: str
    model: str
    firmware: str
    source: str = ""


class MatchCandidate(Contract):
    id: str
    code: str
    status: str
    rfb_version: str
    reasons: list[str]


class DetectResult(Contract):
    detection: Detection
    matched: bool
    usable: bool
    reason: str
    candidates: list[MatchCandidate]
    profile: VendorProfile | None = None
    capability_draft_id: str | None = None
    connection_plan: dict[str, Any] | None = None


class ConnectionPlan(Contract):
    rfb_version: str
    message_profile: str
    asset_paths: list[str]
    login_path: str
    logout_path: str
    console_impl: str
    input_shaping: dict[str, Any]
    concurrency_limit: int
    licence: str


class CapabilityEntry(Contract):
    id: str
    vendor: str
    model: str
    firmware: str
    adapter: str
    models: list[str]
    firmware_min: str
    firmware_max: str
    protocol_versions: list[str]
    input_shaping: dict[str, Any]
    logout_path: str
    console_impl: str
    licence: str
    concurrency_limit: int
    evidence: str


class AssemblyProfile(Contract):
    id: str
    code: str
    status: str
    rfb_version: str
    message_profile: str


class DataPlaneAssembly(Contract):
    adapter: str
    capability_entry: CapabilityEntry


class ConnectionAssembly(Contract):
    ready: bool
    delivery: str
    asset_id: str
    address: str
    profile: AssemblyProfile
    capability_id: str
    credential_id: str
    plan: ConnectionPlan
    data_plane: DataPlaneAssembly
    checks: dict[str, str]
    note: str


class ConsoleTicket(Contract):
    sid: str
    ticket: str
    accept_url: str
    worker_id: str
    instance_id: str
    assembly_id: str
    delivery: str
    hard_until: float
    asset_id: str
    note: str


class ConsoleCloseResult(Contract):
    ok: bool
    sid: str


class ConsoleCleanupResult(Contract):
    ok: bool
    sid: str
    cleanup: str


class ConsoleStatus(Contract):
    id: str
    asset_id: str
    status: str
    cleanup: str
    reason: str | None = None
    created: float
    hard_until: float
    end_evidence: dict[str, Any] | None = None


class WorkerInfo(Contract):
    worker_id: str
    instance_id: str
    capacity: int
    registered_at: float
    metadata: dict[str, Any]
    load: int
    draining: bool


class AuditRow(Contract):
    id: int
    ts: float
    trace_id: str
    actor: str
    action: str
    asset_id: str | None = None
    detail: dict[str, Any]


CONTRACT_MODELS: dict[str, type[BaseModel]] = {
    name: value for name, value in list(globals().items())
    if isinstance(value, type) and value.__module__ == __name__
    and issubclass(value, BaseModel) and value is not Contract
}


def contract_components() -> dict[str, dict]:
    out: dict[str, dict] = {}
    for name, model in CONTRACT_MODELS.items():
        schema = model.model_json_schema(ref_template="#/components/schemas/{model}")
        defs = schema.pop("$defs", {})
        out.update(defs)
        out[name] = schema
    return out


CONTRACT_RESPONSES: dict[str, dict[str, str]] = {
    "/healthz": {"get": "Healthz"},
    "/readyz": {"get": "Readyz"},
    "/api/v2/login": {"post": "LoginResult"},
    "/api/v2/logout": {"post": "OkResult"},
    "/api/v2/me": {"get": "Me"},
    "/api/v2/users": {"get": "list:UserPublic", "post": "UserPublic"},
    "/api/v2/users/{user_id}/active": {"post": "OkResult"},
    "/api/v2/assets": {"get": "list:Asset", "post": "Asset"},
    "/api/v2/credentials": {"post": "CredentialCreated"},
    "/api/v2/grants": {"post": "OkResult"},
    "/api/v2/vendor-profiles": {"get": "list:VendorProfile"},
    "/api/v2/detect": {"post": "DetectResult"},
    "/api/v2/consoles/assembly": {"post": "ConnectionAssembly"},
    "/api/v2/consoles/open": {"post": "ConsoleTicket"},
    "/api/v2/consoles/{sid}": {"get": "ConsoleStatus"},
    "/api/v2/consoles/{sid}/close": {"post": "ConsoleCloseResult"},
    "/api/v2/consoles/{sid}/cleanup": {"post": "ConsoleCleanupResult"},
    "/api/v2/text-input/matrix": {"get": "TextInputMatrix"},
    "/api/v2/text-plan": {"post": "TextPlan"},
    "/api/v2/workers": {"get": "map:WorkerInfo"},
    "/api/v2/audit": {"get": "list:AuditRow"},
}


def response_schema(spec: str) -> dict:
    shape, name = spec.split(":", 1) if ":" in spec else ("", spec)
    ref = {"$ref": f"#/components/schemas/{name}"}
    if shape == "list":
        return {"type": "array", "items": ref}
    if shape == "map":
        return {"type": "object", "additionalProperties": ref}
    return ref
