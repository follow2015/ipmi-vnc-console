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
    retryable: bool = False


class OkResult(Contract):
    ok: bool


class AssetGroup(Contract):
    id: str
    tenant_id: str
    name: str
    created: float
    updated: float
    member_count: int = 0


class GroupMembers(Contract):
    group: AssetGroup
    members: list[str]


class GroupGrantResult(Contract):
    group_id: str
    user_id: str
    granted: int
    revoked_stale: int


class PlatformGrantResult(Contract):
    ok: bool
    level: int
    user_id: str
    asset_id: str


class AssetResetResult(Contract):
    ok: bool
    asset_id: str
    address: str
    method: str
    accepted: bool


class Healthz(Contract):
    status: str
    env: str


class Readyz(Contract):
    status: str
    checks: dict[str, bool]


class UserPublic(Contract):
    id: str
    tenant_id: str | None = None
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
    tenant_id: str | None = None


class Me(Contract):
    user_id: str
    username: str
    tenant_id: str | None = None
    tenant_mode: str | None = None
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
    tenant_id: str | None = None
    name: str
    address: str | None = None
    public_ip: str | None = None
    public_ips: list[str] = []
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


class PublicIpMapping(Contract):
    id: str
    tenant_id: str
    asset_id: str
    primary_ip: str
    additional_ips: str
    public_ips: list[str] = []
    created: float
    updated: float


class PlatformAsset(Asset):

    tenant_code: str | None = None


class AssetAssignment(Contract):

    asset: Asset
    action: str
    previous_tenant: str | None = None


class QuotaUsage(Contract):

    tenant_id: str
    tenant_code: str
    period: str
    assets: int
    sessions: int
    minutes: int
    updated: float


class CredentialCreated(Contract):
    id: str
    label: str
    key_version: int
    created: float
    rotated_at: float | None = None


class VendorProfile(Contract):
    id: str
    tenant_id: str | None = None
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


class OnboardCapability(Contract):

    id: str
    model: str
    firmware: str
    adapter: str
    status: str
    expires: float


class OnboardBrand(Contract):

    profile_id: str
    code: str
    vendor: str
    model_pattern: str
    firmware_min: str
    firmware_max: str
    licence: str
    console_impl: str
    certificate_mode: str
    certificate_note: str
    default_capability_id: str | None = None
    capabilities: list[OnboardCapability]


class AssetOnboarding(Contract):

    brands: list[OnboardBrand]
    note: str


class VendorProfileView(VendorProfile):
    scope: str
    state: str
    approve_command: str | None = None


class CapabilityView(Contract):
    id: str
    tenant_id: str | None = None
    scope: str
    vendor: str
    model: str
    firmware: str
    adapter: str
    profile_id: str | None = None
    status: str
    state: str
    evidence: str = ""
    approver: str = ""
    expires: float = 0
    review_due: float = 0
    models: list[str] = Field(default_factory=list)
    protocol_versions: list[str] = Field(default_factory=list)
    approve_command: str | None = None


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


class AssetProbeResult(Contract):

    address: str
    public_ips: list[str] = []
    certificate_sha256: str
    redfish_auth: str
    detection: Detection
    matched: bool
    usable: bool
    reason: str
    profile_id: str | None = None
    profile_code: str = ""
    note: str = ""


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


class Tenant(Contract):
    id: str
    code: str
    name: str
    status: str
    plan: str
    mode: str = "manager"
    quotas: dict[str, Any]
    created: float
    assets: int = 0
    users: int = 0
    active_sessions: int = 0


class SessionView(Contract):
    sid: str
    tenant_id: str | None = None
    tenant_code: str | None = None
    user_id: str
    username: str | None = None
    asset_id: str
    asset_name: str | None = None
    asset_address: str | None = None
    asset_public_ip: str | None = None
    worker_id: str
    status: str
    cleanup: str
    created: float
    duration_seconds: int
    remaining_seconds: int
    route_active: bool
    lease_active: bool


class SessionRevoked(Contract):
    ok: bool
    sid: str
    status: str
    asset_id: str | None = None
    was_live: bool
    tenant_id: str | None = None
    trace_id: str


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
    tenant_id: str | None = None
    note: str


class ConsoleCloseResult(Contract):
    ok: bool
    sid: str


class IntegrationPing(Contract):

    ok: bool
    tenant_code: str
    service_account: str
    token_label: str
    token_prefix: str


class IntegrationAssets(Contract):

    assets: list[Asset]


class IntegrationConsoleOpen(ConsoleTicket):
    session_limit_minutes: int | None = None


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
    tenant_id: str | None = None
    trace_id: str
    actor: str
    actor_type: str = "user"
    actor_tenant: str | None = None
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
    "/api/v2/platform/login": {"post": "LoginResult"},
    "/api/v2/platform/logout": {"post": "OkResult"},
    "/api/v2/platform/me": {"get": "Me"},
    "/api/v2/users": {"get": "list:UserPublic", "post": "UserPublic"},
    "/api/v2/users/{user_id}/active": {"post": "OkResult"},
    "/api/v2/users/{user_id}/password": {"post": "OkResult"},
    "/api/v2/assets": {"get": "list:Asset", "post": "Asset"},
    "/api/v2/asset-onboarding": {"get": "AssetOnboarding"},
    "/api/v2/assets/probe": {"post": "AssetProbeResult"},
    "/api/v2/public-ips": {"get": "list:PublicIpMapping"},
    "/api/v2/public-ips/{asset_id}": {"put": "PublicIpMapping"},
    "/api/v2/credentials": {"get": "list:CredentialCreated", "post": "CredentialCreated"},
    "/api/v2/grants": {"post": "OkResult"},
    "/api/v2/asset-groups": {"get": "list:AssetGroup", "post": "AssetGroup"},
    "/api/v2/asset-groups/{group_id}": {"delete": "OkResult"},
    "/api/v2/asset-groups/{group_id}/members": {"put": "GroupMembers"},
    "/api/v2/asset-groups/{group_id}/grant": {"post": "GroupGrantResult"},
    "/api/v2/vendor-profiles": {"get": "list:VendorProfile"},
    "/api/v2/detect": {"post": "DetectResult"},
    "/api/v2/consoles/assembly": {"post": "ConnectionAssembly"},
    "/api/v2/consoles/open": {"post": "ConsoleTicket"},
    "/api/v2/consoles/{sid}": {"get": "ConsoleStatus"},
    "/api/v2/consoles/{sid}/close": {"post": "ConsoleCloseResult"},
    "/api/v2/consoles/{sid}/cleanup": {"post": "ConsoleCleanupResult"},
    "/api/v2/sessions": {"get": "list:SessionView"},
    "/api/v2/sessions/{sid}/revoke": {"post": "SessionRevoked"},
    "/api/v2/text-input/matrix": {"get": "TextInputMatrix"},
    "/api/v2/text-plan": {"post": "TextPlan"},
    "/api/v2/workers": {"get": "map:WorkerInfo"},
    "/api/v2/audit": {"get": "list:AuditRow"},
    "/api/v2/platform/tenants": {"get": "list:Tenant", "post": "Tenant"},
    "/api/v2/platform/tenants/{tenant_id}": {"patch": "Tenant"},
    "/api/v2/platform/tenants/{tenant_id}/status": {"post": "Tenant"},
    "/api/v2/platform/tenants/{tenant_id}/users": {"post": "UserPublic"},
    "/api/v2/platform/users": {"get": "list:UserPublic"},
    "/api/v2/platform/users/{user_id}/active": {"post": "OkResult"},
    "/api/v2/platform/users/{user_id}/role": {"patch": "UserPublic"},
    "/api/v2/platform/users/{user_id}/password": {"post": "OkResult"},
    "/api/v2/platform/workers": {"get": "map:WorkerInfo"},
    "/api/v2/platform/workers/{worker_id}/drain": {"post": "WorkerInfo"},
    "/api/v2/platform/vendor-profiles": {"get": "list:VendorProfileView"},
    "/api/v2/platform/capabilities": {"get": "list:CapabilityView"},
    "/api/v2/platform/assets": {"get": "list:PlatformAsset", "post": "Asset"},
    "/api/v2/platform/assets/assign": {"post": "AssetAssignment"},
    "/api/v2/platform/assets/grant": {"post": "PlatformGrantResult"},
    "/api/v2/platform/assets/{asset_id}/reset": {"post": "AssetResetResult"},
    "/api/v2/platform/audit": {"get": "list:AuditRow"},
    "/api/v2/platform/quota-usage": {"get": "list:QuotaUsage"},
    "/api/v2/platform/sessions": {"get": "list:SessionView"},
    "/api/v2/platform/sessions/{sid}/revoke": {"post": "SessionRevoked"},
    "/api/v2/integration/ping": {"get": "IntegrationPing"},
    "/api/v2/integration/assets": {"get": "IntegrationAssets"},
    "/api/v2/integration/console/open": {"post": "IntegrationConsoleOpen"},
    "/api/v2/integration/consoles/{sid}/close": {"post": "ConsoleCloseResult"},
}


def response_schema(spec: str) -> dict:
    shape, name = spec.split(":", 1) if ":" in spec else ("", spec)
    ref = {"$ref": f"#/components/schemas/{name}"}
    if shape == "list":
        return {"type": "array", "items": ref}
    if shape == "map":
        return {"type": "object", "additionalProperties": ref}
    return ref
