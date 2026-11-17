"""Platform-channel administration: tenant quotas and the Worker pool."""
from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from kvmhub.platform import services
from kvmhub.platform.api import create_app
from kvmhub.platform.bus import AssemblyBus, BusError
from kvmhub.platform.config import Settings
from kvmhub.platform.db import bootstrap_platform_admin, init_schema, seed_roles, transaction
from kvmhub.platform.models import DEFAULT_TENANT_ID, Tenant
from kvmhub.platform.redis_state import MemoryState

KEY = b"0123456789abcdef0123456789abcdef"
PASSWORD = "synthetic-password"
ORIGIN = "http://testserver"


def cfg_for(db_url: str) -> Settings:
    return Settings(env="test", db_url=db_url, redis_url="", credential_key=KEY,
                    session_ttl=3600, lease_seconds=30, bootstrap_admin=None,
                    bootstrap_password=None, strict_prod=False)


@pytest.fixture
def rig(tmp_path):
    cfg = cfg_for(f"sqlite:///{tmp_path}/control.db")
    state = MemoryState()
    bus = AssemblyBus(state)
    app = create_app(cfg, state=state, plane=None)
    platform = app.state.platform
    with transaction(platform.factory) as db:
        init_schema(platform.engine)
        seed_roles(db)
        services.create_user(db, "admin", PASSWORD, "admin", actor="test")
        services.create_user(db, "globex-admin", PASSWORD, "admin", actor="test",
                             tenant_id=services.create_tenant(
                                 db, code="globex", name="Globex", actor="test").id)
        bootstrap_platform_admin(db, "platform", PASSWORD)
    asyncio.run(bus.register_worker("w1", instance_id="i1", capacity=4))
    with TestClient(app, base_url=ORIGIN) as client:
        yield SimpleNamespace(client=client, platform=platform, bus=bus)
        platform.engine.dispose()


def login(client: TestClient, username: str, tenant_code: str | None = None) -> str:
    body = {"username": username, "password": PASSWORD}
    if tenant_code:
        body["tenant_code"] = tenant_code
    response = client.post("/api/v2/login", json=body)
    assert response.status_code == 200, response.text
    return response.json()["csrf"]


def platform_login(rig) -> str:
    return login(rig.client, "platform")


def headers(csrf: str) -> dict:
    return {"Origin": ORIGIN, "X-CSRF-Token": csrf}


def tenant_row(rig, code: str = "globex") -> dict:
    rows = rig.client.get("/api/v2/platform/tenants",
                          headers={"Origin": ORIGIN}).json()
    return next(row for row in rows if row["code"] == code)


def test_quota_edit_normalises_and_is_visible_to_the_gate(rig):
    csrf = platform_login(rig)
    row = tenant_row(rig)
    response = rig.client.patch(f"/api/v2/platform/tenants/{row['id']}", json={
        "quotas": {"max_assets": "3", "max_concurrent_sessions": 0,
                   "max_session_minutes": None}},
        headers=headers(csrf))
    assert response.status_code == 200, response.text
    assert response.json()["quotas"] == {"max_assets": 3}
    assert tenant_row(rig)["quotas"] == {"max_assets": 3}

    with transaction(rig.platform.factory) as db:
        quotas = services.tenant_quotas(db, row["id"])
    assert services.quota_limit(quotas, "max_assets") == 3
    assert services.quota_limit(quotas, "max_concurrent_sessions") is None


def test_unknown_quota_key_is_refused_and_nothing_is_written(rig):
    csrf = platform_login(rig)
    row = tenant_row(rig)
    before = row["quotas"]
    response = rig.client.patch(f"/api/v2/platform/tenants/{row['id']}", json={
        "quotas": {"max_asset": 10}}, headers=headers(csrf))
    assert response.status_code == 400, response.text
    assert response.json()["error"] == "invalid_quota"
    assert tenant_row(rig)["quotas"] == before


@pytest.mark.parametrize("value", [-1, "many", True])
def test_invalid_quota_value_is_refused(rig, value):
    csrf = platform_login(rig)
    row = tenant_row(rig)
    response = rig.client.patch(f"/api/v2/platform/tenants/{row['id']}",
                                json={"quotas": {"max_assets": value}},
                                headers=headers(csrf))
    assert response.status_code == 400, response.text
    assert response.json()["error"] == "invalid_quota"


def test_quota_edit_writes_one_audit_row_with_before_and_after(rig):
    csrf = platform_login(rig)
    row = tenant_row(rig)
    rig.client.patch(f"/api/v2/platform/tenants/{row['id']}",
                     json={"quotas": {"max_assets": 5}}, headers=headers(csrf))
    rows = rig.client.get("/api/v2/platform/audit", headers={"Origin": ORIGIN}).json()
    entry = next(item for item in rows if item["action"] == "tenant_updated")
    assert entry["actor"] == "platform"
    assert entry["actor_type"] == "platform"
    assert entry["detail"]["before"]["quotas"] == {}
    assert entry["detail"]["after"]["quotas"] == {"max_assets": 5}


def test_rename_and_plan_are_accepted_but_blank_names_are_not(rig):
    csrf = platform_login(rig)
    row = tenant_row(rig)
    ok = rig.client.patch(f"/api/v2/platform/tenants/{row['id']}",
                          json={"name": "Globex Ltd", "plan": "enterprise"},
                          headers=headers(csrf))
    assert ok.status_code == 200, ok.text
    assert ok.json()["name"] == "Globex Ltd"
    assert ok.json()["plan"] == "enterprise"
    blank = rig.client.patch(f"/api/v2/platform/tenants/{row['id']}",
                             json={"name": "   "}, headers=headers(csrf))
    assert blank.status_code == 400
    assert blank.json()["error"] == "invalid_tenant_name"


def test_default_tenant_cannot_be_suspended_through_the_api(rig):
    csrf = platform_login(rig)
    default = tenant_row(rig, "default")
    response = rig.client.post(f"/api/v2/platform/tenants/{default['id']}/status",
                               json={"status": "suspended"}, headers=headers(csrf))
    assert response.status_code == 400
    assert response.json()["error"] == "default_tenant_protected"


def test_platform_can_suspend_and_resume_another_tenant(rig):
    csrf = platform_login(rig)
    row = tenant_row(rig)
    suspended = rig.client.post(f"/api/v2/platform/tenants/{row['id']}/status",
                                json={"status": "suspended"}, headers=headers(csrf))
    assert suspended.status_code == 200, suspended.text
    assert suspended.json()["status"] == "suspended"
    resumed = rig.client.post(f"/api/v2/platform/tenants/{row['id']}/status",
                              json={"status": "active"}, headers=headers(csrf))
    assert resumed.json()["status"] == "active"


def test_tenant_list_carries_live_usage_counters(rig):
    csrf = platform_login(rig)
    rows = rig.client.get("/api/v2/platform/tenants", headers={"Origin": ORIGIN}).json()
    by_code = {row["code"]: row for row in rows}
    assert by_code["globex"]["active_sessions"] == 0
    assert by_code["globex"]["users"] == 1
    assert by_code["default"]["users"] == 1
    assert csrf


def test_tenant_account_cannot_reach_any_platform_route(rig):
    csrf = login(rig.client, "admin")
    for method, path, body in (
        ("get", "/api/v2/platform/tenants", None),
        ("get", "/api/v2/platform/workers", None),
        ("patch", f"/api/v2/platform/tenants/{DEFAULT_TENANT_ID}", {"quotas": {}}),
        ("post", "/api/v2/platform/workers/w1/drain", {"draining": True}),
        ("post", "/api/v2/platform/tenants/whatever/status", {"status": "suspended"}),
    ):
        response = getattr(rig.client, method)(
            path, headers=headers(csrf), **({"json": body} if body is not None else {}))
        assert response.status_code == 403, (path, response.status_code, response.text)


def test_draining_a_worker_removes_it_from_placement_and_resuming_restores_it(rig):
    csrf = platform_login(rig)
    before = rig.client.get("/api/v2/platform/workers", headers={"Origin": ORIGIN}).json()
    assert before["w1"]["draining"] is False

    drained = rig.client.post("/api/v2/platform/workers/w1/drain",
                              json={"draining": True}, headers=headers(csrf))
    assert drained.status_code == 200, drained.text
    assert drained.json()["draining"] is True

    with pytest.raises(BusError) as refused:
        asyncio.run(rig.bus.choose_worker())
    assert refused.value.code == "worker_capacity_exhausted"

    resumed = rig.client.post("/api/v2/platform/workers/w1/drain",
                              json={"draining": False}, headers=headers(csrf))
    assert resumed.json()["draining"] is False
    assert asyncio.run(rig.bus.choose_worker())["worker_id"] == "w1"


def test_drain_is_audited(rig):
    csrf = platform_login(rig)
    rig.client.post("/api/v2/platform/workers/w1/drain", json={"draining": True},
                    headers=headers(csrf))
    rows = rig.client.get("/api/v2/platform/audit", headers={"Origin": ORIGIN}).json()
    entry = next(item for item in rows if item["action"] == "worker_drain_changed")
    assert entry["actor_type"] == "platform"
    assert entry["detail"] == {"worker_id": "w1", "draining": True}


def test_drain_rejects_a_non_boolean_and_an_unknown_worker(rig):
    csrf = platform_login(rig)
    wrong_type = rig.client.post("/api/v2/platform/workers/w1/drain",
                                 json={"draining": "yes"}, headers=headers(csrf))
    assert wrong_type.status_code == 400
    assert wrong_type.json()["error"] == "invalid_request"

    unknown = rig.client.post("/api/v2/platform/workers/ghost/drain",
                              json={"draining": True}, headers=headers(csrf))
    assert unknown.status_code == 404
    assert unknown.json()["error"] == "invalid_worker"


def test_platform_cannot_read_a_tenant_console_endpoint(rig):
    csrf = platform_login(rig)
    response = rig.client.get("/api/v2/assets", headers={"Origin": ORIGIN})
    assert response.status_code == 403
    assert csrf


def test_platform_tenant_view_never_exposes_a_quota_document_as_text(rig):
    csrf = platform_login(rig)
    row = tenant_row(rig)
    rig.client.patch(f"/api/v2/platform/tenants/{row['id']}",
                     json={"quotas": {"max_assets": 2}}, headers=headers(csrf))
    fresh = tenant_row(rig)
    assert isinstance(fresh["quotas"], dict)
    assert fresh["quotas"]["max_assets"] == 2
