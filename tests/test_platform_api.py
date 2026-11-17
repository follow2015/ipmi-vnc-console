"""HTTP-level tests for the production control plane."""
from __future__ import annotations

import base64

import pytest
from fastapi.testclient import TestClient

from kvmhub.platform import services, vendor_registry
from kvmhub.platform.api import create_app
from kvmhub.platform.config import Settings
from kvmhub.platform.db import init_schema, seed_roles, session_factory, transaction
from kvmhub.platform.redis_state import MemoryState
from kvmhub.platform.security import CredentialCipher

KEY = b"0123456789abcdef0123456789abcdef"
ORIGIN = "http://testserver"

ADMIN_PASSWORD = "synthetic-password"
VIEWER_PASSWORD = "unit-test-password"
BMC_PASSWORD = "local-admin"


@pytest.fixture
def client():
    cfg = Settings(env="test", db_url="sqlite:///:memory:", redis_url="",
                   credential_key=KEY, session_ttl=3600, lease_seconds=30,
                   bootstrap_admin=None, bootstrap_password=None, strict_prod=False)
    state = MemoryState()
    app = create_app(cfg, state=state)
    platform = app.state.platform
    with transaction(platform.factory) as db:
        init_schema(platform.engine)
        seed_roles(db)
        vendor_registry.seed_builtin_profiles(db)
        services.create_user(db, "admin", ADMIN_PASSWORD, "admin", actor="test")
        services.create_user(db, "viewer", VIEWER_PASSWORD, "viewer", actor="test")
    with TestClient(app, base_url=ORIGIN) as c:
        yield c
    platform.engine.dispose()


def login(c: TestClient, username="admin", password=ADMIN_PASSWORD):
    r = c.post("/api/v2/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return r.json()["csrf"]


def headers(csrf, **extra):
    return {"Origin": ORIGIN, "X-CSRF-Token": csrf, **extra}


def test_health_and_readiness_are_public(client):
    assert client.get("/healthz").json()["status"] == "ok"
    ready = client.get("/readyz")
    assert ready.status_code == 200, ready.text
    assert ready.json()["checks"] == {"database": True, "state": True, "credential_key": True}


def test_login_me_logout_and_csrf(client):
    assert client.get("/api/v2/me").status_code == 401
    assert client.post("/api/v2/login", json={"username": "admin", "password": "wrong"}).status_code == 401
    csrf = login(client)
    me = client.get("/api/v2/me").json()
    assert me["username"] == "admin" and "user.write" in me["permissions"]
    assert client.get("/api/v2/users").json()
    assert client.post("/api/v2/users", headers={"Origin": ORIGIN},
                       json={"username": "x", "password": ADMIN_PASSWORD}).status_code == 403
    assert client.post("/api/v2/logout", headers=headers(csrf)).json() == {"ok": True}
    assert client.get("/api/v2/me").status_code == 401


def test_viewer_cannot_create_assets_or_open_consoles(client):
    csrf = login(client, "viewer", VIEWER_PASSWORD)
    me = client.get("/api/v2/me").json()
    assert "asset.write" not in me["permissions"]
    r = client.post("/api/v2/assets", headers=headers(csrf),
                    json={"name": "node", "address": "192.0.2.11"})
    assert r.status_code == 403 and r.json()["error"] == "permission_denied"


def test_credentials_are_write_only_and_assets_never_echo_them(client):
    csrf = login(client)
    r = client.post("/api/v2/credentials", headers=headers(csrf),
                    json={"label": "bmc-01", "username": "ADMIN", "password": BMC_PASSWORD})
    assert r.status_code == 200, r.text
    cred = r.json()
    assert set(cred) >= {"id", "label", "key_version"}
    assert "password" not in r.text and BMC_PASSWORD not in r.text
    asset = client.post("/api/v2/assets", headers=headers(csrf),
                        json={"name": "node-1", "address": "192.0.2.11",
                              "credential_id": cred["id"], "vendor": "supermicro"}).json()
    assert "credential" not in asset and BMC_PASSWORD not in str(asset)
    listed = client.get("/api/v2/assets").json()
    assert [row["name"] for row in listed] == ["node-1"]
    assert "credential" not in str(listed) and BMC_PASSWORD not in str(listed)


def test_a_tenant_device_is_visible_to_every_account_in_that_tenant(client):
    csrf = login(client)
    client.post("/api/v2/assets", headers=headers(csrf),
                json={"name": "node-1", "address": "192.0.2.11"})
    client.post("/api/v2/logout", headers=headers(csrf))
    login(client, "viewer", VIEWER_PASSWORD)
    assert [a["name"] for a in client.get("/api/v2/assets").json()] == ["node-1"]
    assert client.get("/api/v2/assets?scope=granted").json() == []


def test_detect_reports_a_draft_and_never_self_approves(client):
    csrf = login(client)
    inventory = {"resources": {"Managers": [
        {"Id": "1", "Manufacturer": "Supermicro (Inspur OEM)",
         "Model": "X10DRT-PS", "FirmwareVersion": "8.78"}]}}
    r = client.post("/api/v2/detect", headers=headers(csrf), json={"inventory": inventory})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["detection"]["vendor"] == "supermicro"
    assert body["matched"] is True and body["usable"] is False
    assert body["reason"] == "matched_but_not_approved"
    assert body["capability_draft_id"] is None and body["connection_plan"] is None
    assert client.get("/api/v2/vendor-profiles").json()[0]["status"] == "draft"


def test_detect_refuses_an_unknown_brand(client):
    csrf = login(client)
    r = client.post("/api/v2/detect", headers=headers(csrf),
                    json={"inventory": {"resources": {"Managers": [
                        {"Manufacturer": "Acme Unknown", "Model": "X10DRT-PS",
                         "FirmwareVersion": "8.78"}]}}})
    assert r.status_code == 200
    assert r.json()["matched"] is False and r.json()["reason"] == "unknown_vendor"


def test_text_plan_preflight_flags_the_pipe(client):
    csrf = login(client)
    r = client.post("/api/v2/text-plan", headers=headers(csrf),
                    json={"text": "echo root:abc | chpasswd\n"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["has_broken"] is True
    assert any(w["level"] == "known_broken" and "↔" in w["message"] for w in body["warnings"])
    assert body["counts"]["keystrokes"] == body["counts"]["total_chars"]
    matrix = client.get("/api/v2/text-input/matrix").json()
    assert "|" in matrix["levels"]["known_broken"]
    assert "A" in matrix["levels"]["verified"] and "!" in matrix["levels"]["verified"]
    assert "|" not in matrix["levels"]["verified"]


def test_audit_records_the_sensitive_operations(client):
    csrf = login(client)
    client.post("/api/v2/credentials", headers=headers(csrf),
                json={"label": "bmc-01", "username": "ADMIN", "password": BMC_PASSWORD})
    actions = [row["action"] for row in client.get("/api/v2/audit").json()]
    assert "credential_created" in actions and "login_succeeded" in actions
    assert BMC_PASSWORD not in str(client.get("/api/v2/audit").json())


def test_worker_roster_is_not_polluted_by_readiness_probes(client):
    csrf = login(client)
    client.get("/readyz")
    assert "__healthcheck__" not in client.get("/api/v2/workers").json()


def test_me_hands_back_the_csrf_token_so_a_reload_can_still_write(client):
    csrf = login(client)
    me = client.get("/api/v2/me").json()
    assert me["csrf"] == csrf
    r = client.post("/api/v2/assets", headers=headers(me["csrf"]),
                    json={"name": "after-reload", "address": "192.0.2.12"})
    assert r.status_code == 200, r.text


def test_an_unauthenticated_me_never_returns_a_token(client):
    r = client.get("/api/v2/me")
    assert r.status_code == 401 and "csrf" not in r.text


def test_the_default_list_is_the_whole_tenant_fleet(client):
    csrf = login(client)
    created = client.post("/api/v2/assets", headers=headers(csrf),
                          json={"name": "ungranted", "address": "192.0.2.60"}).json()
    listed = client.get("/api/v2/assets").json()
    assert [row["name"] for row in listed] == ["ungranted"]
    assert listed[0]["grant_expires"] is None
    assert listed[0]["id"] == created["id"]
    assert client.get("/api/v2/assets?scope=granted").json() == []
    assert [row["name"] for row in client.get("/api/v2/assets?scope=all").json()] == ["ungranted"]


def test_the_management_scope_is_refused_to_a_read_only_account(client):
    login(client, "viewer", VIEWER_PASSWORD)
    r = client.get("/api/v2/assets?scope=all")
    assert r.status_code == 403 and r.json()["error"] == "permission_denied"


def test_an_unknown_scope_is_rejected_rather_than_silently_widening(client):
    csrf = login(client)
    r = client.get("/api/v2/assets?scope=everything")
    assert r.status_code == 400 and r.json()["error"] == "scope_invalid"


def test_deactivation_revokes_all_existing_sessions_and_reactivation_does_not_restore_them(client):
    platform = client.app.state.platform
    with transaction(platform.factory) as db:
        user = services.create_user(db, "operator", ADMIN_PASSWORD, "operator", actor="test")
        user_id = user.id
    cookies = []
    tokens = []
    for _ in range(2):
        tokens.append(login(client, "operator", ADMIN_PASSWORD))
        cookies.append(client.cookies.get(platform.tenant_cookie_name))
    admin_csrf = login(client)
    assert client.post(f"/api/v2/users/{user_id}/active", headers=headers(admin_csrf),
                       json={"active": False}).status_code == 200
    admin_cookie = client.cookies.get(platform.tenant_cookie_name)
    for cookie, csrf in zip(cookies, tokens):
        client.cookies.set(platform.tenant_cookie_name, cookie)
        assert client.get("/api/v2/me").status_code == 401
        r = client.post("/api/v2/assets", headers=headers(csrf),
                        json={"name": "disabled-write", "address": "192.0.2.99"})
        assert r.status_code == 401
    client.cookies.set(platform.tenant_cookie_name, admin_cookie)
    assert client.post(f"/api/v2/users/{user_id}/active", headers=headers(admin_csrf),
                       json={"active": True}).status_code == 200
    for cookie in cookies:
        client.cookies.set(platform.tenant_cookie_name, cookie)
        assert client.get("/api/v2/me").status_code == 401
    client.cookies.clear()
    login(client, "operator", ADMIN_PASSWORD)
    assert client.get("/api/v2/me").status_code == 200


def test_current_rechecks_accounts_changed_outside_the_http_api(client):
    csrf = login(client)
    uid = client.get("/api/v2/me").json()["user_id"]
    with transaction(client.app.state.platform.factory) as db:
        services.set_user_active(db, uid, False, actor="out-of-band")
    assert client.get("/api/v2/me").status_code == 401
    assert client.get("/api/v2/assets?scope=all").status_code == 401
    assert client.post("/api/v2/assets", headers=headers(csrf),
                       json={"name": "disabled-write", "address": "192.0.2.99"}).status_code == 401
