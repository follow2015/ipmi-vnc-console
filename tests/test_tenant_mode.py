"""Two tenant tiers: use-only (consumer) vs full management (manager)."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from kvmhub.platform import services
from kvmhub.platform.api import create_app
from kvmhub.platform.config import Settings
from kvmhub.platform.db import (bootstrap_platform_admin, init_schema, seed_roles,
                                transaction)
from kvmhub.platform.models import AuditLog, User
from kvmhub.platform.redis_state import MemoryState

KEY = b"0123456789abcdef0123456789abcdef"
ORIGIN = "http://testserver"
PASSWORD = "synthetic-password"


class Rig:
    def __init__(self, client):
        self.client = client
        self.platform = client.app.state.platform

    def login(self, username: str, *, platform: bool = False) -> dict:
        self.client.cookies.clear()
        path = "/api/v2/platform/login" if platform else "/api/v2/login"
        r = self.client.post(path, json={"username": username, "password": PASSWORD})
        assert r.status_code == 200, r.text
        return {"Origin": ORIGIN, "X-CSRF-Token": r.json()["csrf"]}

    def __getattr__(self, name):
        return getattr(self.client, name)

    def tenant(self, code: str) -> dict:
        return self.login(f"{code}-admin")

    def admin(self) -> dict:
        return self.login("root", platform=True)


@pytest.fixture
def rig():
    cfg = Settings(env="test", db_url="sqlite:///:memory:", redis_url="",
                   credential_key=KEY, session_ttl=3600, lease_seconds=30,
                   bootstrap_admin=None, bootstrap_password=None, strict_prod=False)
    app = create_app(cfg, state=MemoryState())
    platform = app.state.platform
    with transaction(platform.factory) as db:
        init_schema(platform.engine)
        seed_roles(db)
        bootstrap_platform_admin(db, "root", PASSWORD)
        tenants = {}
        for code, mode in (("use", "consumer"), ("manage", "manager")):
            tenant = services.create_tenant(db, code=code, name=code, mode=mode,
                                            actor="test")
            tenants[code] = tenant.id
            services.create_user(db, f"{code}-admin", PASSWORD, "admin",
                                 actor="test", tenant_id=tenant.id)
    with TestClient(app, base_url=ORIGIN) as client:
        yield Rig(client), tenants
    platform.engine.dispose()


def test_consumer_me_is_narrowed_but_manager_keeps_full_set(rig):
    client, tenants = rig
    h = client.tenant("use")
    perms = set(client.get("/api/v2/me", headers=h).json()["permissions"])
    assert {"asset.read", "console.open", "user.read", "user.write",
            "grant.write", "audit.read"} <= perms
    assert not ({"asset.write", "credential.write", "vendor.read",
                 "session.revoke", "vendor.approve"} & perms)

    h = client.tenant("manage")
    perms = set(client.get("/api/v2/me", headers=h).json()["permissions"])
    assert {"asset.write", "credential.write", "vendor.read", "session.revoke"} <= perms


def test_consumer_cannot_add_assets_or_credentials_but_can_manage_accounts(rig):
    client, _ = rig
    h = client.tenant("use")
    body = {"name": "assigned-ip", "address": "192.0.2.41"}
    assert client.post("/api/v2/assets", headers=h, json=body).status_code == 403
    assert client.get("/api/v2/assets?scope=all", headers=h).status_code == 403
    assert client.post("/api/v2/credentials", headers=h, json={}).status_code == 403
    assert client.get("/api/v2/vendor-profiles", headers=h).status_code == 403
    assert client.get("/api/v2/audit", headers=h).status_code == 200

    created = client.post("/api/v2/users", headers=h, json={
        "username": "local-user", "password": PASSWORD, "role": "viewer",
    })
    assert created.status_code == 200, created.text
    assert client.post(f"/api/v2/users/{created.json()['id']}/password",
                       headers=h, json={"password": "placeholder-new-password"})
    assert client.get("/api/v2/users", headers=h).status_code == 200


def test_manager_can_add_an_asset(rig):
    client, _ = rig
    h = client.tenant("manage")
    r = client.post("/api/v2/assets", headers=h, json={
        "name": "onboarded-ip", "address": "192.0.2.42",
    })
    assert r.status_code == 200, r.text


def test_platform_changes_mode_and_refuses_unknown_mode(rig):
    client, tenants = rig
    h = client.admin()
    r = client.patch(f"/api/v2/platform/tenants/{tenants['manage']}", headers=h,
                     json={"mode": "consumer"})
    assert r.status_code == 200, r.text
    assert r.json()["mode"] == "consumer"
    tenant_h = client.tenant("manage")
    assert client.post("/api/v2/assets", headers=tenant_h,
                       json={"name": "x", "address": "192.0.2.43"}).status_code == 403

    h = client.admin()
    assert client.post("/api/v2/platform/tenants", headers=h,
                       json={"code": "bad", "name": "bad", "mode": "super"}).status_code == 400


def test_platform_account_management_and_role_change(rig):
    client, tenants = rig
    h = client.admin()
    created = client.post(f"/api/v2/platform/tenants/{tenants['use']}/users",
                          headers=h, json={"username": "platform-made",
                                           "password": PASSWORD, "role": "viewer"})
    assert created.status_code == 200, created.text
    uid = created.json()["id"]

    assert client.post(f"/api/v2/platform/tenants/{tenants['use']}/users", headers=h,
                       json={"username": "must-fail", "password": PASSWORD,
                             "role": "platform_admin"}).status_code == 400

    h = client.login("platform-made")
    assert set(client.get("/api/v2/me", headers=h).json()["permissions"]) == {
        "asset.read", "audit.read",
    }

    h = client.admin()
    changed = client.patch(f"/api/v2/platform/users/{uid}/role", headers=h,
                           json={"role": "admin"})
    assert changed.status_code == 200, changed.text
    assert changed.json()["roles"] == ["admin"]

    h = client.login("platform-made")
    perms = set(client.get("/api/v2/me", headers=h).json()["permissions"])
    assert "user.write" in perms and "asset.write" not in perms

    assert client.post(f"/api/v2/platform/users/{uid}/active", headers=client.admin(),
                       json={"active": False}).status_code == 200
    assert client.post("/api/v2/login", json={"username": "platform-made",
                                              "password": PASSWORD}).status_code == 401


def test_tenant_cannot_mint_a_platform_role(rig):
    client, _ = rig
    h = client.tenant("manage")
    r = client.post("/api/v2/users", headers=h, json={
        "username": "escalate", "password": PASSWORD, "role": "platform_admin",
    })
    assert r.status_code == 400, r.text
    assert r.json()["error"] == "invalid_role"


def test_mode_changes_are_audited(rig):
    client, tenants = rig
    h = client.admin()
    client.patch(f"/api/v2/platform/tenants/{tenants['manage']}", headers=h,
                 json={"mode": "consumer"})
    with transaction(client.app.state.platform.factory) as db:
        rows = db.scalars(select(AuditLog).where(AuditLog.action == "tenant_updated")).all()
    assert any("mode" in (row.detail or "") and "consumer" in (row.detail or "")
               for row in rows)
