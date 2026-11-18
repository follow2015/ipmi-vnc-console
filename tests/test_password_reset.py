"""Password reset for local accounts, on both sides of the tenant boundary."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from kvmhub.platform import services
from kvmhub.platform.api import create_app
from kvmhub.platform.config import Settings
from kvmhub.platform.db import (bootstrap_platform_admin, init_schema, seed_roles,
                                transaction)
from kvmhub.platform.models import AuditLog
from kvmhub.platform.redis_state import MemoryState

KEY = b"0123456789abcdef0123456789abcdef"
ORIGIN = "http://testserver"

ROOT_PASSWORD = "synthetic-password"
TENANT_PASSWORD = "unit-test-password"
NEW_PASSWORD = "sim-password"


class Rig:
    def __init__(self, client, tenants, members):
        self.client = client
        self.tenants = tenants
        self.members = members
        self.platform = client.app.state.platform

    def login(self, username: str, password: str) -> dict:
        self.client.cookies.clear()
        path = "/api/v2/platform/login" if username == "root" else "/api/v2/login"
        r = self.client.post(path, json={"username": username, "password": password})
        assert r.status_code == 200, r.text
        return {"Origin": ORIGIN, "X-CSRF-Token": r.json()["csrf"]}

    def as_platform(self) -> dict:
        return self.login("root", ROOT_PASSWORD)

    def as_tenant(self, code: str = "alpha") -> dict:
        return self.login(f"{code}-admin", TENANT_PASSWORD)

    def as_viewer(self) -> dict:
        return self.login("alpha-viewer", TENANT_PASSWORD)


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
        bootstrap_platform_admin(db, "root", ROOT_PASSWORD)
        tenants, members = {}, {}
        for code in ("alpha", "bravo"):
            tenant = services.create_tenant(db, code=code, name=code, actor="test")
            tenants[code] = tenant.id
            services.create_user(db, f"{code}-admin", TENANT_PASSWORD, "admin",
                                 actor="test", tenant_id=tenant.id)
            member = services.create_user(db, f"{code}-member", TENANT_PASSWORD, "operator",
                                          actor="test", tenant_id=tenant.id)
            members[code] = member.id
        services.create_user(db, "alpha-viewer", TENANT_PASSWORD, "viewer",
                             actor="test", tenant_id=tenants["alpha"])
    with TestClient(app, base_url=ORIGIN) as client:
        yield Rig(client=client, tenants=tenants, members=members)
    platform.engine.dispose()



def test_tenant_admin_resets_password_and_revokes_every_session(rig):
    cookie_name = rig.platform.tenant_cookie_name
    live_cookies = []
    for _ in range(2):
        rig.login("alpha-member", TENANT_PASSWORD)
        live_cookies.append(rig.client.cookies.get(cookie_name))

    h = rig.as_tenant()
    r = rig.client.post(f"/api/v2/users/{rig.members['alpha']}/password",
                        headers=h, json={"password": NEW_PASSWORD})
    assert r.status_code == 200, r.text

    for cookie in live_cookies:
        rig.client.cookies.set(cookie_name, cookie)
        assert rig.client.get("/api/v2/me").status_code == 401

    rig.client.cookies.clear()
    assert rig.client.post("/api/v2/login", json={
        "username": "alpha-member", "password": TENANT_PASSWORD}).status_code == 401
    assert rig.client.post("/api/v2/login", json={
        "username": "alpha-member", "password": NEW_PASSWORD}).status_code == 200


def test_tenant_admin_cannot_reset_an_account_in_another_tenant(rig):
    h = rig.as_tenant("alpha")
    r = rig.client.post(f"/api/v2/users/{rig.members['bravo']}/password",
                        headers=h, json={"password": NEW_PASSWORD})
    assert r.status_code == 404, r.text
    assert r.json()["error"] == "user_not_found"


def test_tenant_viewer_cannot_reset_anything(rig):
    h = rig.as_viewer()
    assert rig.client.post(f"/api/v2/users/{rig.members['alpha']}/password",
                           headers=h, json={"password": NEW_PASSWORD}).status_code == 403


def test_blank_password_is_rejected_without_touching_the_account(rig):
    h = rig.as_tenant()
    assert rig.client.post(f"/api/v2/users/{rig.members['alpha']}/password",
                           headers=h, json={"password": "   "}).status_code == 400
    rig.client.cookies.clear()
    assert rig.client.post("/api/v2/login", json={
        "username": "alpha-member", "password": TENANT_PASSWORD}).status_code == 200


def test_tenant_reset_is_audited_against_the_target_tenant(rig):
    h = rig.as_tenant()
    assert rig.client.post(f"/api/v2/users/{rig.members['alpha']}/password",
                           headers=h, json={"password": NEW_PASSWORD}).status_code == 200
    with transaction(rig.platform.factory) as db:
        row = db.execute(select(AuditLog).where(
            AuditLog.action == "user_password_reset")).first()
    assert row is not None
    assert row[0].tenant_id == rig.tenants["alpha"]
    assert row[0].actor == "alpha-admin"



def test_platform_lists_one_tenants_accounts_and_refuses_a_blank_filter(rig):
    h = rig.as_platform()
    assert rig.client.get("/api/v2/platform/users", headers=h).status_code == 400
    r = rig.client.get("/api/v2/platform/users", headers=h,
                       params={"tenant_id": rig.tenants["alpha"]})
    assert r.status_code == 200, r.text
    names = {row["username"] for row in r.json()}
    assert {"alpha-admin", "alpha-member", "alpha-viewer"} <= names
    assert not any(name.startswith("bravo") for name in names)


def test_platform_admin_resets_an_account_in_any_tenant(rig):
    h = rig.as_platform()
    r = rig.client.post(f"/api/v2/platform/users/{rig.members['bravo']}/password",
                        headers=h, json={"password": NEW_PASSWORD})
    assert r.status_code == 200, r.text
    rig.client.cookies.clear()
    assert rig.client.post("/api/v2/login", json={
        "username": "bravo-member", "password": NEW_PASSWORD}).status_code == 200
    with transaction(rig.platform.factory) as db:
        row = db.execute(select(AuditLog).where(
            AuditLog.action == "user_password_reset")).first()
    assert row[0].tenant_id == rig.tenants["bravo"]
    assert row[0].actor_type == "platform"


def test_tenant_account_cannot_use_the_platform_user_routes(rig):
    h = rig.as_tenant()
    assert rig.client.get("/api/v2/platform/users", headers=h,
                          params={"tenant_id": rig.tenants["alpha"]}).status_code == 403
    assert rig.client.post(f"/api/v2/platform/users/{rig.members['alpha']}/password",
                           headers=h, json={"password": NEW_PASSWORD}).status_code == 403
