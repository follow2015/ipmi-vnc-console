"""Assigning a device to a tenant by IP, and what each side is allowed to see."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from kvmhub.platform import services
from kvmhub.platform.api import create_app
from kvmhub.platform.config import Settings
from kvmhub.platform.db import (bootstrap_platform_admin, init_schema, seed_roles,
                                transaction)
from kvmhub.platform.models import Asset, AuditLog
from kvmhub.platform.redis_state import MemoryState

KEY = b"0123456789abcdef0123456789abcdef"
ORIGIN = "http://testserver"

ROOT_PASSWORD = "synthetic-password"
TENANT_PASSWORD = "unit-test-password"


@pytest.fixture
def fleet():
    cfg = Settings(env="test", db_url="sqlite:///:memory:", redis_url="",
                   credential_key=KEY, session_ttl=3600, lease_seconds=30,
                   bootstrap_admin=None, bootstrap_password=None, strict_prod=False)
    app = create_app(cfg, state=MemoryState())
    platform = app.state.platform
    with transaction(platform.factory) as db:
        init_schema(platform.engine)
        seed_roles(db)
        bootstrap_platform_admin(db, "root", ROOT_PASSWORD)
        tenants = {}
        for code in ("alpha", "bravo"):
            tenant = services.create_tenant(db, code=code, name=code, actor="test")
            services.create_user(db, f"{code}-admin", TENANT_PASSWORD, "admin",
                                 actor="test", tenant_id=tenant.id)
            tenants[code] = tenant.id
    with TestClient(app, base_url=ORIGIN) as client:
        yield SimpleFleet(client=client, tenants=tenants)
    platform.engine.dispose()


class SimpleFleet:
    def __init__(self, *, client, tenants):
        self.client = client
        self.tenants = tenants

    def as_platform(self) -> dict:
        return self._login("root", ROOT_PASSWORD)

    def as_tenant(self, code: str) -> dict:
        return self._login(f"{code}-admin", TENANT_PASSWORD)

    def _login(self, username: str, password: str) -> dict:
        client = self.client
        client.cookies.clear()
        path = "/api/v2/platform/login" if username == "root" else "/api/v2/login"
        r = client.post(path, json={"username": username, "password": password})
        assert r.status_code == 200, r.text
        return {"Origin": ORIGIN, "X-CSRF-Token": r.json()["csrf"]}

    def assign(self, headers, **body):
        return self.client.post("/api/v2/platform/assets/assign", headers=headers, json=body)

    def addresses(self, headers) -> list[str]:
        rows = self.client.get("/api/v2/assets", headers=headers).json()
        assert isinstance(rows, list), rows
        return sorted(row["address"] for row in rows)



def test_assigning_an_address_creates_the_device_in_that_tenant(fleet):
    root = fleet.as_platform()
    r = fleet.assign(root, address="192.0.2.24", tenant_id=fleet.tenants["alpha"],
                     name="机房 A 第一台")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["action"] == "created"
    assert body["previous_tenant"] is None
    assert body["asset"]["tenant_id"] == fleet.tenants["alpha"]
    assert body["asset"]["name"] == "机房 A 第一台"

    assert fleet.addresses(fleet.as_tenant("alpha")) == ["192.0.2.24"]
    assert fleet.addresses(fleet.as_tenant("bravo")) == []


def test_the_same_assignment_twice_is_not_an_error(fleet):
    root = fleet.as_platform()
    fleet.assign(root, address="192.0.2.24", tenant_id=fleet.tenants["alpha"])
    again = fleet.assign(root, address="192.0.2.24", tenant_id=fleet.tenants["alpha"])
    assert again.status_code == 200
    assert again.json()["action"] == "unchanged"


def test_moving_another_tenants_device_needs_an_explicit_reassign(fleet):
    root = fleet.as_platform()
    fleet.assign(root, address="192.0.2.24", tenant_id=fleet.tenants["alpha"])

    refused = fleet.assign(root, address="192.0.2.24", tenant_id=fleet.tenants["bravo"])
    assert refused.status_code == 409
    assert refused.json()["error"] == "asset_owned_by_tenant"
    assert "alpha" in refused.json()["message"]

    moved = fleet.assign(root, address="192.0.2.24", tenant_id=fleet.tenants["bravo"],
                         reassign=True)
    assert moved.status_code == 200
    assert moved.json()["action"] == "moved"
    assert moved.json()["previous_tenant"] == "alpha"
    assert fleet.addresses(fleet.as_tenant("bravo")) == ["192.0.2.24"]
    assert fleet.addresses(fleet.as_tenant("alpha")) == []


def test_a_move_leaves_a_row_saying_where_it_came_from(fleet):
    root = fleet.as_platform()
    fleet.assign(root, address="192.0.2.11", tenant_id=fleet.tenants["alpha"])
    fleet.assign(root, address="192.0.2.11", tenant_id=fleet.tenants["bravo"], reassign=True)

    with transaction(fleet.client.app.state.platform.factory) as db:
        rows = db.scalars(select(AuditLog).where(AuditLog.action == "asset_moved")).all()
    assert len(rows) == 1
    assert '"from":"alpha"' in rows[0].detail and '"to":"bravo"' in rows[0].detail


def test_taking_a_device_back_returns_it_to_the_pool(fleet):
    root = fleet.as_platform()
    fleet.assign(root, address="192.0.2.24", tenant_id=fleet.tenants["alpha"])

    refused = fleet.assign(root, address="192.0.2.24", tenant_id="")
    assert refused.status_code == 409
    assert refused.json()["error"] == "asset_owned_by_tenant"

    back = fleet.assign(root, address="192.0.2.24", tenant_id="", reassign=True)
    assert back.status_code == 200 and back.json()["action"] == "unassigned"
    assert fleet.addresses(fleet.as_tenant("alpha")) == []

    root = fleet.as_platform()
    pooled = fleet.client.get("/api/v2/platform/assets", headers=root).json()
    assert [row["tenant_code"] for row in pooled if row["address"] == "192.0.2.24"] == [None]
    with transaction(fleet.client.app.state.platform.factory) as db:
        assert db.scalar(select(Asset.tenant_id).where(Asset.address == "192.0.2.24")) is None


def test_an_unknown_tenant_cannot_receive_a_device(fleet):
    root = fleet.as_platform()
    missing = fleet.assign(root, address="192.0.2.24", tenant_id="no-such-tenant")
    assert missing.status_code == 404 and missing.json()["error"] == "tenant_not_found"


def test_a_suspended_tenant_cannot_receive_a_device(fleet):
    root = fleet.as_platform()
    bravo = fleet.tenants["bravo"]
    assert fleet.client.post(f"/api/v2/platform/tenants/{bravo}/status", headers=root,
                             json={"status": "suspended"}).status_code == 200
    refused = fleet.assign(root, address="192.0.2.24", tenant_id=bravo)
    assert refused.status_code == 403 and refused.json()["error"] == "tenant_suspended"


def test_the_asset_quota_still_caps_what_a_tenant_may_hold(fleet):
    root = fleet.as_platform()
    alpha = fleet.tenants["alpha"]
    assert fleet.client.patch(f"/api/v2/platform/tenants/{alpha}", headers=root,
                              json={"quotas": {"max_assets": 1}}).status_code == 200
    assert fleet.assign(root, address="192.0.2.24", tenant_id=alpha).status_code == 200
    over = fleet.assign(root, address="192.0.2.11", tenant_id=alpha)
    assert over.status_code == 429 and over.json()["error"] == "quota_exceeded"


def test_a_tenant_account_cannot_touch_the_platform_route(fleet):
    alpha = fleet.as_tenant("alpha")
    refused = fleet.assign(alpha, address="192.0.2.24", tenant_id=fleet.tenants["bravo"])
    assert refused.status_code in (401, 403)


def test_the_pool_is_never_visible_to_a_tenant(fleet):
    root = fleet.as_platform()
    fleet.assign(root, address="192.0.2.11", tenant_id="")
    pooled = fleet.assign(root, address="192.0.2.11", tenant_id=fleet.tenants["alpha"])
    assert pooled.status_code == 200
    assert fleet.assign(root, address="192.0.2.11", tenant_id="").status_code == 409
    assert fleet.assign(root, address="192.0.2.11", tenant_id="",
                        reassign=True).status_code == 200
    assert fleet.addresses(fleet.as_tenant("alpha")) == []


def test_the_compatibility_row_follows_the_device(fleet):
    import time
    import uuid

    from kvmhub.platform.models import Capability

    root = fleet.as_platform()
    fleet.assign(root, address="192.0.2.11", tenant_id=fleet.tenants["alpha"])

    with transaction(fleet.client.app.state.platform.factory) as db:
        asset = db.scalar(select(Asset).where(Asset.address == "192.0.2.11"))
        db.add(Capability(id=str(uuid.uuid4()), tenant_id=fleet.tenants["alpha"],
                          vendor="Supermicro", model="X10DRT-PS", firmware="8.78",
                          adapter="passthrough", status="verified",
                          expires=time.time() + 86400, evidence="lab", approver="operator",
                          created=time.time()))
        db.flush()
        asset.capability_id = db.scalars(select(Capability)).first().id

    fleet.assign(root, address="192.0.2.11", tenant_id=fleet.tenants["bravo"], reassign=True)
    with transaction(fleet.client.app.state.platform.factory) as db:
        asset = db.scalar(select(Asset).where(Asset.address == "192.0.2.11"))
        capability = db.get(Capability, asset.capability_id)
        assert capability.tenant_id == fleet.tenants["bravo"]
        rehomed = db.scalars(select(AuditLog).where(AuditLog.action == "capability_rehomed")).all()
        assert len(rehomed) == 1 and '"from":"alpha"' in rehomed[0].detail

    fleet.assign(root, address="192.0.2.11", tenant_id="", reassign=True)
    with transaction(fleet.client.app.state.platform.factory) as db:
        asset = db.scalar(select(Asset).where(Asset.address == "192.0.2.11"))
        assert db.get(Capability, asset.capability_id).tenant_id is None


def test_the_bmc_secret_travels_with_the_device_but_a_shared_one_does_not(fleet):
    import time
    import uuid

    from kvmhub.platform.models import Credential

    root = fleet.as_platform()
    factory = fleet.client.app.state.platform.factory
    with transaction(factory) as db:
        cred = Credential(id=str(uuid.uuid4()), tenant_id=fleet.tenants["alpha"],
                          label="bmc-1", username_cipher=b"x", password_cipher=b"y",
                          key_version=1, created=time.time())
        db.add(cred)
        db.flush()
        for address in ("192.0.2.24", "192.0.2.11"):
            fleet.assign(root, address=address, tenant_id=fleet.tenants["alpha"])
        first = db.scalar(select(Asset).where(Asset.address == "192.0.2.24"))
        second = db.scalar(select(Asset).where(Asset.address == "192.0.2.11"))
        first.credential_id = cred.id
        second.credential_id = cred.id

    shared = fleet.assign(root, address="192.0.2.24", tenant_id=fleet.tenants["bravo"],
                          reassign=True)
    assert shared.status_code == 409 and shared.json()["error"] == "credential_shared"

    with transaction(factory) as db:
        second = db.scalar(select(Asset).where(Asset.address == "192.0.2.11"))
        second.credential_id = None
    moved = fleet.assign(root, address="192.0.2.24", tenant_id=fleet.tenants["bravo"],
                         reassign=True)
    assert moved.status_code == 200
    with transaction(factory) as db:
        cred = db.get(Credential, cred.id)
        assert cred.tenant_id == fleet.tenants["bravo"]
        rows = db.scalars(select(AuditLog).where(AuditLog.action == "credential_rehomed")).all()
        assert len(rows) == 1



def test_platform_can_record_a_full_device_into_a_tenant(fleet):
    root = fleet.as_platform()
    r = fleet.client.post("/api/v2/platform/assets", headers=root, json={
        "tenant_id": fleet.tenants["alpha"],
        "name": "rack-1", "address": "192.0.2.50",
        "vendor": "huawei", "model": "2288H V5", "firmware": "6.27",
        "public_ips": "203.0.113.10, 203.0.113.11",
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["address"] == "192.0.2.50"
    assert body["public_ips"] == ["203.0.113.10", "203.0.113.11"]
    alpha = fleet.as_tenant("alpha")
    assert fleet.addresses(alpha) == ["192.0.2.50"]
    bravo = fleet.as_tenant("bravo")
    assert fleet.addresses(bravo) == []


def test_platform_intake_needs_a_real_tenant_and_write_permission(fleet):
    root = fleet.as_platform()
    assert fleet.client.post("/api/v2/platform/assets", headers=root,
                             json={"tenant_id": "nope", "name": "x",
                                   "address": "192.0.2.51"}).status_code == 404
    assert fleet.client.post("/api/v2/platform/assets", headers=root,
                             json={"name": "x", "address": "192.0.2.51"}).status_code == 404
    alpha = fleet.as_tenant("alpha")
    r = fleet.client.post("/api/v2/platform/assets", headers=alpha, json={
        "tenant_id": fleet.tenants["alpha"], "name": "x", "address": "192.0.2.52"})
    assert r.status_code in (401, 403)


def test_platform_recorded_device_is_grantable_and_editable(fleet):
    root = fleet.as_platform()
    r = fleet.client.post("/api/v2/platform/assets", headers=root, json={
        "tenant_id": fleet.tenants["alpha"], "name": "rack-2",
        "address": "192.0.2.60"})
    assert r.status_code == 200, r.text
    asset_id = r.json()["id"]
    edit = fleet.client.post("/api/v2/platform/assets", headers=root, json={
        "tenant_id": fleet.tenants["alpha"], "id": asset_id,
        "name": "rack-2", "address": "192.0.2.61",
        "public_ips": "203.0.113.20"})
    assert edit.status_code == 200, edit.text
    assert edit.json()["id"] == asset_id
    assert edit.json()["public_ips"] == ["203.0.113.20"]
