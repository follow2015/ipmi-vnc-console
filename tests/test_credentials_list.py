"""BMC credential management: an operator must be able to *see* the credentials"""
from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

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
        yield SimpleNamespace(client=client, platform=platform, tenants=tenants)
    platform.engine.dispose()


def _login(fleet, code: str) -> dict:
    fleet.client.cookies.clear()
    r = fleet.client.post("/api/v2/login",
                          json={"username": f"{code}-admin", "password": TENANT_PASSWORD})
    assert r.status_code == 200, r.text
    return {"Origin": ORIGIN, "X-CSRF-Token": r.json()["csrf"]}


def _create(fleet, headers: dict, label: str) -> str:
    r = fleet.client.post("/api/v2/credentials", headers=headers,
                          json={"label": label, "username": "ADMIN", "password": "local-admin"})
    assert r.status_code == 200, r.text
    return r.json()["id"]


def test_credentials_list_returns_labels_without_secrets(fleet):
    headers = _login(fleet, "alpha")
    cred_id = _create(fleet, headers, "bmc-row-01")

    r = fleet.client.get("/api/v2/credentials", headers=headers)

    assert r.status_code == 200, r.text
    rows = r.json()
    assert isinstance(rows, list)
    row = next(row for row in rows if row["id"] == cred_id)
    assert row["label"] == "bmc-row-01"
    forbidden = {"username", "password", "username_cipher", "password_cipher",
                 "tenant_id", "created_by"}
    assert not (forbidden & set(row)), row


def test_credentials_list_is_scoped_to_the_callers_tenant(fleet):
    alpha = _login(fleet, "alpha")
    alpha_id = _create(fleet, alpha, "alpha-only")
    bravo = _login(fleet, "bravo")
    bravo_id = _create(fleet, bravo, "bravo-only")

    alpha = _login(fleet, "alpha")
    alpha_rows = fleet.client.get("/api/v2/credentials", headers=alpha).json()
    bravo = _login(fleet, "bravo")
    bravo_rows = fleet.client.get("/api/v2/credentials", headers=bravo).json()

    assert alpha_id in {row["id"] for row in alpha_rows}
    assert bravo_id not in {row["id"] for row in alpha_rows}
    assert bravo_id in {row["id"] for row in bravo_rows}
    assert alpha_id not in {row["id"] for row in bravo_rows}


def test_credentials_list_requires_credential_write(fleet):
    with transaction(fleet.platform.factory) as db:
        services.create_user(db, "alpha-viewer", TENANT_PASSWORD, "viewer",
                             actor="test", tenant_id=fleet.tenants["alpha"])
    fleet.client.cookies.clear()
    r = fleet.client.post("/api/v2/login",
                          json={"username": "alpha-viewer", "password": TENANT_PASSWORD})
    assert r.status_code == 200, r.text
    headers = {"Origin": ORIGIN, "X-CSRF-Token": r.json()["csrf"]}

    got = fleet.client.get("/api/v2/credentials", headers=headers)

    assert got.status_code == 403, got.text
