"""Platform BMC cold-reset: authority, CSRF, auditing and secret hygiene."""
from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from kvmhub.platform import bmc_reset, services
from kvmhub.platform.api import create_app
from kvmhub.platform.config import Settings
from kvmhub.platform.db import bootstrap_platform_admin, init_schema, seed_roles, transaction
from kvmhub.platform.redis_state import MemoryState

KEY = b"0123456789abcdef0123456789abcdef"
PASSWORD = "synthetic-password"
ORIGIN = "http://testserver"
ASSET_IP = "192.0.2.55"


def cfg_for(db_url: str) -> Settings:
    return Settings(env="test", db_url=db_url, redis_url="", credential_key=KEY,
                    session_ttl=3600, lease_seconds=30, bootstrap_admin=None,
                    bootstrap_password=None, strict_prod=False)


@pytest.fixture
def rig(tmp_path):
    cfg = cfg_for(f"sqlite:///{tmp_path}/control.db")
    state = MemoryState()
    app = create_app(cfg, state=state, plane=None)
    platform = app.state.platform
    with transaction(platform.factory) as db:
        init_schema(platform.engine)
        seed_roles(db)
        services.create_user(db, "tenant-admin", PASSWORD, "admin", actor="test",
                             tenant_id=services.create_tenant(
                                 db, code="globex", name="Globex", actor="test").id)
        bootstrap_platform_admin(db, "platform", PASSWORD)
        cred = services.save_credential(db, platform.cipher, label="bmc", username="ADMIN",
                                        password="synthetic-password", actor="test",
                                        tenant_id=None)
        asset = services.upsert_asset(db, name="node-1", address=ASSET_IP,
                                      credential_id=cred.id, actor="test")
        asset_id = asset.id
    with TestClient(app, base_url=ORIGIN) as client:
        yield SimpleNamespace(client=client, platform=platform, asset_id=asset_id)
        platform.engine.dispose()


def login(rig, username: str) -> str:
    path = "/api/v2/platform/login" if username == "platform" else "/api/v2/login"
    body = {"username": username, "password": PASSWORD}
    if username != "platform":
        body["tenant_code"] = "globex"
    response = rig.client.post(path, json=body)
    assert response.status_code == 200, response.text
    return response.json()["csrf"]


def headers(csrf: str) -> dict:
    return {"Origin": ORIGIN, "X-CSRF-Token": csrf}


def test_platform_admin_can_reset(monkeypatch, rig):
    seen = {}

    async def fake(address, username, password, **kw):
        seen.update(address=address, username=username, password=password)
        return {"accepted": True, "result": "cold"}

    monkeypatch.setattr(bmc_reset, "cold_reset_bmc", fake)
    csrf = login(rig, "platform")
    response = rig.client.post(f"/api/v2/platform/assets/{rig.asset_id}/reset",
                               headers=headers(csrf))
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["ok"] is True and body["accepted"] is True
    assert body["address"] == ASSET_IP and body["method"] == "ipmi-cold-reset"
    assert seen["address"] == ASSET_IP
    assert seen["username"] == "ADMIN" and seen["password"] == "synthetic-password"
    assert "password" not in body and "username" not in body


def test_reset_writes_an_audit_row_without_secrets(monkeypatch, rig):
    async def fake(address, username, password, **kw):
        return {"accepted": True, "result": "cold"}
    monkeypatch.setattr(bmc_reset, "cold_reset_bmc", fake)
    csrf = login(rig, "platform")
    rig.client.post(f"/api/v2/platform/assets/{rig.asset_id}/reset", headers=headers(csrf))
    with transaction(rig.platform.factory) as db:
        rows = services.recent_audit(db, 20)
    row = next(r for r in rows if r["action"] == "asset.bmc_reset")
    assert row["actor"] == "platform" and row["actor_type"] == "platform"
    assert row["detail"]["asset_id"] == rig.asset_id
    assert "password" not in str(row["detail"]).lower()


def test_reset_failure_is_normalised_and_audited(monkeypatch, rig):
    async def fake(address, username, password, **kw):
        raise bmc_reset.ResetError("ipmi_auth_failed", "nope")
    monkeypatch.setattr(bmc_reset, "cold_reset_bmc", fake)
    csrf = login(rig, "platform")
    response = rig.client.post(f"/api/v2/platform/assets/{rig.asset_id}/reset",
                               headers=headers(csrf))
    assert response.status_code == 502, response.text
    assert response.json()["error"] == "ipmi_auth_failed"
    with transaction(rig.platform.factory) as db:
        rows = services.recent_audit(db, 20)
    assert any(r["action"] == "asset.bmc_reset_failed" for r in rows)


def test_tenant_cannot_reach_platform_reset(rig):
    csrf = login(rig, "tenant-admin")
    response = rig.client.post(f"/api/v2/platform/assets/{rig.asset_id}/reset",
                               headers=headers(csrf))
    assert response.status_code == 403, response.text


def test_reset_requires_csrf(rig):
    csrf = login(rig, "platform")
    response = rig.client.post(f"/api/v2/platform/assets/{rig.asset_id}/reset",
                               headers={"Origin": ORIGIN})
    assert response.status_code == 403, response.text


def test_reset_of_unknown_asset_is_404(rig):
    csrf = login(rig, "platform")
    response = rig.client.post("/api/v2/platform/assets/does-not-exist/reset",
                               headers=headers(csrf))
    assert response.status_code == 404, response.text



def test_reset_module_rejects_non_ip_addresses():
    with pytest.raises(bmc_reset.ResetError) as exc:
        asyncio.run(bmc_reset.cold_reset_bmc("192.0.2.24; curl evil", "u", "p"))
    assert exc.value.code == "bmc_address_invalid"


def test_cold_reset_calls_pyghmi_reset_bmc_not_set_power(monkeypatch):
    import sys
    from types import ModuleType

    calls = []

    class FakeCommand:
        def __init__(self, **kw):
            calls.append(("init", kw.get("bmc")))
        def reset_bmc(self):
            calls.append(("reset_bmc",))
            return "ok"
        def set_power(self, *a, **k):
            raise AssertionError("set_power must never be called — that cuts host power")

    fake_pkg = ModuleType("pyghmi")
    fake_ipmi = ModuleType("pyghmi.ipmi")
    fake_cmd = ModuleType("pyghmi.ipmi.command")
    fake_cmd.Command = FakeCommand
    monkeypatch.setitem(sys.modules, "pyghmi", fake_pkg)
    monkeypatch.setitem(sys.modules, "pyghmi.ipmi", fake_ipmi)
    monkeypatch.setitem(sys.modules, "pyghmi.ipmi.command", fake_cmd)

    result = bmc_reset._cold_reset_sync("192.0.2.32", "u", "p", 5)
    assert result["accepted"] is True
    assert ("init", "192.0.2.32") in calls and ("reset_bmc",) in calls


def test_reset_module_accepts_ipv6_literal(monkeypatch):
    seen = {}

    def fake_sync(address, username, password, timeout):
        seen["address"] = address
        return {"accepted": True, "result": "cold"}
    monkeypatch.setattr(bmc_reset, "_cold_reset_sync", fake_sync)
    result = asyncio.run(bmc_reset.cold_reset_bmc("2001:db8::1", "u", "p"))
    assert result["accepted"] is True and seen["address"] == "2001:db8::1"


def test_reset_module_timeout_is_normalised(monkeypatch):
    import time as _time

    def slow_sync(*args, **kw):
        _time.sleep(1)
    monkeypatch.setattr(bmc_reset, "_cold_reset_sync", slow_sync)
    monkeypatch.setattr(bmc_reset, "WAIT_MARGIN", 0.01)
    with pytest.raises(bmc_reset.ResetError) as exc:
        asyncio.run(bmc_reset.cold_reset_bmc("192.0.2.1", "u", "p", timeout=0.01))
    assert exc.value.code == "ipmi_timeout"
