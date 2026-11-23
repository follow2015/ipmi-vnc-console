"""Tenant-facing public IPs are query labels, never connection targets."""
from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from kvmhub.platform import public_ip, services
from kvmhub.platform.api import create_app
from kvmhub.platform.config import Settings
from kvmhub.platform.db import init_schema, seed_roles, session_factory, transaction
from kvmhub.platform.models import Asset, PublicIpAlias
from kvmhub.platform.redis_state import MemoryState

KEY = b"0123456789abcdef0123456789abcdef"
ORIGIN = "http://testserver"
ADMIN_PASSWORD = "synthetic-password"
VIEWER_PASSWORD = "local-admin"


@pytest.fixture
def world(tmp_path):
    cfg = Settings(env="test", db_url=f"sqlite:///{tmp_path}/control.db", redis_url="",
                   credential_key=KEY, session_ttl=3600, lease_seconds=30,
                   bootstrap_admin=None, bootstrap_password=None, strict_prod=False)
    app = create_app(cfg, state=MemoryState())
    platform = app.state.platform
    with transaction(platform.factory) as db:
        init_schema(platform.engine)
        seed_roles(db)
        services.create_user(db, "admin", ADMIN_PASSWORD, "admin", actor="test")
        services.create_user(db, "viewer", VIEWER_PASSWORD, "viewer", actor="test")
    with TestClient(app, base_url=ORIGIN) as c:
        r = c.post("/api/v2/login", json={"username": "admin", "password": ADMIN_PASSWORD})
        assert r.status_code == 200, r.text
        admin_csrf = r.json()["csrf"]
        v = TestClient(app, base_url=ORIGIN)
        rv = v.post("/api/v2/login", json={"username": "viewer", "password": VIEWER_PASSWORD})
        assert rv.status_code == 200, rv.text
        yield c, admin_csrf, v, rv.json()["csrf"], platform
    platform.engine.dispose()


def _h(csrf):
    return {"Origin": ORIGIN, "X-CSRF-Token": csrf}


def _create_asset(c, csrf, name, ipmi, **extra):
    body = {"name": name, "address": ipmi, **extra}
    r = c.post("/api/v2/assets", headers=_h(csrf), json=body)
    assert r.status_code == 200, r.text
    return r.json()


def test_normalize_splits_dedupes_and_orders():
    ips = public_ip.normalize_public_ips("203.0.113.10, 203.0.113.11;203.0.113.10\n198.51.100.7")
    assert ips == ["203.0.113.10", "203.0.113.11", "198.51.100.7"]


def test_normalize_accepts_hostname_and_rejects_garbage():
    assert public_ip.normalize_public_ips(["bmc.example.com"]) == ["bmc.example.com"]
    with pytest.raises(Exception) as exc:
        public_ip.normalize_public_ips("bad..host")
    assert "public_ip_invalid" in str(exc.value)


def test_normalize_dedupes_hostnames_case_insensitively():
    assert public_ip.normalize_public_ips("A.com,a.com,BMc.Example.COM") == [
        "A.com", "BMc.Example.COM"]


def test_normalize_rejects_dotted_numeric_non_ip():
    with pytest.raises(Exception) as exc:
        public_ip.normalize_public_ips("999.999.999.999")
    assert "public_ip_invalid" in str(exc.value)


def test_asset_entry_writes_aliases_and_exposes_them(world):
    c, csrf, _, _, _ = world
    asset = _create_asset(c, csrf, "web-01", "192.0.2.24",
                          public_ips="203.0.113.10,203.0.113.11")
    assert asset["public_ip"] == "203.0.113.10"
    assert asset["public_ips"] == ["203.0.113.10", "203.0.113.11"]
    assert asset["address"] == "192.0.2.24"


def test_public_ips_endpoint_lists_only_aliases(world):
    c, csrf, _, _, _ = world
    _create_asset(c, csrf, "web-01", "192.0.2.24", public_ips="203.0.113.10")
    rows = c.get("/api/v2/public-ips").json()
    assert len(rows) == 1
    assert rows[0]["primary_ip"] == "203.0.113.10"
    assert rows[0]["public_ips"] == ["203.0.113.10"]
    assert "address" not in rows[0]


def test_put_replaces_aliases_by_row_id(world):
    c, csrf, _, _, platform = world
    asset = _create_asset(c, csrf, "web-01", "192.0.2.24", public_ips="203.0.113.10")
    r = c.put(f"/api/v2/public-ips/{asset['id']}", headers=_h(csrf),
              json={"public_ips": "198.51.100.9,198.51.100.10"})
    assert r.status_code == 200, r.text
    assert r.json()["public_ips"] == ["198.51.100.9", "198.51.100.10"]


def test_ipmi_edit_by_row_id_keeps_mapping(world):
    c, csrf, _, _, _ = world
    asset = _create_asset(c, csrf, "web-01", "192.0.2.24", public_ips="203.0.113.10")
    r = c.post("/api/v2/assets", headers=_h(csrf), json={
        "id": asset["id"], "name": "web-01", "address": "192.0.2.99",
    })
    assert r.status_code == 200, r.text
    assert r.json()["address"] == "192.0.2.99"
    assert r.json()["public_ips"] == ["203.0.113.10"]
    rows = c.get("/api/v2/public-ips").json()
    assert rows[0]["asset_id"] == asset["id"]


def test_end_user_never_sees_ipmi_but_sees_public(world):
    c, csrf, viewer, vcsrf, services_ = world
    _create_asset(c, csrf, "web-01", "192.0.2.24", public_ips="203.0.113.10")
    rows = viewer.get("/api/v2/assets").json()
    assert len(rows) == 1
    assert rows[0]["public_ip"] == "203.0.113.10"
    assert "address" not in rows[0], "IPMI leaked to an end user"
    manager_rows = c.get("/api/v2/assets?scope=all").json()
    assert manager_rows[0]["address"] == "192.0.2.24"


def test_viewer_cannot_maintain_public_ips(world):
    c, csrf, viewer, vcsrf, platform = world
    asset = _create_asset(c, csrf, "web-01", "192.0.2.24", public_ips="203.0.113.10")
    r = viewer.put(f"/api/v2/public-ips/{asset['id']}", headers=_h(vcsrf),
                   json={"public_ips": "198.51.100.9"})
    assert r.status_code == 403


def test_duplicate_public_ip_in_tenant_refused(world):
    c, csrf, _, _, _ = world
    _create_asset(c, csrf, "web-01", "192.0.2.24", public_ips="203.0.113.10")
    r = c.post("/api/v2/assets", headers=_h(csrf), json={
        "name": "web-02", "address": "192.0.2.25", "public_ips": "203.0.113.10"})
    assert r.status_code == 409
    assert r.json()["error"] == "public_ip_conflict"


def test_lookup_by_ipmi_or_public_alias(world):
    c, csrf, _, _, platform = world
    a = _create_asset(c, csrf, "web-01", "192.0.2.24", public_ips="203.0.113.10,203.0.113.11")
    with transaction(platform.factory) as db:
        assert public_ip.asset_by_public_ip(db, None, "192.0.2.24").id == a["id"]
        assert public_ip.asset_by_public_ip(db, None, "203.0.113.11").id == a["id"]
        assert public_ip.asset_by_public_ip(db, None, "192.0.2.99") is None


def test_tenant_isolation_on_mapping(world, tmp_path):
    c, csrf, _, _, platform = world
    a = _create_asset(c, csrf, "web-01", "192.0.2.24", public_ips="203.0.113.10")
    with transaction(platform.factory) as db:
        other = services.create_tenant(db, code="other", name="other", actor="test")
        db.commit()
        other_id = other.id
    with transaction(platform.factory) as db:
        row = db.get(public_ip.PublicIpMapping, c.get("/api/v2/public-ips").json()[0]["id"])
        row.tenant_id = other_id
        db.commit()
    assert c.get("/api/v2/public-ips").json() == []
    with transaction(platform.factory) as db:
        default_id = services.DEFAULT_TENANT_ID
        assert public_ip.asset_by_public_ip(db, default_id, "203.0.113.10") is None
        assert public_ip.asset_by_public_ip(db, other_id, "203.0.113.10") is None


def test_assign_accepts_public_ip(world):
    c, csrf, _, _, platform = world
    a = _create_asset(c, csrf, "web-01", "192.0.2.24", public_ips="203.0.113.10")
    with transaction(platform.factory) as db:
        result = services.assign_asset(
            db, address="203.0.113.10", tenant_id=services.DEFAULT_TENANT_ID,
            actor="test")
    assert result["asset"]["id"] == a["id"]
    assert result["asset"]["address"] == "192.0.2.24"


def test_reassign_moves_public_ip_mapping_to_new_tenant(world):
    c, csrf, _, _, platform = world
    a = _create_asset(c, csrf, "web-01", "192.0.2.24", public_ips="203.0.113.10")
    with transaction(platform.factory) as db:
        other = services.create_tenant(db, code="other", name="other", actor="test")
        db.commit()
        other_id = other.id
    with transaction(platform.factory) as db:
        services.assign_asset(db, address="192.0.2.24", tenant_id=other_id,
                              actor="test", reassign=True)
    with transaction(platform.factory) as db:
        row = db.get(public_ip.PublicIpMapping,
                     public_ip.mapping_for_asset(db, a["id"]).id)
        assert row.tenant_id == other_id
        asset = db.get(Asset, a["id"])
        assert asset.tenant_id == other_id
        assert public_ip.asset_by_public_ip(db, other_id, "203.0.113.10").id == a["id"]
        assert public_ip.asset_by_public_ip(db, services.DEFAULT_TENANT_ID,
                                           "203.0.113.10") is None


def test_unassign_drops_public_ip_mapping(world):
    c, csrf, _, _, platform = world
    a = _create_asset(c, csrf, "web-01", "192.0.2.24", public_ips="203.0.113.10")
    with transaction(platform.factory) as db:
        services.assign_asset(db, address="192.0.2.24", tenant_id=None,
                              actor="test", reassign=True)
    with transaction(platform.factory) as db:
        assert public_ip.mapping_for_asset(db, a["id"]) is None
        assert public_ip.asset_by_public_ip(db, services.DEFAULT_TENANT_ID,
                                           "203.0.113.10") is None


def test_alias_rows_follow_mapping_lifecycle(world):
    c, csrf, _, _, platform = world
    a = _create_asset(c, csrf, "web-01", "192.0.2.24",
                      public_ips="203.0.113.10,203.0.113.11")
    with transaction(platform.factory) as db:
        rows = db.scalars(select(PublicIpAlias).where(
            PublicIpAlias.asset_id == a["id"])).all()
        assert sorted(row.ip for row in rows) == ["203.0.113.10", "203.0.113.11"]
        assert all(row.mapping_id == public_ip.mapping_for_asset(db, a["id"]).id
                   for row in rows)

    r = c.put(f"/api/v2/public-ips/{a['id']}", headers=_h(csrf),
              json={"public_ips": "198.51.100.9"})
    assert r.status_code == 200, r.text
    with transaction(platform.factory) as db:
        assert [row.ip for row in db.scalars(select(PublicIpAlias).where(
            PublicIpAlias.asset_id == a["id"])).all()] == ["198.51.100.9"]

    r = c.put(f"/api/v2/public-ips/{a['id']}", headers=_h(csrf),
              json={"public_ips": ""})
    assert r.status_code == 200, r.text
    with transaction(platform.factory) as db:
        assert db.scalars(select(PublicIpAlias).where(
            PublicIpAlias.asset_id == a["id"])).all() == []


def test_alias_table_rejects_race_duplicate_at_db_level(world):
    c, csrf, _, _, platform = world
    a = _create_asset(c, csrf, "web-01", "192.0.2.24", public_ips="203.0.113.10")
    b = _create_asset(c, csrf, "web-02", "192.0.2.25", public_ips="203.0.113.20")

    with pytest.raises(IntegrityError):
        with transaction(platform.factory) as db:
            mapping = public_ip.mapping_for_asset(db, b["id"])
            stamp = 1.0
            db.add(PublicIpAlias(
                id=str(uuid.uuid4()), tenant_id=services.DEFAULT_TENANT_ID,
                ip="203.0.113.10", asset_id=b["id"], mapping_id=mapping.id,
                created=stamp, updated=stamp))
            db.flush()
    with transaction(platform.factory) as db:
        owners = db.scalars(select(PublicIpAlias.asset_id).where(
            PublicIpAlias.ip == "203.0.113.10")).all()
        assert owners == [a["id"]]


def test_rehomed_aliases_follow_the_new_tenant(world):
    c, csrf, _, _, platform = world
    a = _create_asset(c, csrf, "web-01", "192.0.2.24", public_ips="203.0.113.10")
    with transaction(platform.factory) as db:
        other = services.create_tenant(db, code="other", name="other", actor="test")
        db.commit()
        other_id = other.id
    with transaction(platform.factory) as db:
        services.assign_asset(db, address="192.0.2.24", tenant_id=other_id,
                              actor="test", reassign=True)
    with transaction(platform.factory) as db:
        rows = db.scalars(select(PublicIpAlias).where(
            PublicIpAlias.asset_id == a["id"])).all()
        assert len(rows) == 1 and rows[0].tenant_id == other_id
