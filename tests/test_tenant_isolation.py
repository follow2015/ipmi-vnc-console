"""Multi-tenant isolation (design §4)."""
from __future__ import annotations

import asyncio
import importlib.util
import json
import os
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from kvmhub.common import Problem
from kvmhub.platform import services
from kvmhub.platform.api import create_app
from kvmhub.platform.config import Settings
from kvmhub.platform.data_plane import verify_tenant
from kvmhub.platform.db import (bootstrap_admin, bootstrap_platform_admin,
                                init_schema, seed_roles, session_factory, transaction)
from kvmhub.platform.models import DEFAULT_TENANT_ID, Asset, Credential, User
from kvmhub.platform.redis_state import MemoryState
from kvmhub.platform.security import CredentialCipher, new_session_token, token_digest
import sqlalchemy as sa
from sqlalchemy import select

ROOT = Path(__file__).resolve().parents[1]
KEY = b"0123456789abcdef0123456789abcdef"
ORIGIN = "http://testserver"

ADMIN_PASSWORD = "synthetic-password"
PLATFORM_PASSWORD = "synthetic-password"
BMC_PASSWORD = "synthetic-password"


@pytest.fixture
def env():
    cfg = Settings(env="test", db_url="sqlite:///:memory:", redis_url="",
                   credential_key=KEY, session_ttl=3600, lease_seconds=30,
                   bootstrap_admin=None, bootstrap_password=None, strict_prod=False)
    app = create_app(cfg, state=MemoryState())
    platform = app.state.platform
    with transaction(platform.factory) as db:
        init_schema(platform.engine)
        seed_roles(db)
        acme = services.create_tenant(db, code="acme", name="Acme", actor="test")
        globex = services.create_tenant(db, code="globex", name="Globex", actor="test")
        services.create_user(db, "admin", ADMIN_PASSWORD, "admin", actor="test",
                             tenant_id=acme.id)
        services.create_user(db, "admin", ADMIN_PASSWORD, "admin", actor="test",
                             tenant_id=globex.id)
        bootstrap_platform_admin(db, "platform", PLATFORM_PASSWORD)
        globex_cred = services.save_credential(db, CredentialCipher(KEY), label="g",
                                               username="u", password="p", actor="test",
                                               tenant_id=globex.id)
        acme_cred = services.save_credential(db, CredentialCipher(KEY), label="a",
                                             username="u", password="p", actor="test",
                                             tenant_id=acme.id)
        services.upsert_asset(db, name="acme-bmc", address="192.0.2.11",
                             credential_id=acme_cred.id, actor="test", tenant_id=acme.id)
        services.upsert_asset(db, name="globex-bmc", address="192.0.2.12",
                             credential_id=globex_cred.id, actor="test", tenant_id=globex.id)
    with TestClient(app, base_url=ORIGIN) as client:
        yield {"client": client, "app": app, "platform": platform,
               "acme": acme.id, "globex": globex.id}
    platform.engine.dispose()


def login(client, password, tenant_code="", username="admin"):
    body = {"username": username, "password": password}
    path = "/api/v2/login"
    if username == "platform":
        path = "/api/v2/platform/login"
    elif tenant_code:
        body["tenant_code"] = tenant_code
    return client.post(path, json=body)


def signed_in(env, tenant_code="", username="admin", password=ADMIN_PASSWORD):
    client = env["client"]
    client.cookies.clear()
    response = login(client, password, tenant_code, username)
    assert response.status_code == 200, response.text
    return response.json()["csrf"]


def write_headers(csrf):
    return {"Origin": ORIGIN, "X-CSRF-Token": csrf}



def test_same_username_exists_once_per_tenant(env):
    acme = signed_in(env, "acme")
    assert env["client"].get("/api/v2/me").json()["tenant_id"] == env["acme"]
    globex = signed_in(env, "globex")
    assert env["client"].get("/api/v2/me").json()["tenant_id"] == env["globex"]
    assert acme != globex


def test_ambiguous_username_without_tenant_code_is_refused(env):
    response = login(env["client"], ADMIN_PASSWORD)
    assert response.status_code == 400
    assert response.json()["error"] == "tenant_required"


def test_platform_account_logs_in_without_a_tenant(env):
    response = login(env["client"], PLATFORM_PASSWORD, username="platform")
    assert response.status_code == 200, response.text
    assert response.json()["tenant_id"] is None
    me = env["client"].get("/api/v2/platform/me").json()
    assert me["tenant_id"] is None
    assert any(code.startswith("platform.") for code in me["permissions"])


def test_wrong_tenant_code_is_a_plain_auth_failure(env):
    response = login(env["client"], ADMIN_PASSWORD, "globex", username="nobody")
    assert response.status_code == 401
    response = login(env["client"], "wrong-password", "acme")
    assert response.status_code == 401



def test_assets_do_not_cross_tenant_boundaries(env):
    signed_in(env, "acme")
    rows = env["client"].get("/api/v2/assets?scope=all").json()
    assert [row["address"] for row in rows] == ["192.0.2.11"]
    signed_in(env, "globex")
    rows = env["client"].get("/api/v2/assets?scope=all").json()
    assert [row["address"] for row in rows] == ["192.0.2.12"]


def test_asset_cannot_bind_another_tenants_credential(env):
    with transaction(env["platform"].factory) as db:
        foreign_cred = db.scalar(select(Credential).where(Credential.tenant_id == env["globex"]))
    with pytest.raises(services.PlatformError) as exc:
        with transaction(env["platform"].factory) as db:
            services.upsert_asset(db, name="acme-stolen", address="192.0.2.99",
                                  credential_id=foreign_cred.id, actor="test",
                                  tenant_id=env["acme"])
    assert exc.value.code == "cross_tenant_credential"
    assert exc.value.status == 403


def test_same_address_in_two_tenants_is_two_rows(env):
    with transaction(env["platform"].factory) as db:
        services.upsert_asset(db, name="acme-2", address="192.0.2.12", actor="test",
                              tenant_id=env["acme"])
        rows = db.scalars(select(Asset).where(Asset.address == "192.0.2.12")).all()
    assert {row.tenant_id for row in rows} == {env["acme"], env["globex"]}


def test_cross_tenant_grant_and_disable_are_not_found(env):
    signed_in(env, "acme")
    with transaction(env["platform"].factory) as db:
        globex_asset = db.scalar(select(Asset).where(Asset.tenant_id == env["globex"]))
        acme_user = db.scalar(select(User).where(User.tenant_id == env["acme"]))
        globex_user = db.scalar(select(User).where(User.tenant_id == env["globex"]))
    with pytest.raises(services.PlatformError) as exc:
        with transaction(env["platform"].factory) as db:
            services.grant_asset(db, user_id=acme_user.id, asset_id=globex_asset.id,
                                 actor="test", tenant_id=env["acme"])
    assert exc.value.code == "grant_target_missing"
    with pytest.raises(services.PlatformError) as exc:
        with transaction(env["platform"].factory) as db:
            services.set_user_active(db, globex_user.id, False, actor="test",
                                     tenant_id=env["acme"])
    assert exc.value.code == "user_not_found"


def test_user_list_is_scoped_to_the_calling_tenant(env):
    signed_in(env, "acme")
    names = [row["username"] for row in env["client"].get("/api/v2/users").json()]
    assert names == ["admin"]



def test_tenant_session_cannot_reach_the_platform_namespace(env):
    signed_in(env, "acme")
    response = env["client"].get("/api/v2/platform/tenants")
    assert response.status_code == 403
    assert response.json()["error"] == "platform_access_denied"


def test_platform_session_cannot_reach_tenant_routes(env):
    response = login(env["client"], PLATFORM_PASSWORD, username="platform")
    assert response.status_code == 200
    for path in ("/api/v2/assets", "/api/v2/users", "/api/v2/audit"):
        response = env["client"].get(path)
        assert response.status_code == 403, path
        assert response.json()["error"] == "platform_account_requires_platform_api"


def test_the_two_entrances_mint_different_cookies(env):
    client, platform = env["client"], env["platform"]
    client.cookies.clear()
    assert login(client, ADMIN_PASSWORD, "acme").status_code == 200
    assert client.cookies.get(platform.tenant_cookie_name)
    assert client.cookies.get(platform.admin_cookie_name) is None
    client.cookies.clear()
    assert login(client, PLATFORM_PASSWORD, username="platform").status_code == 200
    assert client.cookies.get(platform.admin_cookie_name)
    assert client.cookies.get(platform.tenant_cookie_name) is None


def test_neither_entrance_accepts_the_other_account(env):
    client = env["client"]
    response = client.post("/api/v2/login",
                           json={"username": "platform", "password": PLATFORM_PASSWORD})
    assert response.status_code == 403
    assert response.json()["error"] == "platform_account_requires_platform_login"

    with transaction(env["platform"].factory) as db:
        services.create_user(db, "solo-admin", ADMIN_PASSWORD, "admin", actor="test",
                             tenant_id=env["acme"])
    response = client.post("/api/v2/platform/login",
                           json={"username": "solo-admin", "password": ADMIN_PASSWORD})
    assert response.status_code == 403
    assert response.json()["error"] == "platform_access_denied"


def test_admin_logout_does_not_sign_out_the_tenant_tab(env):
    client, platform = env["client"], env["platform"]
    client.cookies.clear()
    admin_csrf = login(client, PLATFORM_PASSWORD, username="platform").json()["csrf"]
    assert login(client, ADMIN_PASSWORD, "acme").status_code == 200
    tenant_cookie = client.cookies.get(platform.tenant_cookie_name)
    assert tenant_cookie

    response = client.post("/api/v2/platform/logout",
                            headers={"Origin": ORIGIN, "X-CSRF-Token": admin_csrf})
    assert response.status_code == 200, response.text
    assert client.cookies.get(platform.admin_cookie_name) is None
    assert client.cookies.get(platform.tenant_cookie_name) == tenant_cookie
    assert client.get("/api/v2/me").status_code == 200
    assert client.get("/api/v2/platform/me").status_code == 403


def _park_platform_account_in_tenant_cookie(env):
    client, platform = env["client"], env["platform"]
    client.cookies.clear()
    assert login(client, ADMIN_PASSWORD, "acme").status_code == 200
    token = client.cookies.get(platform.tenant_cookie_name)
    with transaction(platform.factory) as db:
        platform_user = db.scalar(select(User).where(User.tenant_id.is_(None)))

    async def seed():
        await platform.state.put_session(
            token_digest(token),
            {"user_id": platform_user.id, "username": platform_user.username,
             "roles": ["platform_admin"], "csrf": new_session_token(),
             "tenant_id": None, "expires": time.time() + 3600}, 3600)

    asyncio.run(seed())
    return token


def test_legacy_platform_cookie_in_tenant_channel_heals_on_me(env):
    client, platform = env["client"], env["platform"]
    token = _park_platform_account_in_tenant_cookie(env)

    me = client.get("/api/v2/me")
    assert me.status_code == 401
    assert me.json()["error"] == "authentication_required"
    assert any(platform.tenant_cookie_name in h and "Max-Age=0" in h
               for h in me.headers.get_list("set-cookie"))
    assert client.cookies.get(platform.tenant_cookie_name) is None

    async def gone():
        return await platform.state.get_session(token_digest(token))

    assert asyncio.run(gone()) is None
    assert client.get("/api/v2/me").status_code == 401


def test_logout_clears_legacy_cookie_without_csrf(env):
    client, platform = env["client"], env["platform"]
    _park_platform_account_in_tenant_cookie(env)

    response = client.post("/api/v2/logout")
    assert response.status_code == 200, response.text
    assert client.cookies.get(platform.tenant_cookie_name) is None


def test_platform_can_enumerate_tenants_and_their_counts(env):
    login(env["client"], PLATFORM_PASSWORD, username="platform")
    rows = {row["code"]: row for row in env["client"].get("/api/v2/platform/tenants").json()}
    assert {"acme", "globex", "default"} <= set(rows)
    assert rows["acme"]["assets"] == 1 and rows["acme"]["users"] == 1


def test_platform_can_create_and_suspend_a_tenant(env):
    response = login(env["client"], PLATFORM_PASSWORD, username="platform")
    csrf = response.json()["csrf"]
    created = env["client"].post("/api/v2/platform/tenants", headers=write_headers(csrf),
                                 json={"code": "initech", "name": "Initech"}).json()
    assert created["status"] == "active"
    suspended = env["client"].post(
        f"/api/v2/platform/tenants/{created['id']}/status",
        headers=write_headers(csrf), json={"status": "suspended"}).json()
    assert suspended["status"] == "suspended"
    with transaction(env["platform"].factory) as db:
        services.create_user(db, "boss", ADMIN_PASSWORD, "admin", actor="test",
                             tenant_id=created["id"])
    assert login(env["client"], ADMIN_PASSWORD, "initech", "boss").status_code == 403


def test_the_default_tenant_cannot_be_suspended(env):
    csrf = login(env["client"], PLATFORM_PASSWORD, username="platform").json()["csrf"]
    response = env["client"].post(
        f"/api/v2/platform/tenants/{DEFAULT_TENANT_ID}/status",
        headers=write_headers(csrf), json={"status": "suspended"})
    assert response.status_code == 400
    assert response.json()["error"] == "default_tenant_protected"


def test_platform_asset_view_is_read_only_and_hides_credential_ids(env):
    login(env["client"], PLATFORM_PASSWORD, username="platform")
    rows = env["client"].get("/api/v2/platform/assets").json()
    assert {row["address"] for row in rows} == {"192.0.2.11", "192.0.2.12"}
    assert all("credential_id" not in row for row in rows)
    assert env["client"].post("/api/v2/platform/assets", json={}).status_code in (401, 403)



def test_audit_is_scoped_and_platform_audit_strips_secret_detail(env):
    csrf = signed_in(env, "acme")
    with transaction(env["platform"].factory) as db:
        services.save_credential(db, CredentialCipher(KEY), label="acme-2",
                                 username="svc", password=BMC_PASSWORD, actor="admin",
                                 tenant_id=env["acme"])
    assert env["client"].post("/api/v2/logout", headers=write_headers(csrf)).json() == {"ok": True}
    csrf = signed_in(env, "globex")
    rows = env["client"].get("/api/v2/audit").json()
    assert rows and all(row["tenant_id"] == env["globex"] for row in rows)

    csrf = login(env["client"], PLATFORM_PASSWORD, username="platform").json()["csrf"]
    all_rows = env["client"].get("/api/v2/platform/audit", headers=write_headers(csrf)).json()
    assert {row["tenant_id"] for row in all_rows} >= {env["acme"], env["globex"]}
    for row in all_rows:
        assert "password" not in row["detail"] and "username" not in row["detail"]



def test_ticket_carries_the_tenant_and_the_worker_checks_it():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from kvmhub.common import issue, verify

    private = Ed25519PrivateKey.generate()
    public = private.public_key()
    now = time.time()
    row = {"id": "a" * 32, "jti": "b" * 32, "user_id": "u", "asset_id": "asset",
           "worker_id": "w1", "instance_id": "i1", "hard_until": now + 600}
    token = issue(private, row, now, tenant_id="tenant-a")
    claims = verify(public, token, "w1", "i1")
    assert claims["tid"] == "tenant-a"

    verify_tenant({"tenant_id": "tenant-a"}, "tenant-a")
    with pytest.raises(Problem) as exc:
        verify_tenant({"tenant_id": "tenant-b"}, "tenant-a")
    assert exc.value.code == "invalid_target_policy"
    with pytest.raises(Problem):
        verify_tenant({"tenant_id": "tenant-a"}, "")


def test_single_tenant_tickets_stay_wire_compatible():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from kvmhub.common import issue, verify

    private = Ed25519PrivateKey.generate()
    now = time.time()
    row = {"id": "a" * 32, "jti": "b" * 32, "user_id": "u", "asset_id": "asset",
           "worker_id": "w1", "instance_id": "i1", "hard_until": now + 600}
    claims = verify(private.public_key(), issue(private, row, now), "w1", "i1")
    assert "tid" not in claims



LEGACY_SCHEMA = """
CREATE TABLE kvm_user (
    id VARCHAR(36) PRIMARY KEY,
    username VARCHAR(128) NOT NULL UNIQUE,
    display_name VARCHAR(128), password_hash VARCHAR(128) NOT NULL,
    is_active BOOLEAN, failed_attempts INTEGER, locked_until FLOAT,
    created FLOAT NOT NULL, last_login FLOAT);
CREATE TABLE kvm_asset (
    id VARCHAR(36) PRIMARY KEY, name VARCHAR(256) NOT NULL,
    address VARCHAR(256) NOT NULL, vendor VARCHAR(128), model VARCHAR(128),
    firmware VARCHAR(64), fingerprint VARCHAR(128), credential_id VARCHAR(36),
    profile_id VARCHAR(36), capability_id VARCHAR(36), licence VARCHAR(128),
    status VARCHAR(32), notes TEXT, created FLOAT NOT NULL, updated FLOAT NOT NULL);
CREATE INDEX ix_kvm_asset_address ON kvm_asset (address);
CREATE TABLE kvm_credential (
    id VARCHAR(36) PRIMARY KEY, label VARCHAR(128) NOT NULL,
    username_cipher BLOB NOT NULL, password_cipher BLOB NOT NULL,
    key_version INTEGER, created_by VARCHAR(128), created FLOAT NOT NULL,
    rotated_at FLOAT);
CREATE TABLE kvm_access_grant (
    user_id VARCHAR(36) NOT NULL, asset_id VARCHAR(36) NOT NULL,
    expires FLOAT NOT NULL, granted_by VARCHAR(128), created FLOAT NOT NULL,
    PRIMARY KEY (user_id, asset_id));
CREATE TABLE kvm_audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts FLOAT NOT NULL,
    trace_id VARCHAR(64), actor VARCHAR(128) NOT NULL, action VARCHAR(96) NOT NULL,
    asset_id VARCHAR(36), detail TEXT);
CREATE TABLE kvm_vendor_profile (
    id VARCHAR(36) PRIMARY KEY, code VARCHAR(96) NOT NULL UNIQUE,
    vendor VARCHAR(128) NOT NULL, status VARCHAR(32), created FLOAT NOT NULL);
CREATE TABLE kvm_capability (
    id VARCHAR(36) PRIMARY KEY, vendor VARCHAR(128) NOT NULL,
    model VARCHAR(128) NOT NULL, firmware VARCHAR(64) NOT NULL,
    adapter VARCHAR(128) NOT NULL, status VARCHAR(32), created FLOAT NOT NULL);
INSERT INTO kvm_user (id, username, password_hash, is_active, failed_attempts,
                      locked_until, created)
    VALUES ('u1', 'admin', 'x', 1, 0, 0, 1.0);
INSERT INTO kvm_asset (id, name, address, created, updated)
    VALUES ('a1', 'legacy-bmc', '192.0.2.9', 1.0, 1.0);
INSERT INTO kvm_credential (id, label, username_cipher, password_cipher, key_version, created)
    VALUES ('c1', 'legacy', x'00', x'00', 1, 1.0);
INSERT INTO kvm_access_grant (user_id, asset_id, expires, created)
    VALUES ('u1', 'a1', 9999999999.0, 1.0);
INSERT INTO kvm_audit_log (ts, actor, action, detail) VALUES (1.0, 'admin', 'asset_created', '{}');
INSERT INTO kvm_vendor_profile (id, code, vendor, status, created)
    VALUES ('p1', 'legacy-profile', 'supermicro', 'approved', 1.0);
INSERT INTO kvm_capability (id, vendor, model, firmware, adapter, status, created)
    VALUES ('k1', 'supermicro', 'X10', '1.0', 'passthrough', 'verified', 1.0);
CREATE TABLE alembic_version (version_num VARCHAR(32) NOT NULL PRIMARY KEY);
INSERT INTO alembic_version (version_num) VALUES ('0001_baseline');
"""


def _legacy_db(path: Path) -> None:
    conn = sqlite3.connect(path)
    try:
        conn.executescript(LEGACY_SCHEMA)
        conn.commit()
    finally:
        conn.close()


def _alembic(db_path: Path, *args: str) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env["KVMHUB_ENV"] = "test"
    env["KVMHUB_DB_URL"] = f"sqlite:///{db_path.as_posix()}"
    env.pop("MYSQL_HOST", None)
    return subprocess.run([sys.executable, "-m", "alembic", "-c", "alembic.ini", *args],
                          cwd=str(ROOT), env=env, capture_output=True, text=True)


def _public_ip_migration():
    path = ROOT / "migrations" / "versions" / "0011_public_ip_alias_unique.py"
    spec = importlib.util.spec_from_file_location("m0011_public_ip_alias", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_migration_0011_reports_legacy_duplicate_claims(capsys):
    migration = _public_ip_migration()
    engine = sa.create_engine("sqlite:///:memory:")
    with engine.begin() as conn:
        conn.exec_driver_sql(
            "CREATE TABLE kvm_public_ip (id TEXT PRIMARY KEY, tenant_id TEXT, "
            "asset_id TEXT, primary_ip TEXT, additional_ips TEXT, "
            "created REAL, updated REAL)")
        conn.exec_driver_sql(
            "CREATE TABLE kvm_public_ip_alias (id TEXT PRIMARY KEY, "
            "tenant_id TEXT NOT NULL, ip TEXT NOT NULL, asset_id TEXT NOT NULL, "
            "mapping_id TEXT NOT NULL, created REAL NOT NULL, updated REAL NOT NULL)")
        conn.execute(migration._PUBLIC_IP.insert(), [
            {"id": "m1", "tenant_id": "t1", "asset_id": "a1",
             "primary_ip": "203.0.113.10", "additional_ips": "",
             "created": 1.0, "updated": 1.0},
            {"id": "m2", "tenant_id": "t1", "asset_id": "a2",
             "primary_ip": "203.0.113.10", "additional_ips": "",
             "created": 2.0, "updated": 2.0},
        ])
        migration.backfill_aliases(conn)

    out = capsys.readouterr().out
    assert "duplicate public IP claim" in out
    assert "m2" in out
    with engine.connect() as conn:
        rows = conn.execute(sa.select(migration._ALIAS)).mappings().all()
    assert len(rows) == 1 and rows[0]["mapping_id"] == "m1"
    engine.dispose()


def test_legacy_database_upgrades_in_place(tmp_path):
    db_path = tmp_path / "legacy.db"
    _legacy_db(db_path)

    completed = _alembic(db_path, "upgrade", "head")
    assert completed.returncode == 0, completed.stdout + completed.stderr

    with sqlite3.connect(db_path) as conn:
        tenants = conn.execute("SELECT id, code FROM kvm_tenant").fetchall()
        assert tenants == [(DEFAULT_TENANT_ID, "default")]
        for table in ("kvm_user", "kvm_asset", "kvm_credential",
                      "kvm_access_grant", "kvm_audit_log"):
            values = {row[0] for row in conn.execute(f"SELECT tenant_id FROM {table}")}
            assert values == {DEFAULT_TENANT_ID}, table
        for table in ("kvm_vendor_profile", "kvm_capability"):
            values = {row[0] for row in conn.execute(f"SELECT tenant_id FROM {table}")}
            assert values == {None}, table
        assert {row[0] for row in conn.execute(
            "SELECT actor_type FROM kvm_audit_log")} == {"user"}
        asset_columns = {row[1] for row in conn.execute("PRAGMA table_info(kvm_asset)")}
        assert {"vnc_username_cipher", "vnc_password_cipher",
                "vnc_key_version"} <= asset_columns
        with sqlite3.connect(db_path) as check:
            check.execute("INSERT INTO kvm_user (id, tenant_id, username, password_hash, "
                          "is_active, failed_attempts, locked_until, created) "
                          "VALUES ('u2', 'other-tenant', 'admin', 'x', 1, 0, 0, 1.0)")
        with pytest.raises(sqlite3.IntegrityError):
            with sqlite3.connect(db_path) as check:
                check.execute("INSERT INTO kvm_user (id, tenant_id, username, password_hash, "
                              "is_active, failed_attempts, locked_until, created) "
                              "VALUES ('u3', :tid, 'admin', 'x', 1, 0, 0, 1.0)",
                              {"tid": DEFAULT_TENANT_ID})

    from sqlalchemy import create_engine

    engine = create_engine(f"sqlite:///{db_path.as_posix()}")
    init_schema(engine)
    factory = session_factory(engine)
    with transaction(factory) as db:
        assert db.scalar(select(User.username).where(User.tenant_id == DEFAULT_TENANT_ID)) == "admin"
        assert seed_roles(db)["roles"] >= 1
    engine.dispose()


def test_migration_reports_its_head_and_downgrade_is_reversible(tmp_path):
    db_path = tmp_path / "roundtrip.db"
    _legacy_db(db_path)
    assert _alembic(db_path, "upgrade", "head").returncode == 0
    head = _alembic(db_path, "current")
    assert "0016_profile_overlay (head)" in head.stdout + head.stderr
    down = _alembic(db_path, "downgrade", "0001_baseline")
    assert down.returncode == 0, down.stdout + down.stderr
    with sqlite3.connect(db_path) as conn:
        assert not conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='kvm_quota_usage'").fetchall()
        columns = {row[1] for row in conn.execute("PRAGMA table_info(kvm_user)")}
        assert "tenant_id" not in columns
        assert not conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='kvm_tenant'").fetchall()
