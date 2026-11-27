"""Out-of-band tooling for stage 30: key rotation, capacity probe, asset sync."""
from __future__ import annotations

import asyncio
import base64
import json
import os
import time
import uuid
from contextlib import nullcontext
from types import SimpleNamespace

import pytest
from sqlalchemy import select

from kvmhub.platform import connection, services, vendor_registry
from kvmhub.platform.config import settings
from kvmhub.platform.db import init_schema, make_engine, seed_roles, session_factory, transaction
from kvmhub.platform.models import AccessGrant, Asset, Capability, Credential, VendorProfile
from kvmhub.platform.security import CredentialCipher
from kvmhub.store import Store
from tools import key_rotate, platform_admin, worker_capacity

OLD_KEY = b"0123456789abcdef0123456789abcdef"
NEW_KEY = b"fedcba9876543210fedcba9876543210"
DATA_KEY = b"aaaabbbbccccddddaaaabbbbccccdddd"
ADMIN_PASSWORD = "synthetic-password"
BMC_USERNAME = "synthetic-user"
BMC_PASSWORD = "local-admin"
PROFILE_CODE = "smci-x10-ast2100-rfb003008"
MANUFACTURER = "Supermicro (Inspur OEM)"
FINGERPRINT = "ab1eed64" * 8



@pytest.fixture
def credential_db(tmp_path):
    cfg_path = tmp_path / "control.db"
    engine = make_engine(f"sqlite:///{cfg_path}")
    init_schema(engine)
    factory = session_factory(engine)
    old = CredentialCipher(OLD_KEY)
    with transaction(factory) as db:
        seed_roles(db)
        ids = []
        for index in range(3):
            cred = services.save_credential(db, old, label=f"bmc-{index}",
                                            username=BMC_USERNAME,
                                            password=BMC_PASSWORD, actor="test")
            ids.append(cred.id)
    yield engine, factory, old, ids
    engine.dispose()


def test_rotation_reencrypts_every_row_and_bumps_the_version(credential_db):
    engine, factory, old, ids = credential_db
    new = CredentialCipher(NEW_KEY)
    with transaction(factory) as db:
        result = key_rotate.rotate(db, old, new, write=True, actor="operator", stamp=time.time())
    assert result["rows"] == 3 and result["key_versions_before"] == [1]
    assert result["key_version_after"] == 2
    with transaction(factory) as db:
        rows = db.scalars(select(Credential)).all()
        assert all(row.key_version == 2 and row.rotated_at for row in rows)
        assert key_rotate.verify_all(db, new)["ok"] is True
        assert len(key_rotate.verify_all(db, old)["undecryptable"]) == 3
        assert services.read_credential(db, new, ids[0])["password"] == BMC_PASSWORD


def test_aad_binding_survives_rotation(credential_db):
    engine, factory, old, _ = credential_db
    new = CredentialCipher(NEW_KEY)
    with transaction(factory) as db:
        key_rotate.rotate(db, old, new, write=True, actor="operator", stamp=time.time())
        row = db.scalars(select(Credential)).first()
        with pytest.raises(Exception):
            new.decrypt(row.password_cipher, aad="another-row:password")


def test_dry_run_writes_nothing(credential_db):
    engine, factory, old, _ = credential_db
    new = CredentialCipher(NEW_KEY)
    with transaction(factory) as db:
        result = key_rotate.rotate(db, old, new, write=False, actor="operator", stamp=time.time())
    assert result["rows"] == 3 and result["written"] is False
    with transaction(factory) as db:
        assert all(row.key_version == 1 for row in db.scalars(select(Credential)).all())


def test_a_failure_midway_rolls_back_the_whole_batch(credential_db, monkeypatch):
    engine, factory, old, _ = credential_db
    new = CredentialCipher(NEW_KEY)
    original = new.encrypt
    calls = {"n": 0}

    def failing(plaintext, *, aad):
        calls["n"] += 1
        if calls["n"] == 3:
            raise RuntimeError("kms unavailable mid-rotation")
        return original(plaintext, aad=aad)

    monkeypatch.setattr(new, "encrypt", failing)
    with pytest.raises(RuntimeError, match="kms unavailable"):
        with transaction(factory) as db:
            key_rotate.rotate(db, old, new, write=True, actor="operator", stamp=time.time())
    with transaction(factory) as db:
        assert all(row.key_version == 1 for row in db.scalars(select(Credential)).all())
        assert key_rotate.verify_all(db, old)["ok"] is True


def test_rotation_writes_a_secret_free_audit_row(credential_db):
    engine, factory, old, _ = credential_db
    with transaction(factory) as db:
        key_rotate.rotate(db, old, CredentialCipher(NEW_KEY), write=True,
                          actor="operator", stamp=time.time())
    with transaction(factory) as db:
        rows = services.recent_audit(db)
    entry = next(row for row in rows if row["action"] == "credential_key_rotated")
    assert entry["detail"]["rows"] == 3
    assert BMC_PASSWORD not in json.dumps(entry) and OLD_KEY.hex() not in json.dumps(entry)



@pytest.mark.parametrize("mode", ["write", "dry_run", "corrupt", "incomplete", "encrypt_failure"])
def test_rotation_covers_hidden_vnc_secrets_atomically(credential_db, monkeypatch, mode):
    _, factory, old, ids = credential_db
    new = CredentialCipher(NEW_KEY)
    with transaction(factory) as db:
        asset = services.upsert_asset(db, name="synthetic", address="192.0.2.90",
                                      credential_id=ids[0], actor="test")
        services.save_vnc_secret(db, old, asset_id=asset.id, username=BMC_USERNAME,
                                 password=BMC_PASSWORD, actor="test")
        aid = asset.id
        if mode == "corrupt":
            asset.vnc_password_cipher = b"corrupt"
        elif mode == "incomplete":
            asset.vnc_username_cipher = None
    if mode in ("corrupt", "incomplete"):
        with transaction(factory) as db:
            report = key_rotate.verify_all(db, old)
            assert not report["ok"] and report["undecryptable"] == ["vnc:" + aid]
        with pytest.raises(ValueError):
            with transaction(factory) as db:
                key_rotate.rotate(db, old, new, write=True, actor="test", stamp=time.time())
    else:
        if mode == "encrypt_failure":
            original = new.encrypt
            def failing(plaintext, *, aad):
                if aad.endswith(":vnc_password"):
                    raise RuntimeError("kms unavailable")
                return original(plaintext, aad=aad)
            monkeypatch.setattr(new, "encrypt", failing)
            with pytest.raises(RuntimeError, match="kms unavailable"):
                with transaction(factory) as db:
                    key_rotate.rotate(db, old, new, write=True, actor="test", stamp=time.time())
        else:
            with transaction(factory) as db:
                report = key_rotate.rotate(db, old, new, write=mode == "write",
                                           actor="test", stamp=time.time())
                assert report["rows"] == 4 and report["vnc_rows"] == 1
                assert report["credential_rows"] == 3
        with transaction(factory) as db:
            cipher = new if mode == "write" else old
            report = key_rotate.verify_all(db, cipher)
            assert report["ok"] and report["decryptable"] == 4
            assert services.read_vnc_secret(db, cipher, aid)["password"] == BMC_PASSWORD
            assert db.get(Asset, aid).vnc_key_version == (2 if mode == "write" else 1)
            with pytest.raises(Exception):
                cipher.decrypt(db.get(Asset, aid).vnc_password_cipher, aad=aid + ":password")
    if mode != "write":
        with transaction(factory) as db:
            assert all(row.key_version == 1 for row in db.scalars(select(Credential)))
            assert services.read_credential(db, old, ids[0])["password"] == BMC_PASSWORD

def test_capacity_probe_never_oversubscribes_and_releases_slots():
    report = asyncio.run(worker_capacity.run_probe(workers=4, sessions=40, capacity=3))
    assert report["granted"] == 12 and report["refused"] == 28
    assert report["no_oversubscription"] and report["bounded"]
    assert report["least_loaded_spread"] <= 1
    assert report["release_frees_slots"] and report["reclaim_granted"] == report["released"]
    assert report["no_unexplained_refusal"]


def test_a_single_worker_saturates_exactly_at_capacity():
    report = asyncio.run(worker_capacity.run_probe(workers=1, sessions=9, capacity=2))
    assert report["granted"] == 2 and report["refused"] == 7
    assert report["distribution"] == {"w0": 2}


def test_ttl_removes_a_worker_that_stopped_refreshing():
    clock_box = {"now": 1000.0}
    result = asyncio.run(worker_capacity.ttl_probe(clock_box=clock_box, ttl=30))
    assert result == {"before": 1, "after": 0, "expired": True}



@pytest.fixture
def sync_world(tmp_path, monkeypatch):
    control = tmp_path / "control.db"
    engine = make_engine(f"sqlite:///{control}")
    init_schema(engine)
    factory = session_factory(engine)
    cipher = CredentialCipher(OLD_KEY)
    with transaction(factory) as db:
        seed_roles(db)
        vendor_registry.seed_builtin_profiles(db)
        admin = services.create_user(db, "admin", ADMIN_PASSWORD, "admin", actor="test")
        profile = db.scalar(select(VendorProfile).where(VendorProfile.code == PROFILE_CODE))
        profile.status = "approved"
        cred = services.save_credential(db, cipher, label="bmc-01", username=BMC_USERNAME,
                                        password=BMC_PASSWORD, actor="test")
        cap = Capability(id=str(uuid.uuid4()), vendor=MANUFACTURER, model="X10DRT-PS",
                         firmware="8.78", adapter="passthrough", profile_id=profile.id,
                         status="verified", expires=time.time() + 86400 * 30,
                         evidence="synthetic fixture", approver="operator",
                         console_impl="AST2100 / iKVM HTML5", licence="synthetic",
                         created=time.time())
        db.add(cap)
        db.flush()
        asset = services.upsert_asset(
            db, name="node-1", address="192.0.2.11", vendor=MANUFACTURER,
            model="X10DRT-PS", firmware="8.78", fingerprint=FINGERPRINT,
            credential_id=cred.id, profile_id=profile.id, capability_id=cap.id,
            actor="test")
        services.grant_asset(db, user_id=admin.id, asset_id=asset.id, actor="test")
        ids = {"asset": asset.id, "admin": admin.id, "capability": cap.id}
    evidence = tmp_path / "evidence.json"
    evidence.write_text(json.dumps({"measured": True}), encoding="utf-8")
    monkeypatch.setenv("KVMHUB_DB_URL", f"sqlite:///{control}")
    monkeypatch.setenv("KVMHUB_CREDENTIAL_KEY", base64.b64encode(OLD_KEY).decode())
    monkeypatch.setenv("KVMHUB_DATA_PLANE_KEY", base64.b64encode(DATA_KEY).decode())
    monkeypatch.setenv("KVMHUB_ENV", "test")
    yield SimpleNamespace(engine=engine, factory=factory, evidence=evidence,
                          data_db=tmp_path / "data-plane.db", ids=ids)
    engine.dispose()


def _sync_args(world, **overrides):
    values = dict(store=str(world.data_db), asset=None, user=None,
                  evidence=str(world.evidence), approver="operator",
                  valid_days=365, review_days=180, grant_days=30,
                  dry_run=False, env_file=None, actor="operator")
    values.update(overrides)
    return SimpleNamespace(**values)


def test_sync_dry_run_writes_nothing(sync_world, capsys):
    platform_admin.cmd_sync_data_plane(_sync_args(sync_world, dry_run=True))
    out = json.loads(capsys.readouterr().out)
    assert out["dry_run"] is True and len(out["synced"]) == 1
    assert not sync_world.data_db.exists()


def test_sync_summary_never_prints_the_store_password(sync_world, capsys):
    platform_admin.cmd_sync_data_plane(_sync_args(
        sync_world, dry_run=True,
        store="mysql+pymysql://kvmhub:placeholder-db-password@127.0.0.1:3306/kvmhub?charset=utf8mb4"))
    out = capsys.readouterr().out
    assert "placeholder-db-password" not in out
    masked = ("mysql+pymysql://kvmhub:" + "*" * 3 +
              "@127.0.0.1:3306/kvmhub?charset=utf8mb4")
    assert json.loads(out)["store"] == masked


@pytest.mark.parametrize("dsn", [
    "mysql+pymysql://kvmhub:placeholder-db-password@127.0.0.1:3306/kvmhub?charset=utf8mb4",
    "mysql+pymysql://kvmhub@127.0.0.1:3306/kvmhub?password=placeholder-db-password&charset=utf8mb4",
])
def test_sync_summary_redacts_a_password_in_any_dsn_position(sync_world, capsys, dsn):
    platform_admin.cmd_sync_data_plane(_sync_args(sync_world, dry_run=True, store=dsn))
    out = capsys.readouterr().out
    assert "placeholder-db-password" not in out
    assert "***" in json.loads(out)["store"]


def test_init_db_summary_never_prints_the_db_password(monkeypatch, capsys):
    dsn = "mysql+pymysql://kvmhub:placeholder-db-password@127.0.0.1:3306/kvmhub?charset=utf8mb4"
    cfg = SimpleNamespace(db_url=dsn, bootstrap_admin="", bootstrap_password="")
    engine = SimpleNamespace(dispose=lambda: None)
    monkeypatch.setattr(platform_admin, "_context", lambda args: (cfg, engine, object(), None))
    monkeypatch.setattr(platform_admin, "init_schema", lambda e: None)
    monkeypatch.setattr(platform_admin, "transaction", lambda factory: nullcontext())
    monkeypatch.setattr(platform_admin, "seed_roles", lambda db: ["admin"])
    monkeypatch.setattr(platform_admin.vendor_registry, "seed_builtin_profiles", lambda db: 3)
    platform_admin.cmd_init_db(SimpleNamespace(env_file=None))
    out = capsys.readouterr().out
    assert "placeholder-db-password" not in out
    masked = ("mysql+pymysql://kvmhub:" + "*" * 3 +
              "@127.0.0.1:3306/kvmhub?charset=utf8mb4")
    assert json.loads(out)["db"] == masked


def test_sync_imports_a_verified_capability_and_an_encrypted_credential(sync_world, capsys):
    platform_admin.cmd_sync_data_plane(_sync_args(sync_world))
    out = json.loads(capsys.readouterr().out)
    assert out["synced"][0]["asset"] == sync_world.ids["asset"]
    store = Store(str(sync_world.data_db), DATA_KEY,
                  passthrough_targets=("https://192.0.2.11",))
    try:
        cap = store.capability(out["synced"][0]["capability"])
        assert cap["status"] == "verified" and cap["approver"] == "operator"
        assert store.assets(sync_world.ids["admin"])
        asset, reason = store.gate(sync_world.ids["asset"], sync_world.ids["admin"])
        assert reason is None and asset["target"] == "https://192.0.2.11"
        assert asset["fingerprint"] == FINGERPRINT
        assert "credential" not in json.dumps({"reason": reason})
    finally:
        store.close()
    platform_admin.cmd_sync_data_plane(_sync_args(sync_world))
    again = json.loads(capsys.readouterr().out)
    assert again["synced"][0]["capability"] == out["synced"][0]["capability"]


def test_sync_refuses_an_asset_whose_approval_gate_is_open(sync_world, capsys):
    with transaction(sync_world.factory) as db:
        db.get(Capability, sync_world.ids["capability"]).status = "draft"
    platform_admin.cmd_sync_data_plane(_sync_args(sync_world))
    out = json.loads(capsys.readouterr().out)
    assert out["synced"] == [] and out["skipped"][0]["reason"] == "approval_gate_open"
