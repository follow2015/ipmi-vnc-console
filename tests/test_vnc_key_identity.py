"""N1: key rotation must identify keys, not "was a previous key configured"."""
from __future__ import annotations

import json
import time

import pytest

from kvmhub.platform import services
from kvmhub.platform.db import init_schema, make_engine, session_factory, transaction
from kvmhub.platform.models import Asset, VendorProfile
from kvmhub.platform.security import CredentialCipher
from tools import platform_admin

KEY_A = bytes((i + 1 for i in range(32)))
KEY_B = bytes((i + 33 for i in range(32)))
KEY_C = bytes((i + 65 for i in range(32)))


@pytest.fixture
def world(tmp_path):
    engine = make_engine(f"sqlite:///{tmp_path}/keys.db")
    init_schema(engine)
    factory = session_factory(engine)
    with transaction(factory) as db:
        platform_admin.seed_roles(db)
        profile = VendorProfile(
            id="p", code="test-profile", vendor="Supermicro",
            firmware_min="1", firmware_max="1", status="approved",
            evidence="test", approver="t", review_due=time.time() + 86400,
            console_impl="passthrough", rfb_version="3.8", created=time.time())
        db.add(profile)
        db.flush()
        cap = services.capability_draft(
            db, profile, detection={"model": "X10", "firmware": "1"}, actor="test")
        cap.status = "verified"
        db.flush()
        cred = services.save_credential(db, CredentialCipher(KEY_A), label="bmc",
                                        username="u", password="placeholder-bmc-password", actor="test")
        asset = services.upsert_asset(db, name="node", address="192.0.2.11",
                                      vendor="Supermicro", model="X10", firmware="1",
                                      fingerprint="ab" * 32, credential_id=cred.id,
                                      capability_id=cap.id, actor="test")
        asset_id = asset.id
    yield engine, factory, asset_id
    engine.dispose()


def _read(factory, asset_id, cipher):
    with transaction(factory) as db:
        return services.read_vnc_secret(db, cipher, asset_id)


def test_cli_style_rotation_actually_rewrites_legacy_rows(world):
    engine, factory, aid = world
    old = CredentialCipher(KEY_A)
    with transaction(factory) as db:
        asset = db.get(Asset, aid)
        services.save_vnc_secret(db, old, asset_id=aid, username="vnc",
                                 password="placeholder-vnc-password", actor="test")
        asset.vnc_key_id = ""
    new_only = CredentialCipher(KEY_B)
    assert new_only.version == old.version == 1
    with transaction(factory) as db:
        result = services.rotate_vnc_secret_key(db, old, new_only, actor="cli")
    assert result["rotated"] == 1 and result["failed"] == []
    assert result["key_id"] == new_only.key_id
    assert _read(factory, aid, new_only)["password"] == "placeholder-vnc-password"
    with transaction(factory) as db:
        assert db.get(Asset, aid).vnc_key_id == new_only.key_id


def test_two_rotations_a_to_b_to_c_do_not_collide(world):
    engine, factory, aid = world
    a = CredentialCipher(KEY_A)
    with transaction(factory) as db:
        services.save_vnc_secret(db, a, asset_id=aid, username="vnc",
                                 password="placeholder-vnc-password", actor="test")
    b = CredentialCipher(KEY_B)
    with transaction(factory) as db:
        assert services.rotate_vnc_secret_key(db, a, b, actor="cli")["rotated"] == 1
    c = CredentialCipher(KEY_C)
    with transaction(factory) as db:
        assert services.rotate_vnc_secret_key(db, b, c, actor="cli")["rotated"] == 1
    assert _read(factory, aid, c)["password"] == "placeholder-vnc-password"
    with transaction(factory) as db:
        assert db.get(Asset, aid).vnc_key_id == c.key_id
    with transaction(factory) as db:
        result = services.rotate_vnc_secret_key(db, c, c, actor="cli")
    assert result["rotated"] == 0 and result["skipped"] == 1


def test_undecryptable_rows_are_reported_not_swallowed(world):
    engine, factory, aid = world
    with transaction(factory) as db:
        asset = db.get(Asset, aid)
        services.save_vnc_secret(db, CredentialCipher(KEY_A), asset_id=aid,
                                 username="vnc", password="placeholder-vnc-password", actor="test")
        asset.vnc_password_cipher = b"damaged"
    with transaction(factory) as db:
        result = services.rotate_vnc_secret_key(
            db, CredentialCipher(KEY_A), CredentialCipher(KEY_B), actor="cli")
    assert result["rotated"] == 0 and result["failed"] == [aid]


def test_key_ids_are_stable_and_secret_free():
    assert CredentialCipher(KEY_A).key_id == CredentialCipher(KEY_A).key_id
    assert CredentialCipher(KEY_A).key_id != CredentialCipher(KEY_B).key_id
    assert "placeholder-vnc-password" not in CredentialCipher(KEY_A).key_id


def test_check_subcommand_lists_rows_per_key_id(world, monkeypatch, capsys):
    engine, factory, aid = world
    old = CredentialCipher(KEY_A)
    with transaction(factory) as db:
        services.save_vnc_secret(db, old, asset_id=aid, username="vnc",
                                 password="placeholder-vnc-password", actor="test")
    monkeypatch.setattr(platform_admin, "_context",
                        lambda args: (None, engine, factory, old))
    platform_admin.cmd_rotate_vnc_key(type("A", (), {"check": True})())
    out = json.loads(capsys.readouterr().out)
    assert out["rows_by_key_id"] == {old.key_id: 1}
