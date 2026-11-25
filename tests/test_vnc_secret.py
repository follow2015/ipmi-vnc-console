"""Hidden VNC-only credential: normalisation without losing complex VNC passwords."""
from __future__ import annotations

import json

import pytest

from kvmhub.platform import services
from kvmhub.platform.db import init_schema, make_engine, session_factory, transaction
from kvmhub.platform.models import Asset
from kvmhub.platform.security import CredentialCipher

from test_platform import BMC_PASSWORD, KEY, make_cfg


@pytest.fixture
def ctx():
    cfg = make_cfg()
    engine = make_engine(cfg.db_url)
    init_schema(engine)
    factory = session_factory(engine)
    yield engine, factory, CredentialCipher(KEY)
    engine.dispose()


def _asset_with_bmc_credential(db, cipher, address="192.0.2.31"):
    cred = services.save_credential(db, cipher, label="bmc", username="root",
                                    password=BMC_PASSWORD, actor="cli")
    asset = services.upsert_asset(db, name="node", address=address,
                                  credential_id=cred.id, actor="cli")
    return cred, asset


def test_vnc_secret_is_encrypted_and_hidden_from_public(ctx):
    _, factory, cipher = ctx
    with transaction(factory) as db:
        cred, asset = _asset_with_bmc_credential(db, cipher)
        services.save_vnc_secret(db, cipher, asset_id=asset.id,
                                 username="vnc", password="unit-test-password",
                                 actor="cli")
        db.refresh(asset)
        raw_u = bytes(asset.vnc_username_cipher)
        raw_p = bytes(asset.vnc_password_cipher)
        public = asset.public()
    assert b"vnc" not in raw_u
    assert b"unit-test-password" not in raw_p
    assert "vnc" not in json.dumps(public).lower()
    assert "password" not in json.dumps(public).lower()
    assert "vnc_username_cipher" not in public
    assert public.get("credential_id") is None
    with transaction(factory) as db:
        fresh = db.get(type(asset), asset.id)
        assert fresh.credential_id == cred.id


def test_vnc_secret_read_back_and_aad_bound_to_asset(ctx):
    _, factory, cipher = ctx
    with transaction(factory) as db:
        _, a1 = _asset_with_bmc_credential(db, cipher, "192.0.2.31")
        _, a2 = _asset_with_bmc_credential(db, cipher, "192.0.2.32")
        services.save_vnc_secret(db, cipher, asset_id=a1.id,
                                 username="vnc", password="unit-test-password", actor="cli")
        assert services.read_vnc_secret(db, cipher, a1.id) == {
            "username": "vnc", "password": "unit-test-password"}
        assert services.has_vnc_secret(a2) is False
        with pytest.raises(services.PlatformError):
            services.read_vnc_secret(db, cipher, a2.id)
        with pytest.raises(Exception):
            cipher.decrypt(bytes(a1.vnc_password_cipher), aad=a2.id + ":vnc_password")


def test_save_vnc_secret_joins_caller_transaction(ctx):
    _, factory, cipher = ctx
    with transaction(factory) as db:
        _, asset = _asset_with_bmc_credential(db, cipher)
    asset_id = asset.id
    with pytest.raises(RuntimeError, match="abort"):
        with transaction(factory) as db:
            services.save_vnc_secret(db, cipher, asset_id=asset_id,
                                     username="vnc", password="unit-test-password",
                                     actor="cli")
            raise RuntimeError("abort")
    with transaction(factory) as db:
        assert services.has_vnc_secret(db.get(Asset, asset_id)) is False


def test_clear_vnc_secret_joins_caller_transaction(ctx):
    _, factory, cipher = ctx
    with transaction(factory) as db:
        _, asset = _asset_with_bmc_credential(db, cipher)
        asset_id = asset.id
        services.save_vnc_secret(db, cipher, asset_id=asset_id,
                                 username="vnc", password="unit-test-password",
                                 actor="cli")
    with pytest.raises(RuntimeError, match="abort"):
        with transaction(factory) as db:
            services.clear_vnc_secret(db, asset_id=asset_id, actor="cli")
            raise RuntimeError("abort")
    with transaction(factory) as db:
        reloaded = db.get(Asset, asset_id)
        assert services.has_vnc_secret(reloaded) is True
        assert services.read_vnc_secret(db, cipher, asset_id)["password"] == "unit-test-password"


def test_select_sync_secret_prefers_vnc_then_falls_back_to_bmc(ctx):
    _, factory, cipher = ctx
    with transaction(factory) as db:
        _, asset = _asset_with_bmc_credential(db, cipher)
        secret, source = services.select_sync_secret(db, cipher, asset)
        assert source == "bmc"
        assert secret["password"] == BMC_PASSWORD
        services.save_vnc_secret(db, cipher, asset_id=asset.id,
                                 username="vnc", password="unit-test-password", actor="cli")
        db.refresh(asset)
        secret, source = services.select_sync_secret(db, cipher, asset)
        assert source == "vnc_hidden"
        assert secret == {"username": "vnc", "password": "unit-test-password"}


def test_clear_vnc_secret_restores_bmc_fallback(ctx):
    _, factory, cipher = ctx
    with transaction(factory) as db:
        _, asset = _asset_with_bmc_credential(db, cipher)
        services.save_vnc_secret(db, cipher, asset_id=asset.id,
                                 username="vnc", password="unit-test-password", actor="cli")
        db.refresh(asset)
        assert services.has_vnc_secret(asset) is True
        services.clear_vnc_secret(db, asset_id=asset.id, actor="cli")
        db.refresh(asset)
        assert services.has_vnc_secret(asset) is False
        secret, source = services.select_sync_secret(db, cipher, asset)
        assert source == "bmc" and secret["password"] == BMC_PASSWORD
