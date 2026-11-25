"""Existing asset/credential write entries must feed the G0 outbox."""
from __future__ import annotations

import time
import uuid
from types import SimpleNamespace

import pytest
from sqlalchemy import func, select

from kvmhub.platform import services
from kvmhub.platform.db import init_schema, make_engine, session_factory, transaction
from kvmhub.platform.models import (Asset, Capability, Credential, DeviceAdmission,
                                    PlaneOutbox, Tenant, User)

KEY = b"0123456789abcdef0123456789abcdef"
STAMP = 1_760_000_000.0


@pytest.fixture
def rig(tmp_path):
    engine = make_engine(f"sqlite:///{tmp_path / 'control.db'}")
    init_schema(engine)
    yield SimpleNamespace(engine=engine, factory=session_factory(engine),
                          cipher=services.CredentialCipher(KEY))
    engine.dispose()


def _count(db, model):
    return db.scalar(select(func.count()).select_from(model))


def _seed_asset(rig, *, address="192.0.2.70", tenant_id=None):
    aid, cid = str(uuid.uuid4()), str(uuid.uuid4())
    with transaction(rig.factory) as db:
        db.add(Tenant(id="tenant-a", code="tenant-a", name="A", status="active",
                      plan="standard", quotas_json='{"assets": 10}', created=STAMP))
        db.add(Tenant(id="tenant-b", code="tenant-b", name="B", status="active",
                      plan="standard", quotas_json='{"assets": 10}', created=STAMP))
        db.add(Credential(id=cid, tenant_id=tenant_id, label="bmc",
                          username_cipher=b"u", password_cipher=b"p",
                          key_version=1, revision=1, created=STAMP))
        db.add(Asset(id=aid, tenant_id=tenant_id, name="node", address=address,
                     credential_id=cid, created=STAMP, updated=STAMP))
    return aid, cid


def test_save_credential_alone_emits_no_device_event(rig):
    with transaction(rig.factory) as db:
        cred = services.save_credential(db, rig.cipher, label="bmc", username="root",
                                        password="synthetic-password", actor="tester", now=STAMP)
        assert _count(db, PlaneOutbox) == 0
    assert cred.label == "bmc"


def test_upsert_asset_emits_one_event(rig):
    with transaction(rig.factory) as db:
        asset = services.upsert_asset(db, name="node", address="192.0.2.71",
                                      actor="tester", now=STAMP)
        assert _count(db, PlaneOutbox) == 1
        assert _count(db, DeviceAdmission) == 1

    with rig.factory() as db:
        row = db.scalar(select(PlaneOutbox).where(PlaneOutbox.asset_id == asset.id))
        assert row.event_type == "asset_created"


def test_unchanged_asset_edit_emits_no_event(rig):
    with transaction(rig.factory) as db:
        asset = services.upsert_asset(db, name="node", address="192.0.2.72",
                                      actor="tester", now=STAMP)
    with transaction(rig.factory) as db:
        services.upsert_asset(db, name="node", address="192.0.2.72",
                              actor="tester", now=STAMP, asset_id=asset.id,
                              public_ips=[])
        assert _count(db, PlaneOutbox) == 1


def test_display_fields_do_not_advance_connection_revision(rig):
    with transaction(rig.factory) as db:
        asset = services.upsert_asset(db, name="node", address="192.0.2.73",
                                      actor="tester", now=STAMP)
    with transaction(rig.factory) as db:
        services.upsert_asset(db, name="renamed", address="192.0.2.73",
                              licence="changed", notes="changed",
                              actor="tester", now=STAMP, asset_id=asset.id)
        assert _count(db, PlaneOutbox) == 1


def test_vnc_secret_resave_and_reclear_are_noops(rig):
    aid, _ = _seed_asset(rig)
    with transaction(rig.factory) as db:
        services.save_vnc_secret(db, rig.cipher, asset_id=aid,
                                 username="vnc", password="synthetic-password",
                                 actor="tester", now=STAMP, tenant_id=None)
        assert _count(db, PlaneOutbox) == 1
    with transaction(rig.factory) as db:
        asset = services.save_vnc_secret(db, rig.cipher, asset_id=aid,
                                         username="vnc", password="synthetic-password",
                                         actor="tester", now=STAMP, tenant_id=None)
        assert asset.vnc_secret_revision == 2
        assert _count(db, PlaneOutbox) == 1
    with transaction(rig.factory) as db:
        services.clear_vnc_secret(db, asset_id=aid, actor="tester", now=STAMP,
                                  tenant_id=None)
        assert _count(db, PlaneOutbox) == 2
    with transaction(rig.factory) as db:
        services.clear_vnc_secret(db, asset_id=aid, actor="tester", now=STAMP,
                                  tenant_id=None)
        assert _count(db, PlaneOutbox) == 2


def test_vnc_secret_change_bumps_revision_and_emits_event(rig):
    aid, _ = _seed_asset(rig)
    with transaction(rig.factory) as db:
        asset = services.save_vnc_secret(db, rig.cipher, asset_id=aid,
                                         username="vnc", password="synthetic-password",
                                         actor="tester", now=STAMP, tenant_id=None)
        assert asset.vnc_secret_revision == 2
        assert _count(db, PlaneOutbox) == 1

    with transaction(rig.factory) as db:
        services.clear_vnc_secret(db, asset_id=aid, actor="tester", now=STAMP,
                                  tenant_id=None)
        assert _count(db, PlaneOutbox) == 2


def test_tenant_change_revokes_admission(rig):
    aid, _ = _seed_asset(rig, tenant_id="tenant-a")
    with transaction(rig.factory) as db:
        db.add(User(id="user-1", tenant_id="tenant-a", username="u",
                    password_hash="x", created=STAMP))
        db.flush()
        services.grant_asset(db, user_id="user-1", asset_id=aid,
                             tenant_id="tenant-a", actor="tester")
        result = services.assign_asset(db, address="192.0.2.70",
                                       tenant_id="tenant-b", actor="tester",
                                       reassign=True, now=STAMP)
        assert result["action"] == "moved"
        assert _count(db, PlaneOutbox) >= 1

    with rig.factory() as db:
        states = list(db.scalars(select(DeviceAdmission.state).where(
            DeviceAdmission.asset_id == aid)).all())
        assert "revoked" in states
