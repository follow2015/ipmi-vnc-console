"""G0 transaction service: one asset change, one snapshot, one outbox event."""
from __future__ import annotations

import json
import time
import uuid
from types import SimpleNamespace

import pytest
from sqlalchemy import func, select

from kvmhub.platform import connection_config
from kvmhub.platform.db import init_schema, make_engine, session_factory, transaction
from kvmhub.platform.models import (Asset, AssetConnection, Capability, Credential,
                                    DeviceAdmission, PlaneOutbox, PlaneProjection,
                                    VendorProfile)
from kvmhub.video import client_v2

STAMP = 1_760_000_000.0
SYNTHETIC_BMC = b"synthetic-password"
SYNTHETIC_VNC = b"synthetic-user"


@pytest.fixture
def rig(tmp_path):
    engine = make_engine(f"sqlite:///{tmp_path / 'control.db'}")
    init_schema(engine)
    yield SimpleNamespace(engine=engine, factory=session_factory(engine))
    engine.dispose()


def _seed_asset(rig, *, address="192.0.2.10", secret=SYNTHETIC_BMC,
                vnc_secret=SYNTHETIC_VNC):
    aid = str(uuid.uuid4())
    cid = str(uuid.uuid4())
    kid = str(uuid.uuid4())
    with transaction(rig.factory) as db:
        cred = Credential(id=cid, tenant_id=None, label="bmc",
                          username_cipher=b"u", password_cipher=secret,
                          key_version=1, revision=1, created=STAMP)
        cap = Capability(id=kid, vendor="Supermicro", model="X10", firmware="1.0",
                         adapter="idrac8", status="verified", evidence="measured",
                         approver="operator", expires=STAMP + 86400,
                         revision=1, created=STAMP)
        db.add_all([cred, cap])
        db.flush()
        db.add(Asset(id=aid, tenant_id=None, name="node-1", address=address,
                     credential_id=cid, capability_id=kid,
                     vnc_username_cipher=b"v", vnc_password_cipher=vnc_secret,
                     vnc_key_version=1, vnc_secret_revision=1,
                     created=STAMP, updated=STAMP))
    return aid, cid


def _counts(rig):
    with rig.factory() as db:
        return tuple(db.scalar(select(func.count()).select_from(model))
                     for model in (DeviceAdmission, AssetConnection, PlaneOutbox))


def test_record_change_rolls_back_admission_snapshot_and_outbox_together(rig, monkeypatch):
    aid, _ = _seed_asset(rig)
    before = _counts(rig)

    def explode(*args, **kwargs):
        raise RuntimeError("injected failure")

    monkeypatch.setattr(connection_config, "audit", explode)
    with pytest.raises(RuntimeError):
        with transaction(rig.factory) as db:
            connection_config.record_change(db, asset_ids=[aid], reason="import",
                                            actor="tester", now=STAMP)

    assert _counts(rig) == before


def _make_lane(rig, aid, *, bundle="novnc-v2-1.6.0:test"):
    with transaction(rig.factory) as db:
        asset = db.get(Asset, aid)
        profile = VendorProfile(id=str(uuid.uuid4()), tenant_id=None,
                                code="huawei-lane", vendor="Huawei",
                                status="approved", revision=1, created=STAMP,
                                recipe_id="huawei-recipe-v1", recipe_revision=3,
                                config_schema_version="v1")
        db.add(profile)
        db.flush()
        asset.profile_id = profile.id
        capability = db.get(Capability, asset.capability_id)
        capability.bundle_revision = bundle
        db.flush()


def _latest_digest(rig, aid):
    with rig.factory() as db:
        row = db.scalar(select(AssetConnection).where(AssetConnection.asset_id == aid)
                        .order_by(AssetConnection.revision.desc()))
        return row.revision, row.digest, json.loads(row.source_versions_json)


def test_legacy_digest_still_covers_the_recorded_bundle(rig):
    aid, _ = _seed_asset(rig)
    with transaction(rig.factory) as db:
        connection_config.record_change(db, asset_ids=[aid], reason="import",
                                        actor="tester", now=STAMP)
    first = _latest_digest(rig, aid)[1]

    with transaction(rig.factory) as db:
        cap = db.scalar(select(Capability).limit(1))
        cap.bundle_revision = "bundle-20261125"
    with transaction(rig.factory) as db:
        connection_config.record_change(db, asset_ids=[aid], reason="recipe_change",
                                        actor="tester", now=STAMP)
    assert _latest_digest(rig, aid)[1] != first


def test_lane_digest_binds_the_contract_not_the_viewer_build(rig):
    aid, _ = _seed_asset(rig)
    _make_lane(rig, aid)
    with transaction(rig.factory) as db:
        connection_config.record_change(db, asset_ids=[aid], reason="import",
                                        actor="tester", now=STAMP)
    revision, digest, versions = _latest_digest(rig, aid)
    assert versions["protocol_contract"] == client_v2.protocol_contract()
    assert "bundle_revision" not in versions

    with transaction(rig.factory) as db:
        cap = db.scalar(select(Capability).limit(1))
        cap.bundle_revision = "novnc-v2-1.7.0:test"
    with transaction(rig.factory) as db:
        connection_config.record_change(db, asset_ids=[aid], reason="bundle_note",
                                        actor="tester", now=STAMP)
    newer_revision, newer_digest, _ = _latest_digest(rig, aid)
    assert newer_revision == revision + 1
    assert newer_digest == digest


def test_lane_contract_change_moves_the_digest(rig, monkeypatch):
    aid, _ = _seed_asset(rig)
    _make_lane(rig, aid)
    with transaction(rig.factory) as db:
        connection_config.record_change(db, asset_ids=[aid], reason="import",
                                        actor="tester", now=STAMP)
    before = _latest_digest(rig, aid)[1]
    monkeypatch.setattr(client_v2, "PROTOCOL_CONTRACT", "console-rfb/2")
    with transaction(rig.factory) as db:
        connection_config.record_change(db, asset_ids=[aid], reason="contract_change",
                                        actor="tester", now=STAMP)
    assert _latest_digest(rig, aid)[1] != before


def test_import_cannot_approve_by_default(rig):
    aid, _ = _seed_asset(rig)
    with transaction(rig.factory) as db:
        connection_config.record_change(db, asset_ids=[aid], reason="import",
                                        actor="tester", now=STAMP)

    with rig.factory() as db:
        states = list(db.scalars(select(DeviceAdmission.state)).all())
    assert states == ["pending"]


def test_old_revision_cannot_override_confirmed_new_revision(rig):
    aid, _ = _seed_asset(rig)
    with transaction(rig.factory) as db:
        events = []
        for _ in range(2):
            events.extend(connection_config.record_change(
                db, asset_ids=[aid], reason="change", actor="tester", now=STAMP))
        revisions = list(db.scalars(
            select(AssetConnection.revision).where(AssetConnection.asset_id == aid)
            .order_by(AssetConnection.revision)).all())
        digests = list(db.scalars(
            select(AssetConnection.digest).where(AssetConnection.asset_id == aid)
            .order_by(AssetConnection.revision)).all())

    assert revisions == [1, 2]
    with transaction(rig.factory) as db:
        accepted = connection_config.ack_projection(
            db, event_id=events[1], asset_id=aid, revision=revisions[0],
            digest=digests[0], domain_id="admission-canary",
            generation="g-1", policy_fingerprint="policy-1", now=STAMP)

    assert accepted is False
    with rig.factory() as db:
        projection = db.scalar(select(PlaneProjection).where(
            PlaneProjection.asset_id == aid))
        assert projection.desired_revision == 2
        assert projection.applied_revision == 0


def test_stale_ack_cannot_mark_new_config_ready(rig):
    aid, _ = _seed_asset(rig)
    with transaction(rig.factory) as db:
        events = connection_config.record_change(db, asset_ids=[aid], reason="change",
                                                 actor="tester", now=STAMP)

    with transaction(rig.factory) as db:
        accepted = connection_config.ack_projection(
            db, event_id=events[-1], asset_id=aid, revision=2, digest="not-the-digest",
            domain_id="admission-canary", generation="g-1",
            policy_fingerprint="policy-1", now=STAMP)

    assert accepted is False
    with rig.factory() as db:
        projection = db.scalar(select(PlaneProjection).where(
            PlaneProjection.asset_id == aid))
        assert projection.status == "pending"
        assert projection.applied_revision == 0


def test_secret_reference_but_no_plaintext_in_snapshot(rig):
    aid, cid = _seed_asset(rig)
    with transaction(rig.factory) as db:
        connection_config.record_change(db, asset_ids=[aid], reason="change",
                                        actor="tester", now=STAMP)

    with rig.factory() as db:
        rows = db.execute(select(AssetConnection).where(
            AssetConnection.asset_id == aid)).scalars().all()
    newest = max(rows, key=lambda row: row.revision)
    assert newest.secret_ref == cid
    assert newest.secret_revision >= 1
    assert "synthetic-password" not in json.dumps(
        {"secret_ref": newest.secret_ref, "secret_revision": newest.secret_revision,
         "source_versions_json": newest.source_versions_json})
