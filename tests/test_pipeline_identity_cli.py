"""Two writes on the V1 lane identity: a build note and a recipe change."""
from __future__ import annotations

import json
import time
import uuid
from types import SimpleNamespace

import pytest
from sqlalchemy import func, select

from kvmhub.platform.db import init_schema, make_engine, session_factory, transaction
from kvmhub.platform.models import (Asset, AssetConnection, Capability, Credential,
                                    VendorProfile)
from kvmhub.video import client_v2
from tools import platform_admin

STAMP = 1_760_000_000.0


@pytest.fixture
def rig(tmp_path):
    engine = make_engine(f"sqlite:///{tmp_path / 'control.db'}")
    init_schema(engine)
    factory = session_factory(engine)
    ids = {"asset": str(uuid.uuid4()), "credential": str(uuid.uuid4()),
           "capability": str(uuid.uuid4()), "profile": str(uuid.uuid4())}
    with transaction(factory) as db:
        db.add(Credential(id=ids["credential"], tenant_id=None, label="bmc",
                          username_cipher=b"u", password_cipher=b"p",
                          key_version=1, revision=1, created=STAMP))
        db.add(Capability(id=ids["capability"], tenant_id=None, vendor="Huawei",
                          model="2288H V5", firmware="6.27", adapter="huawei-ibmc-kvm-gateway",
                          status="verified", evidence="measured", approver="operator",
                          expires=STAMP + 86400, revision=1, created=STAMP))
        db.add(VendorProfile(id=ids["profile"], tenant_id=None, code="huawei-2288h-v5",
                             vendor="Huawei", status="approved", revision=1, created=STAMP))
        db.flush()
        capability = db.get(Capability, ids["capability"])
        capability.profile_id = ids["profile"]
        db.add(Asset(id=ids["asset"], tenant_id=None, name="node-1", address="192.0.2.10",
                     credential_id=ids["credential"], capability_id=ids["capability"],
                     profile_id=ids["profile"], created=STAMP, updated=STAMP))
    try:
        yield SimpleNamespace(factory=factory, ids=ids, engine=engine)
    finally:
        engine.dispose()


def _args(rig, tmp_path, **overrides):
    evidence = tmp_path / "pipeline-evidence.json"
    evidence.write_text('{"measured": true}', encoding="utf-8")
    values = dict(profile=rig.ids["profile"], capability=rig.ids["capability"],
                  recipe_id="huawei-ibmc-jpeg-v1", recipe_revision=3, schema="v1",
                  bundle="novnc-v2-1.6.0:first", evidence=str(evidence),
                  approver="operator", actor="operator", env_file=None)
    values.update(overrides)
    return SimpleNamespace(**values)


def _snapshot_count(rig):
    with rig.factory() as db:
        return db.scalar(select(func.count()).select_from(AssetConnection))


def test_bundle_only_update_is_an_annotation_not_an_identity_change(rig, tmp_path, capsys,
                                                                    monkeypatch):
    monkeypatch.setattr(platform_admin, "_context", lambda args: (None, None, rig.factory, None))
    platform_admin.cmd_set_pipeline_identity(_args(rig, tmp_path))
    first = json.loads(capsys.readouterr().out)
    assert first["bundle_only"] is False and first["reprojected_assets"] == 1
    snapshots = _snapshot_count(rig)

    platform_admin.cmd_set_pipeline_identity(
        _args(rig, tmp_path, bundle="novnc-v2-1.7.0:second"))
    second = json.loads(capsys.readouterr().out)
    assert second["bundle_only"] is True
    assert second["reprojected_assets"] == 0
    assert _snapshot_count(rig) == snapshots, "a build note must not open a G0 window"
    with rig.factory() as db:
        assert db.get(Capability, rig.ids["capability"]).bundle_revision == "novnc-v2-1.7.0:second"
        assert db.get(VendorProfile, rig.ids["profile"]).revision == 2


def test_refresh_lane_contract_only_touches_stale_lane_assets(rig, tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(platform_admin, "_context", lambda args: (None, None, rig.factory, None))
    platform_admin.cmd_refresh_lane_contract(
        SimpleNamespace(asset=None, profile=None, actor="operator", env_file=None))
    assert json.loads(capsys.readouterr().out)["assets"] == 0

    platform_admin.cmd_set_pipeline_identity(_args(rig, tmp_path))
    capsys.readouterr()
    before = _snapshot_count(rig)
    monkeypatch.setattr(client_v2, "PROTOCOL_CONTRACT", "console-rfb/2")
    platform_admin.cmd_refresh_lane_contract(
        SimpleNamespace(asset=None, profile=None, actor="operator", env_file=None))
    result = json.loads(capsys.readouterr().out)
    assert result["assets"] == 1 and result["contract"] == "console-rfb/2"
    assert _snapshot_count(rig) == before + 1

    platform_admin.cmd_refresh_lane_contract(
        SimpleNamespace(asset=None, profile=None, actor="operator", env_file=None))
    assert json.loads(capsys.readouterr().out)["assets"] == 0
    assert _snapshot_count(rig) == before + 1
