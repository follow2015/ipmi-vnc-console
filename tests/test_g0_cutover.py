"""TDD for the auditable G0 cutover importer."""
from __future__ import annotations

import sys
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import pytest  # noqa: E402
from sqlalchemy import select  # noqa: E402

from kvmhub.platform.db import init_schema, make_engine, session_factory, transaction  # noqa: E402
from kvmhub.platform.models import (Asset, Capability, Credential,  # noqa: E402
                                    ExecutionDomain, DeviceAdmission, AssetConnection,
                                    PlaneProjection, PlaneOutbox)
from tools import g0_cutover  # noqa: E402

NOW = 1_800_000_000.0


def _seed(db, *, status="verified", expires=None, fingerprint="a" * 64,
          with_credential=True, cap_evidence="evidence/fleet.json",
          cap_approver="platform-admin"):
    cid, capid = str(uuid.uuid4()), str(uuid.uuid4())
    if with_credential:
        db.add(Credential(id=cid, label="bmc", username_cipher=b"u",
                          password_cipher=b"p", key_version=1, revision=1, created=NOW))
    db.add(Capability(id=capid, vendor="Supermicro", model="X10", firmware="1.0",
                      adapter="rfb-vnc", status=status, evidence=cap_evidence,
                      approver=cap_approver, expires=expires or NOW + 86400,
                      review_due=NOW + 86400, revision=1, created=NOW))
    aid = str(uuid.uuid4())
    db.add(Asset(id=aid, tenant_id=None, name="n", address="192.0.2.50",
                 credential_id=cid if with_credential else None,
                 capability_id=capid, fingerprint=fingerprint,
                 created=NOW, updated=NOW))
    db.flush()
    return aid, capid


@pytest.fixture
def world(tmp_path):
    engine = make_engine(f"sqlite:///{tmp_path / 'cutover.db'}")
    init_schema(engine)
    factory = session_factory(engine)
    yield factory
    engine.dispose()


def test_collect_only_verified_unexpired_with_fingerprint(world):
    with transaction(world) as db:
        good, _ = _seed(db)
        expired, _ = _seed(db, expires=NOW - 1)
        nofp, _ = _seed(db, fingerprint="")
        draft, _ = _seed(db, status="draft")
        nocred, _ = _seed(db, with_credential=False)
    with transaction(world) as db:
        rep = g0_cutover.collect(db, domain_id="prod-bmc", now=NOW)
    assert [c.asset_id for c in rep["candidates"]] == [good]
    reasons = {s["asset_id"]: s["reasons"] for s in rep["skipped"]}
    assert "capability_expired" in reasons[expired]
    assert "no_fingerprint" in reasons[nofp]
    assert "capability_draft" in reasons[draft]
    assert "no_credential" in reasons[nocred]


def test_candidate_evidence_and_approver_come_from_capability(world):
    with transaction(world) as db:
        _seed(db, cap_evidence="evidence/real-fleet.json", cap_approver="platform-admin")
    with transaction(world) as db:
        rep = g0_cutover.collect(db, domain_id="prod-bmc", now=NOW)
    c = rep["candidates"][0]
    assert c.evidence == "evidence/real-fleet.json"
    assert c.approver == "platform-admin"


def test_apply_creates_full_g0_chain_through_real_service(world):
    with transaction(world) as db:
        aid, _ = _seed(db)
    with transaction(world) as db:
        rep = g0_cutover.collect(db, domain_id="prod-bmc", now=NOW)
        g0_cutover.ensure_domain(db, domain_id="prod-bmc", store_id="s1", endpoint="https://x")
        for c in rep["candidates"]:
            g0_cutover.import_asset(db, row=c, domain_id="prod-bmc", now=NOW, actor="t")
    with transaction(world) as db:
        dom = db.get(ExecutionDomain, "prod-bmc")
        assert dom is not None and dom.health == "healthy"
        adm = db.scalars(select(DeviceAdmission).where(
            DeviceAdmission.asset_id == aid,
            DeviceAdmission.domain_id == "prod-bmc")).all()
        assert any(a.state == "approved" and a.evidence == "evidence/fleet.json" for a in adm)
        assert db.scalar(select(AssetConnection).where(
            AssetConnection.asset_id == aid)) is not None
        assert db.scalar(select(PlaneProjection).where(
            PlaneProjection.asset_id == aid, PlaneProjection.domain_id == "prod-bmc")) is not None
        assert db.scalar(select(PlaneOutbox).where(
            PlaneOutbox.asset_id == aid)) is not None
        proj = db.scalar(select(PlaneProjection).where(
            PlaneProjection.asset_id == aid, PlaneProjection.domain_id == "prod-bmc"))
        assert proj.applied_revision == 0 and proj.status == "pending"


def test_reapply_is_idempotent(world):
    with transaction(world) as db:
        _seed(db)
    for _ in range(2):
        with transaction(world) as db:
            rep = g0_cutover.collect(db, domain_id="prod-bmc", now=NOW)
            if rep["candidates"]:
                g0_cutover.ensure_domain(db, domain_id="prod-bmc", store_id="s1", endpoint="https://x")
                for c in rep["candidates"]:
                    g0_cutover.import_asset(db, row=c, domain_id="prod-bmc", now=NOW, actor="t")
    with transaction(world) as db:
        rep2 = g0_cutover.collect(db, domain_id="prod-bmc", now=NOW)
        assert rep2["candidates"] == []
        assert len(rep2["already_admitted"]) == 1


def test_conflicting_domain_fails_closed(world):
    with transaction(world) as db:
        db.add(ExecutionDomain(domain_id="prod-bmc", store_id="s1",
                               endpoint="https://x", supported_schema='["v2"]',
                               health="healthy", generation="other-gen",
                               policy_fingerprint="other-policy"))
    with transaction(world) as db:
        with pytest.raises(RuntimeError, match="conflicts"):
            g0_cutover.ensure_domain(db, domain_id="prod-bmc", store_id="s1", endpoint="https://x")
