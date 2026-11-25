"""P0 migration report: read-only inventory of the two authorization planes."""
from __future__ import annotations

import json
import time
import uuid
from types import SimpleNamespace

import pytest
from sqlalchemy import func, select

from kvmhub.platform.db import init_schema, make_engine, session_factory, transaction
from kvmhub.platform.models import Asset, AuditLog, Capability
from kvmhub.store import Store
from tools.platform_admin import build_migration_report

DATA_KEY = b"aaaabbbbccccddddaaaabbbbccccdddd"
FINGERPRINT = "ab" * 32


@pytest.fixture
def rig(tmp_path):
    control = tmp_path / "control.db"
    engine = make_engine(f"sqlite:///{control}")
    init_schema(engine)
    factory = session_factory(engine)
    store = Store(str(tmp_path / "data-plane.db"), DATA_KEY)
    yield SimpleNamespace(engine=engine, factory=factory, store=store)
    store.close()
    engine.dispose()


def _add_control_asset(rig, address, *, status="verified", evidence="measured",
                       secret=None, tenant_id=None):
    aid = str(uuid.uuid4())
    stamp = time.time()
    with transaction(rig.factory) as db:
        cap = Capability(id=str(uuid.uuid4()), vendor="Supermicro", model="X10",
                         firmware="1.0", adapter="passthrough", status=status,
                         evidence=evidence, approver="operator",
                         expires=stamp + 86400, created=stamp)
        db.add(cap)
        db.flush()
        db.add(Asset(id=aid, tenant_id=tenant_id, name=aid[:8], address=address,
                     capability_id=cap.id, vnc_password_cipher=secret,
                     created=stamp, updated=stamp))
    return aid


def _add_store_target(rig, aid, target):
    cid = str(uuid.uuid4())
    with rig.store.tx():
        rig.store.db.execute(
            "INSERT INTO adapter_capability (id,vendor,model,firmware,adapter,status,"
            "expires,evidence,approver) VALUES (?,?,?,?,?,?,?,?,?)",
            (cid, "Supermicro", "X10", "1.0", "passthrough", "verified",
             time.time() + 86400, "measured", "operator"))
        rig.store.db.execute(
            "INSERT INTO asset (id,name,vendor,model,firmware,capability_id,target,"
            "fingerprint,credential) VALUES (?,?,?,?,?,?,?,?,?)",
            (aid, aid[:8], "Supermicro", "X10", "1.0", cid, target, FINGERPRINT, b""))


def _snapshot(rig):
    with rig.factory() as db:
        audit = db.scalar(select(func.count()).select_from(AuditLog))
        statuses = list(db.scalars(select(Capability.status)).all())
    rows = rig.store.db.execute("SELECT id,target FROM asset").fetchall()
    return audit, statuses, rows


def test_migration_report_classifies_missing_asset_and_extra_target(rig):
    aid = _add_control_asset(rig, "192.0.2.10")
    _add_store_target(rig, "store-extra", "https://192.0.2.99")

    with rig.factory() as db:
        report = build_migration_report(db=db, store=rig.store, now=time.time())

    assert any(row["asset"] == aid for row in report["categories"]["db_asset_missing_target"])
    assert any("192.0.2.99" in row["target"]
               for row in report["categories"]["target_without_asset"])


def test_migration_report_flags_duplicate_physical_endpoint_and_norm_mismatch(rig):
    _add_control_asset(rig, "192.0.2.22")
    _add_control_asset(rig, "https://192.0.2.22:443")
    _add_store_target(rig, "store-dup", "https://192.0.2.22:443")
    _add_store_target(rig, "store-query", "https://192.0.2.33:443/?token=secret")

    with rig.factory() as db:
        report = build_migration_report(db=db, store=rig.store, now=time.time())

    assert report["categories"]["duplicate_endpoint"]
    assert report["categories"]["noncanonical_target"]


def test_migration_report_is_read_only(rig):
    _add_control_asset(rig, "192.0.2.44", status="draft", evidence="")
    before = _snapshot(rig)

    with rig.factory() as db:
        build_migration_report(db=db, store=rig.store, now=time.time())

    assert _snapshot(rig) == before


def test_migration_report_never_emits_secret_material(rig):
    _add_control_asset(rig, "192.0.2.55", secret=b"cipher-placeholder")

    with rig.factory() as db:
        report = build_migration_report(db=db, store=rig.store, now=time.time())

    text = json.dumps(report, ensure_ascii=False)
    assert "placeholder" not in text
    assert "cipher" not in text
