"""G0 authority schema: additive migration, uniqueness and admit permission."""
from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
import time
import uuid
from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from kvmhub.platform.db import init_schema, make_engine, seed_roles, session_factory, transaction
from kvmhub.platform.models import (DeviceAdmission, Permission, PlaneProjection,
                                    ROLE_ADMIN, ROLE_PLATFORM_ADMIN, Role,
                                    RolePermission)

ROOT = Path(__file__).resolve().parents[1]
ADMISSION_TABLES = {
    "kvm_device_admission", "kvm_asset_connection", "kvm_plane_outbox",
    "kvm_plane_projection", "kvm_execution_domain",
}


def _alembic(db_path: Path, *args: str) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env["KVMHUB_ENV"] = "test"
    env["KVMHUB_DB_URL"] = f"sqlite:///{db_path.as_posix()}"
    env.pop("MYSQL_HOST", None)
    return subprocess.run([sys.executable, "-m", "alembic", "-c", "alembic.ini", *args],
                          cwd=str(ROOT), env=env, capture_output=True, text=True)


def test_alembic_head_creates_admission_tables(tmp_path):
    db_path = tmp_path / "admission.db"
    from sqlalchemy import create_engine

    engine = create_engine(f"sqlite:///{db_path.as_posix()}")
    from kvmhub.platform.db import init_schema

    init_schema(engine)
    with engine.begin() as conn:
        for table in ADMISSION_TABLES | {
                'kvm_profile_overlay', 'kvm_profile_overlay_revision',
                'kvm_asset_overlay_binding', 'kvm_device_identity_evidence',
                'kvm_clock_watermark'}:
            conn.exec_driver_sql(f"DROP TABLE IF EXISTS {table}")
        conn.exec_driver_sql("ALTER TABLE kvm_credential DROP COLUMN revision")
        conn.exec_driver_sql("ALTER TABLE kvm_asset DROP COLUMN vnc_secret_revision")
        conn.exec_driver_sql("ALTER TABLE kvm_vendor_profile DROP COLUMN recipe_id")
        conn.exec_driver_sql("ALTER TABLE kvm_vendor_profile DROP COLUMN recipe_revision")
        conn.exec_driver_sql("ALTER TABLE kvm_vendor_profile DROP COLUMN config_schema_version")
        conn.exec_driver_sql("ALTER TABLE kvm_capability DROP COLUMN bundle_revision")
    engine.dispose()
    assert _alembic(db_path, "stamp", "0012_asset_vnc_secret").returncode == 0

    upgraded = _alembic(db_path, "upgrade", "head")
    assert upgraded.returncode == 0, upgraded.stdout + upgraded.stderr

    with sqlite3.connect(db_path) as conn:
        tables = {row[0] for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        assert ADMISSION_TABLES <= tables
        assert "kvm_asset" in tables
        assert conn.execute("SELECT version_num FROM alembic_version").fetchone()[0] == (
            "0017_clock_watermark")

    down = _alembic(db_path, "downgrade", "0012_asset_vnc_secret")
    assert down.returncode == 0, down.stdout + down.stderr
    with sqlite3.connect(db_path) as conn:
        tables = {row[0] for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        assert not (ADMISSION_TABLES & tables)
        assert "kvm_asset" in tables


def test_unique_and_index_constraints_reject_duplicate_revision():
    engine = make_engine("sqlite:///:memory:")
    init_schema(engine)
    factory = session_factory(engine)
    stamp = time.time()

    with transaction(factory) as db:
        db.add(DeviceAdmission(id=str(uuid.uuid4()), asset_id="asset-1", revision=1,
                               state="pending", created=stamp))
        db.add(PlaneProjection(id=str(uuid.uuid4()), asset_id="asset-1",
                               domain_id="domain-1", status="pending"))

    with pytest.raises(IntegrityError):
        with transaction(factory) as db:
            db.add(DeviceAdmission(id=str(uuid.uuid4()), asset_id="asset-1", revision=1,
                                   state="pending", created=stamp))

    with pytest.raises(IntegrityError):
        with transaction(factory) as db:
            db.add(PlaneProjection(id=str(uuid.uuid4()), asset_id="asset-1",
                                   domain_id="domain-1", status="pending"))
    engine.dispose()


def test_seed_roles_installs_asset_admit_for_platform_admin():
    engine = make_engine("sqlite:///:memory:")
    init_schema(engine)
    factory = session_factory(engine)
    stamp = time.time()

    with transaction(factory) as db:
        seed_roles(db, now=stamp)

    with factory() as db:
        permission = db.scalar(select(Permission).where(
            Permission.code == "platform.asset.admit"))
        assert permission is not None
        linked = {row[0] for row in db.execute(
            select(Role.code).join(RolePermission, RolePermission.role_id == Role.id)
            .where(RolePermission.permission_id == permission.id)).all()}
        assert ROLE_PLATFORM_ADMIN in linked
        assert ROLE_ADMIN not in linked
    engine.dispose()
