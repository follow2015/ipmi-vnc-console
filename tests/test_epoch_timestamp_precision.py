"""Control-plane epoch columns are DOUBLE in the models and in the migration."""
from __future__ import annotations

import importlib.util
from pathlib import Path

import sqlalchemy as sa

from kvmhub.platform.models import Base

ALREADY_DOUBLE = {
    ("kvm_quota_usage", "updated"),
    ("kvm_public_ip", "created"),
    ("kvm_public_ip", "updated"),
    ("kvm_public_ip_alias", "created"),
    ("kvm_public_ip_alias", "updated"),
    ("kvm_device_identity_evidence", "expires"),
    ("kvm_profile_overlay_revision", "created"),
    ("kvm_clock_watermark", "monotonic_anchor"),
}


def _migration():
    path = (Path(__file__).resolve().parents[1] / "migrations" / "versions"
            / "0021_epoch_timestamps_double.py")
    spec = importlib.util.spec_from_file_location("m0021", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_no_plain_float_column_survives_in_the_models():
    plain = [(table.name, column.name)
             for table in Base.metadata.sorted_tables
             for column in table.columns
             if isinstance(column.type, sa.Float) and column.type.precision != 53]
    assert plain == []


def test_the_migration_covers_exactly_the_time_columns_it_upgrades():
    module = _migration()
    assert module.revision == "0021_epoch_timestamps_double"
    assert module.down_revision == "0020_profile_access_params"
    moved = {(table, name)
             for table, columns in module.COLUMNS.items() for name, _ in columns}
    all_floats = {(table.name, column.name)
                  for table in Base.metadata.sorted_tables
                  for column in table.columns if isinstance(column.type, sa.Float)}
    assert moved == all_floats - ALREADY_DOUBLE
    assert len(moved) == 40


def test_revision_0022_adds_key_identity_and_clock_anchor():
    path = (Path(__file__).resolve().parents[1] / "migrations" / "versions"
            / "0022_key_clock_anchor.py")
    spec = importlib.util.spec_from_file_location("m0022", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.revision == "0022_key_clock_anchor"
    assert module.down_revision == "0021_epoch_timestamps_double"
    assets = Base.metadata.tables["kvm_asset"].columns
    clock = Base.metadata.tables["kvm_clock_watermark"].columns
    assert "vnc_key_id" in assets
    assert "monotonic_anchor" in clock and "suspicious_forward" in clock


def test_migration_nullability_matches_the_models():
    module = _migration()
    for table_name, columns in module.COLUMNS.items():
        table = Base.metadata.tables[table_name]
        for name, nullable in columns:
            assert table.columns[name].nullable is nullable, (table_name, name)
