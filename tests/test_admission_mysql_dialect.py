"""Guard: admission migrations emit DDL valid on MySQL 8.4."""
from __future__ import annotations

import re
from pathlib import Path

MIGRATIONS = Path(__file__).resolve().parents[1] / "migrations" / "versions"


def test_0013_has_no_text_server_default():
    src = (MIGRATIONS / "0013_admission_v2.py").read_text(encoding="utf-8")
    bad = [line for line in src.splitlines()
           if "sa.Text(" in line and "server_default" in line]
    assert not bad, bad


def test_0015_has_no_text_server_default():
    src = (MIGRATIONS / "0015_pipeline_recipe_identity.py").read_text(encoding="utf-8")
    bad = [line for line in src.splitlines()
           if "sa.Text(" in line and "server_default" in line]
    assert not bad, bad


def test_0013_creates_five_admission_tables():
    src = (MIGRATIONS / "0013_admission_v2.py").read_text(encoding="utf-8")
    for table in ("kvm_device_admission", "kvm_asset_connection", "kvm_plane_outbox",
                  "kvm_plane_projection", "kvm_execution_domain"):
        assert re.search(r'create_table\(\s*"%s"' % table, src), table
