"""Guard: store DDL must quote MySQL reserved words."""
from __future__ import annotations

from pathlib import Path

STORE = Path(__file__).resolve().parents[1] / "kvmhub" / "store.py"


def test_mysql_connection_snapshot_quotes_schema_column():
    src = STORE.read_text(encoding="utf-8")
    mysql = src.split("MYSQL_SCHEMA", 1)[1]
    block = mysql.split("connection_snapshot", 1)[1].split(");", 1)[0]
    assert "`schema`" in block, block[:300]
    assert "schema VARCHAR" not in block, block[:300]


def test_snapshot_insert_quotes_schema_column():
    src = STORE.read_text(encoding="utf-8")
    assert "INSERT INTO connection_snapshot" in src
    assert '"schema,domain_id,generation' not in src
    assert "`#schema`" not in src
    assert "schema,domain_id,generation,policy_fingerprint,created" in src.replace(
        "`schema`,domain_id,generation,policy_fingerprint,created",
        "schema,domain_id,generation,policy_fingerprint,created")
