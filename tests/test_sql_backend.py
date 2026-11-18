"""Tests for the dual-backend data-plane store."""
from __future__ import annotations

import sqlite3
import time

import pytest

from kvmhub import sql_backend
from kvmhub.common import Problem
from kvmhub.sql_backend import (MysqlCursor, MysqlConnection, Row, StoreDSN,
                                open_store, parse_store_dsn)
from kvmhub.store import MYSQL_SCHEMA, SQLITE_SCHEMA, Store


def test_parse_store_dsn_sqlite_backward_compatible():
    assert parse_store_dsn("/tmp/manager.sqlite3") == StoreDSN("sqlite", "/tmp/manager.sqlite3")
    assert parse_store_dsn("sqlite:///relative.db").target == "relative.db"
    assert parse_store_dsn("sqlite:////tmp/abs.db").target == "/tmp/abs.db"
    assert parse_store_dsn("sqlite:///:memory:").target == ":memory:"


def test_parse_store_dsn_mysql_credentials_and_options():
    dsn = parse_store_dsn("mysql+pymysql://kv%40user:p%2Fss@db.internal:3307/kvmhub?charset=utf8mb4")
    assert dsn.dialect == "mysql"
    assert dsn.target["host"] == "db.internal"
    assert dsn.target["port"] == 3307
    assert dsn.target["user"] == "kv@user"
    assert dsn.target["password"] == "p/ss"
    assert dsn.target["database"] == "kvmhub"
    assert dsn.target["charset"] == "utf8mb4"


@pytest.mark.parametrize("value", ["", "postgres://host/db", "mysql://host",
                                   "mysql://u:password@host:abc/db", "mysql://u:password@host/db?bogus=1"])
def test_parse_store_dsn_rejects_bad_values(value):
    with pytest.raises(ValueError):
        parse_store_dsn(value)


def test_placeholders_ignore_quoted_literals():
    assert sql_backend._rewrite_placeholders("SELECT ? FROM t WHERE x=?") == \
        "SELECT %s FROM t WHERE x=%s"
    assert sql_backend._rewrite_placeholders("SELECT '?' AS q, ?") == "SELECT '?' AS q, %s"


def test_row_supports_both_access_styles():
    row = Row({"id": "s1", "status": "active"})
    assert row["id"] == "s1"
    assert row[0] == "s1"
    assert dict(row) == {"id": "s1", "status": "active"}


def test_mysql_cursor_rewrites_transaction_and_placeholders():
    class FakeCursor:
        def __init__(self):
            self.statements = []

        def execute(self, statement, params):
            self.statements.append((statement, params))

    raw = FakeCursor()
    cursor = MysqlCursor(raw)
    cursor.execute("BEGIN IMMEDIATE")
    cursor.execute("SELECT * FROM session WHERE id=?", ("s1",))
    assert raw.statements == [("START TRANSACTION", None),
                              ("SELECT * FROM session WHERE id=%s", ("s1",))]


def test_schema_tables_match_across_dialects():
    import re

    pattern = re.compile(r"CREATE TABLE IF NOT EXISTS (\w+)")
    assert set(pattern.findall(SQLITE_SCHEMA)) == set(pattern.findall(MYSQL_SCHEMA))


class _ShimCursor:

    def __init__(self, owner):
        self.owner = owner
        self.raw = owner.sqlite.cursor()
        self.columns = False

    def execute(self, statement, params=None):
        head = statement.strip().upper()
        if head.startswith("CREATE TABLE") or head.startswith("CREATE TRIGGER") \
                or head.startswith("PRAGMA FOREIGN"):
            return self
        if head.startswith("SET SESSION TRANSACTION"):
            return self
        if head == "START TRANSACTION" or head == "BEGIN IMMEDIATE" \
                or head == "START TRANSACTION READ ONLY":
            statement = "BEGIN"
        elif head.startswith("SHOW COLUMNS FROM"):
            table = statement.strip().rsplit(" ", 1)[-1]
            self.raw.execute(f"PRAGMA table_info({table})")
            self.columns = True
            return self
        self.columns = False
        self.raw.execute(statement.replace("%s", "?"), params or ())
        return self

    @property
    def rowcount(self):
        return self.raw.rowcount

    def _row(self, value):
        if value is None:
            return None
        if self.columns:
            return Row({"Field": value[1]})
        return Row(zip((item[0] for item in self.raw.description), value))

    def fetchone(self):
        return self._row(self.raw.fetchone())

    def fetchall(self):
        return [self._row(item) for item in self.raw.fetchall()]

    def __iter__(self):
        for item in self.raw:
            yield self._row(item)

    def close(self):
        self.raw.close()


class _ShimConnection:
    def __init__(self, **kwargs):
        self.sqlite = sqlite3.connect(":memory:", isolation_level=None)
        self.sqlite.row_factory = None
        self.sqlite.executescript(SQLITE_SCHEMA)
        self.db = _ShimCursor(self)

    def execute(self, statement, params=()):
        return self.db.execute(statement, params)

    def commit(self):
        self.sqlite.commit()

    def rollback(self):
        self.sqlite.rollback()

    def close(self):
        self.db.close()
        self.sqlite.close()


def test_store_mysql_dialect_runs_the_session_contract(monkeypatch):
    monkeypatch.setattr(sql_backend, "MysqlConnection", _ShimConnection)
    store = Store("mysql://u:password@host/db", b"k" * 32)
    assert store.dialect == "mysql"
    try:
        store.seed_mock("127.0.0.1:5900", "0" * 64, "admin", "secret")
        row = store.allocate("mock-1", "local-admin", "w1", "i1", "0" * 32)
        sid = row["id"]
        assert store.get(sid)["status"] == "pending"
        claims = {key: row[key] for key in ("id", "user_id", "asset_id", "worker_id",
                                            "instance_id", "jti")}
        claims = {"sid": claims["id"], "sub": claims["user_id"], "aid": claims["asset_id"],
                  "wid": claims["worker_id"], "iid": claims["instance_id"], "jti": claims["jti"]}
        exchanged = store.exchange(claims, "0" * 32)
        assert exchanged["username"] == "admin"
        assert store.renew(sid, "w1", "i1", activate=True)["lease_seconds"] > 0
        store.finish(sid, "w1", "i1", "pending", "client_closed")
        assert store.get(sid)["status"] == "closed"
        assert store.db.execute("SELECT COUNT(*) FROM audit").fetchone()[0] > 0
    finally:
        store.close()


def test_readonly_sqlite_store_cannot_write(tmp_path):
    path = tmp_path / "ro.sqlite"
    Store(str(path)).close()
    db = open_store(parse_store_dsn(str(path)), readonly=True)
    try:
        with pytest.raises(sqlite3.OperationalError):
            db.execute("DELETE FROM audit")
    finally:
        db.close()


def test_reaping_is_idempotent_across_replicas(tmp_path):
    path = str(tmp_path / "shared.sqlite")
    writer = Store(path, b"k" * 32)
    writer.seed_mock("127.0.0.1:5900", "0" * 64, "admin", "secret")
    row = writer.allocate("mock-1", "local-admin", "w1", "i1", "0" * 32)
    writer.db.execute("UPDATE session SET phase_until=0 WHERE id=?", (row["id"],))
    writer.close()
    replicas = [Store(path, b"k" * 32) for _ in range(2)]
    try:
        assert [len(replica.sweep()) for replica in replicas] == [1, 0]
        audit = list(replicas[0].db.execute(
            "SELECT session_id FROM audit WHERE action='session_deadline'"))
        assert [row["session_id"] for row in audit] == [row["id"]]
    finally:
        for replica in replicas:
            replica.close()


def test_config_exposes_data_plane_dialect(monkeypatch):
    from kvmhub.platform.config import Settings

    def settings(**overrides):
        values = dict(env="dev", db_url="sqlite://", redis_url="", credential_key=None,
                      session_ttl=3600, lease_seconds=30, bootstrap_admin=None,
                      bootstrap_password=None, strict_prod=False,
                      signing_key_path="signing.key", data_plane_key=b"k" * 32)
        values.update(overrides)
        cfg = Settings(**values)
        cfg.validate()
        return cfg

    assert settings(data_plane_store="").data_plane_dialect == ""
    assert settings(data_plane_store="/tmp/x.sqlite").data_plane_dialect == "sqlite"
    assert settings(data_plane_store="mysql://u:password@h/db").data_plane_dialect == "mysql"


def test_exchange_guard_rejects_a_stale_read(monkeypatch):
    monkeypatch.setattr(sql_backend, "MysqlConnection", _ShimConnection)
    store = Store("mysql://u:password@host/db", b"k" * 32)
    try:
        store.seed_mock("127.0.0.1:5900", "0" * 64, "admin", "secret")
        row = store.allocate("mock-1", "local-admin", "w1", "i1", "0" * 32)
        claims = {"sid": row["id"], "sub": row["user_id"], "aid": row["asset_id"],
                  "wid": row["worker_id"], "iid": row["instance_id"], "jti": row["jti"]}
        store.exchange(claims, "0" * 32)

        stale = dict(row)
        stale["consumed"] = 0
        stale["status"] = "pending"
        monkeypatch.setattr(store, "get", lambda sid: stale)
        with pytest.raises(Problem) as exc:
            store.exchange(claims, "0" * 32)
        assert exc.value.code == "ticket_consumed_or_expired"
    finally:
        store.close()


def test_mysql_asset_slot_conflict_maps_to_asset_busy(monkeypatch):
    from pymysql.err import IntegrityError

    class ConflictShim(_ShimConnection):
        def execute(self, statement, params=()):
            if statement.strip().upper().startswith("INSERT INTO ASSET_SLOT"):
                raise IntegrityError(1062, "Duplicate entry 'mock-1' for key 'PRIMARY'")
            return super().execute(statement, params)

    monkeypatch.setattr(sql_backend, "MysqlConnection", ConflictShim)
    store = Store("mysql://u:password@host/db", b"k" * 32)
    try:
        store.seed_mock("127.0.0.1:5900", "0" * 64, "admin", "secret")
        with pytest.raises(Problem) as exc:
            store.allocate("mock-1", "local-admin", "w1", "i1", "0" * 32)
        assert exc.value.code == "asset_busy"
    finally:
        store.close()


def test_mysql_schema_makes_audit_append_only():
    from kvmhub.store import MYSQL_AUDIT_TRIGGERS

    assert set(MYSQL_AUDIT_TRIGGERS) == {"audit_no_update", "audit_no_delete"}
    joined = " ".join(MYSQL_AUDIT_TRIGGERS.values()).upper()
    assert "BEFORE UPDATE ON AUDIT" in joined
    assert "BEFORE DELETE ON AUDIT" in joined
    assert "SIGNAL SQLSTATE" in joined


def test_mysql_audit_triggers_are_created_idempotently(monkeypatch):
    from kvmhub import store as store_mod

    created = []

    class TriggerShim(_ShimConnection):
        def execute(self, statement, params=()):
            head = statement.strip().upper()
            if head.startswith("SELECT TRIGGER_NAME FROM INFORMATION_SCHEMA.TRIGGERS"):
                self.db.columns = False
                self.db.raw.execute("SELECT 'audit_no_update' AS TRIGGER_NAME WHERE 1=0 "
                                    "UNION SELECT 'audit_no_update' WHERE 1=1")
                return self.db
            if head.startswith("CREATE TRIGGER"):
                created.append(statement.strip().split()[2])
                return self.db
            return super().execute(statement, params)

    monkeypatch.setattr(sql_backend, "MysqlConnection", TriggerShim)
    monkeypatch.setattr(store_mod, "MYSQL_AUDIT_TRIGGERS", {
        "audit_no_update": "CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit FOR EACH ROW SIGNAL SQLSTATE '45000'",
        "audit_no_delete": "CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit FOR EACH ROW SIGNAL SQLSTATE '45000'",
    })
    store = Store("mysql://u:password@host/db", b"k" * 32)
    store.close()
    assert created == ["audit_no_delete"]


def test_mysql_readonly_connection_sets_read_only_transaction(monkeypatch):
    statements = []

    class RoShim(_ShimConnection):
        def execute(self, statement, params=()):
            statements.append(statement.strip().upper())
            return super().execute(statement, params)

    monkeypatch.setattr(sql_backend, "MysqlConnection", RoShim)
    db = open_store(StoreDSN("mysql", {"host": "h", "database": "d"}), readonly=True)
    db.close()
    assert "SET SESSION TRANSACTION READ ONLY" in statements


def test_mysql_transaction_pings_connection_before_begin(monkeypatch):
    pings = []

    class PingShim(_ShimConnection):
        def ping(self, reconnect=False):
            pings.append(reconnect)

    monkeypatch.setattr(sql_backend, "MysqlConnection", PingShim)
    store = Store("mysql://u:password@host/db", b"k" * 32)
    try:
        with store.tx():
            pass
        with store.tx():
            pass
        assert pings == [True, True]
    finally:
        store.close()


def test_sqlite_store_can_be_used_from_the_store_executor_thread():
    import threading

    db = open_store(StoreDSN("sqlite", ":memory:"))
    errors = []

    def use():
        try:
            db.execute("BEGIN IMMEDIATE")
            db.execute("CREATE TABLE t (x INT)")
            db.execute("COMMIT")
        except Exception as exc:
            errors.append(exc)

    t = threading.Thread(target=use)
    t.start()
    t.join()
    db.close()
    assert not errors, errors
