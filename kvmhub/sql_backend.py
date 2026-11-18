"""sqlite3-shaped storage connections for the data-plane Store."""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from urllib.parse import parse_qsl, unquote, urlsplit

MYSQL_SCHEMES = ("mysql", "mysql+pymysql")


@dataclass(frozen=True)
class StoreDSN:
    dialect: str
    target: str | dict


def parse_store_dsn(value: str) -> StoreDSN:
    raw = str(value or "").strip()
    if not raw:
        raise ValueError("KVMHUB_DATA_PLANE_STORE is empty")
    scheme = raw.split("://", 1)[0].lower() if "://" in raw else ""
    if scheme in MYSQL_SCHEMES:
        parts = urlsplit(raw)
        if not parts.hostname or not parts.path.strip("/"):
            raise ValueError("MySQL store DSN needs a host and a database")
        try:
            port = parts.port or 3306
        except ValueError as exc:
            raise ValueError("MySQL store DSN has an invalid port") from exc
        options = dict(parse_qsl(parts.query, keep_blank_values=True))
        kwargs = {
            "host": parts.hostname,
            "port": port,
            "user": unquote(parts.username or ""),
            "password": unquote(parts.password or ""),
            "database": unquote(parts.path.lstrip("/")),
            "charset": options.pop("charset", "utf8mb4"),
        }
        known = {"connect_timeout", "read_timeout", "write_timeout", "ssl", "ssl_ca",
                 "ssl_cert", "ssl_key", "autocommit", "cursorclass"}
        extra = set(options) - known
        if extra:
            raise ValueError("unsupported MySQL store options: " + ", ".join(sorted(extra)))
        kwargs.update(options)
        return StoreDSN("mysql", kwargs)
    if scheme == "sqlite":
        path = raw[len("sqlite:///"):]
        if not path:
            raise ValueError("SQLite store DSN needs a path")
        return StoreDSN("sqlite", path)
    if scheme:
        raise ValueError(f"unsupported store scheme: {scheme}")
    return StoreDSN("sqlite", raw)


def _rewrite_placeholders(sql: str) -> str:
    out: list[str] = []
    quote: str | None = None
    escaped = False
    for char in sql:
        if escaped:
            out.append(char)
            escaped = False
            continue
        if char == "\\" and quote:
            out.append(char)
            escaped = True
            continue
        if quote:
            if char == quote:
                quote = None
            out.append(char)
            continue
        if char in ("'", '"', "`"):
            quote = char
            out.append(char)
            continue
        out.append("%s" if char == "?" else char)
    return "".join(out)


class Row(dict):

    def __getitem__(self, key):
        if isinstance(key, int):
            return tuple(self.values())[key]
        return dict.__getitem__(self, key)


class MysqlCursor:

    def __init__(self, cursor):
        self._cursor = cursor

    def execute(self, sql: str, params=()):
        statement = _rewrite_placeholders(sql)
        if statement.strip().upper() == "BEGIN IMMEDIATE":
            statement = "START TRANSACTION"
        self._cursor.execute(statement, tuple(params) if params else None)
        return self

    def _row(self, values):
        if values is None:
            return None
        description = self._cursor.description or ()
        return Row(zip((item[0] for item in description), values))

    def fetchone(self):
        return self._row(self._cursor.fetchone())

    def fetchall(self):
        return [self._row(value) for value in self._cursor.fetchall()]

    def __iter__(self):
        for value in self._cursor:
            yield self._row(value)

    def close(self):
        self._cursor.close()

    @property
    def rowcount(self):
        return self._cursor.rowcount

    @property
    def lastrowid(self):
        return self._cursor.lastrowid


class MysqlConnection:

    def __init__(self, **kwargs):
        import pymysql

        kwargs.setdefault("autocommit", True)
        self._conn = pymysql.connect(**kwargs)
        self.db = MysqlCursor(self._conn.cursor())

    def execute(self, sql: str, params=()):
        return self.db.execute(sql, params)

    def commit(self):
        self._conn.commit()

    def rollback(self):
        self._conn.rollback()

    def close(self):
        self.db.close()
        self._conn.close()


def open_store(dsn: StoreDSN, *, readonly: bool = False):
    if dsn.dialect == "sqlite":
        target = str(dsn.target)
        if readonly and target != ":memory:":
            from urllib.parse import quote
            return sqlite3.connect(f"file:{quote(target)}?mode=ro", uri=True,
                                   isolation_level=None, timeout=5)
        return sqlite3.connect(target, isolation_level=None, timeout=5)
    if readonly:
        return MysqlConnection(**dsn.target)
    return MysqlConnection(**dsn.target)


def mysql_capability_ddl(sql: str) -> str:
    return (sql.replace("TEXT NOT NULL DEFAULT", "VARCHAR(2048) NOT NULL DEFAULT")
               .replace("INTEGER NOT NULL DEFAULT", "INT NOT NULL DEFAULT")
               .replace("REAL NOT NULL DEFAULT", "DOUBLE NOT NULL DEFAULT"))
