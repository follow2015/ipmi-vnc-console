"""Transactional data-plane Store: SQLite locally, MySQL in production."""
import json
import logging
import os
import secrets
import sqlite3
import time
import uuid
from contextlib import contextmanager

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import capability
from .common import (HUAWEI_IBMC_KVM_GATEWAY_ID, HUAWEI_IBMC_VNC_ADAPTER_ID,
                     IDRAC8_ADAPTER_ID,
                     IDRAC_VNC_ADAPTER_ID, PASSTHROUGH_ADAPTER_ID, Problem,
                     bmc_allowed_networks_from_env, parse_controlled_networks)
from .sql_backend import (INTEGRITY_ERRORS, mysql_capability_ddl, open_store,
                          parse_store_dsn)
from .telemetry import audit_evidence

logger = logging.getLogger(__name__)

TENANT_GRANT = "*"

STRICT_GRANTS_ENV = "KVMHUB_STRICT_GRANTS"


def _env_strict_grants() -> bool:
    return os.environ.get(STRICT_GRANTS_ENV, "").strip().lower() in ("1", "true", "yes", "on")


SQLITE_SCHEMA = """
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS adapter_capability (
 id TEXT PRIMARY KEY, vendor TEXT NOT NULL, model TEXT NOT NULL, firmware TEXT NOT NULL,
 adapter TEXT NOT NULL, status TEXT NOT NULL, expires REAL NOT NULL,
 evidence TEXT NOT NULL, approver TEXT NOT NULL,
 console_impl TEXT NOT NULL DEFAULT '', licence TEXT NOT NULL DEFAULT '',
 concurrency_limit INTEGER NOT NULL DEFAULT 1, models TEXT NOT NULL DEFAULT '[]',
 firmware_min TEXT NOT NULL DEFAULT '', firmware_max TEXT NOT NULL DEFAULT '',
 approved_at REAL NOT NULL DEFAULT 0, effective_from REAL NOT NULL DEFAULT 0,
 review_due REAL NOT NULL DEFAULT 0, status_reason TEXT NOT NULL DEFAULT '',
 revision INTEGER NOT NULL DEFAULT 0,
 protocol_versions TEXT NOT NULL DEFAULT '[]',
 input_shaping TEXT NOT NULL DEFAULT '{}');
CREATE TABLE IF NOT EXISTS asset (
 id TEXT PRIMARY KEY, name TEXT NOT NULL, vendor TEXT NOT NULL, model TEXT NOT NULL,
 firmware TEXT NOT NULL, capability_id TEXT NOT NULL REFERENCES adapter_capability(id),
 target TEXT NOT NULL, fingerprint TEXT NOT NULL, credential BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS access_grant (
 user_id TEXT NOT NULL, asset_id TEXT NOT NULL REFERENCES asset(id), expires REAL NOT NULL,
 PRIMARY KEY(user_id,asset_id));
CREATE TABLE IF NOT EXISTS subject_authz (
 user_id TEXT PRIMARY KEY, console_allowed INTEGER NOT NULL DEFAULT 1,
 epoch INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS session (
 id TEXT PRIMARY KEY, user_id TEXT NOT NULL, asset_id TEXT NOT NULL REFERENCES asset(id),
 worker_id TEXT NOT NULL, instance_id TEXT NOT NULL, jti TEXT NOT NULL UNIQUE,
 consumed INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL, version INTEGER NOT NULL DEFAULT 0,
 created REAL NOT NULL, phase_until REAL NOT NULL, lease_until REAL NOT NULL,
 hard_until REAL NOT NULL, cleanup TEXT NOT NULL DEFAULT 'not_needed', reason TEXT,
 epoch INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS asset_slot (
 asset_id TEXT PRIMARY KEY REFERENCES asset(id), session_id TEXT NOT NULL UNIQUE REFERENCES session(id));
CREATE TABLE IF NOT EXISTS audit (
 id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, trace_id TEXT NOT NULL,
 actor TEXT NOT NULL, action TEXT NOT NULL, session_id TEXT, detail TEXT NOT NULL);
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit BEGIN
 SELECT RAISE(ABORT,'append only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit BEGIN
 SELECT RAISE(ABORT,'append only'); END;
"""

SCHEMA = SQLITE_SCHEMA

MYSQL_SCHEMA = """
CREATE TABLE IF NOT EXISTS adapter_capability (
 id VARCHAR(64) PRIMARY KEY, vendor VARCHAR(128) NOT NULL, model VARCHAR(128) NOT NULL,
 firmware VARCHAR(128) NOT NULL, adapter VARCHAR(128) NOT NULL, status VARCHAR(32) NOT NULL,
 expires DOUBLE NOT NULL, evidence TEXT NOT NULL, approver VARCHAR(128) NOT NULL,
 console_impl VARCHAR(128) NOT NULL DEFAULT '', licence TEXT NOT NULL,
 concurrency_limit INT NOT NULL DEFAULT 1, models VARCHAR(4096) NOT NULL DEFAULT '[]',
 firmware_min VARCHAR(128) NOT NULL DEFAULT '', firmware_max VARCHAR(128) NOT NULL DEFAULT '',
 approved_at DOUBLE NOT NULL DEFAULT 0, effective_from DOUBLE NOT NULL DEFAULT 0,
 review_due DOUBLE NOT NULL DEFAULT 0, status_reason VARCHAR(512) NOT NULL DEFAULT '',
 revision INT NOT NULL DEFAULT 0, protocol_versions VARCHAR(4096) NOT NULL DEFAULT '[]',
 input_shaping VARCHAR(4096) NOT NULL DEFAULT '{}', logout_path VARCHAR(256) NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS asset (
 id VARCHAR(64) PRIMARY KEY, name VARCHAR(255) NOT NULL, vendor VARCHAR(128) NOT NULL,
 model VARCHAR(128) NOT NULL, firmware VARCHAR(128) NOT NULL,
 capability_id VARCHAR(64) NOT NULL, target VARCHAR(255) NOT NULL,
 fingerprint VARCHAR(128) NOT NULL, credential LONGBLOB NOT NULL,
 INDEX ix_asset_capability (capability_id));
CREATE TABLE IF NOT EXISTS access_grant (
 user_id VARCHAR(128) NOT NULL, asset_id VARCHAR(64) NOT NULL, expires DOUBLE NOT NULL,
 PRIMARY KEY(user_id,asset_id), INDEX ix_grant_asset (asset_id), INDEX ix_grant_expiry (expires));
CREATE TABLE IF NOT EXISTS subject_authz (
 user_id VARCHAR(128) PRIMARY KEY, console_allowed INT NOT NULL DEFAULT 1,
 epoch INT NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS session (
 id VARCHAR(64) PRIMARY KEY, user_id VARCHAR(128) NOT NULL, asset_id VARCHAR(64) NOT NULL,
 worker_id VARCHAR(64) NOT NULL, instance_id VARCHAR(64) NOT NULL,
 jti VARCHAR(64) NOT NULL UNIQUE, consumed INT NOT NULL DEFAULT 0,
 status VARCHAR(32) NOT NULL, version INT NOT NULL DEFAULT 0,
 created DOUBLE NOT NULL, phase_until DOUBLE NOT NULL, lease_until DOUBLE NOT NULL,
 hard_until DOUBLE NOT NULL, cleanup VARCHAR(32) NOT NULL DEFAULT 'not_needed',
 reason VARCHAR(64), end_evidence TEXT, epoch INT NOT NULL DEFAULT 0,
 INDEX ix_session_status (status), INDEX ix_session_asset (asset_id),
 INDEX ix_session_created (created));
CREATE TABLE IF NOT EXISTS asset_slot (
 asset_id VARCHAR(64) PRIMARY KEY, session_id VARCHAR(64) NOT NULL UNIQUE);
CREATE TABLE IF NOT EXISTS audit (
 id BIGINT AUTO_INCREMENT PRIMARY KEY, ts DOUBLE NOT NULL, trace_id VARCHAR(64) NOT NULL,
 actor VARCHAR(128) NOT NULL, action VARCHAR(96) NOT NULL, session_id VARCHAR(64),
 detail TEXT NOT NULL, INDEX ix_audit_session (session_id), INDEX ix_audit_action (action));
"""

MYSQL_AUDIT_TRIGGERS = {
    "audit_no_update": "CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit "
                       "FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='audit is append only'",
    "audit_no_delete": "CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit "
                       "FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='audit is append only'",
}

CAPABILITY_COLUMNS = {
    "console_impl": "TEXT NOT NULL DEFAULT ''",
    "licence": "TEXT NOT NULL DEFAULT ''",
    "concurrency_limit": "INTEGER NOT NULL DEFAULT 1",
    "models": "TEXT NOT NULL DEFAULT '[]'",
    "firmware_min": "TEXT NOT NULL DEFAULT ''",
    "firmware_max": "TEXT NOT NULL DEFAULT ''",
    "approved_at": "REAL NOT NULL DEFAULT 0",
    "effective_from": "REAL NOT NULL DEFAULT 0",
    "review_due": "REAL NOT NULL DEFAULT 0",
    "status_reason": "TEXT NOT NULL DEFAULT ''",
    "revision": "INTEGER NOT NULL DEFAULT 0",
    "protocol_versions": "TEXT NOT NULL DEFAULT '[]'",
    "input_shaping": "TEXT NOT NULL DEFAULT '{}'",
    "logout_path": "TEXT NOT NULL DEFAULT ''",
}

SESSION_COLUMNS = {
    "end_evidence": "TEXT",
    "epoch": "INTEGER NOT NULL DEFAULT 0",
}

END_REASONS = ("client_closed", "revoked", "capability_withdrawn", "upstream_error",
               "upstream_unresponsive", "lease_expired", "login_failed", "worker_shutdown",
               "exchange_failed",
               "role_downgraded",
               "client_message_denied", "client_message_malformed",
               "input_overflow",
               "upstream_reconnect_failed")


class _CapabilityLost(Exception):
    pass


class Store:
    def __init__(self, path, key: bytes | None = None, clock=time.time, lease_seconds=30,
                 passthrough_targets: tuple[str, ...] = (),
                 strict_grants: bool | None = None,
                 bmc_allowed_networks: tuple[str, ...] | None = None):
        self._dsn = parse_store_dsn(str(path))
        self.dialect = self._dsn.dialect
        self.strict_grants = _env_strict_grants() if strict_grants is None else strict_grants
        self.db = open_store(self._dsn)
        if self.dialect == "sqlite":
            self.db.row_factory = sqlite3.Row
            self.db.executescript(SQLITE_SCHEMA)
        else:
            for statement in MYSQL_SCHEMA.split(";"):
                if statement.strip():
                    self.db.execute(statement)
            self._ensure_audit_triggers()
        self._migrate()
        self.cipher = AESGCM(key) if key is not None else None
        self.clock, self.lease_seconds = clock, lease_seconds
        self.passthrough_targets = frozenset(passthrough_targets)
        raw_networks = (bmc_allowed_networks_from_env()
                        if bmc_allowed_networks is None else bmc_allowed_networks)
        try:
            self.bmc_allowed_networks = parse_controlled_networks(raw_networks)
        except ValueError:
            self.bmc_allowed_networks = ()

    def _ensure_audit_triggers(self):
        try:
            rows = self.db.execute(
                "SELECT TRIGGER_NAME FROM information_schema.triggers "
                "WHERE TRIGGER_SCHEMA=DATABASE()").fetchall()
            present = {row[0] for row in rows}
        except Exception:
            return
        for name, ddl in MYSQL_AUDIT_TRIGGERS.items():
            if name not in present:
                self.db.execute(ddl)

    def _migrate(self):
        for table, columns in (("adapter_capability", CAPABILITY_COLUMNS),
                               ("session", SESSION_COLUMNS)):
            if self.dialect == "sqlite":
                present = {row["name"] for row in self.db.execute(f"PRAGMA table_info({table})")}
            else:
                present = {row["Field"] for row in self.db.execute(f"SHOW COLUMNS FROM {table}")}
            for name, ddl in columns.items():
                if name not in present:
                    statement = f"ALTER TABLE {table} ADD COLUMN {name} {ddl}"
                    self.db.execute(mysql_capability_ddl(statement)
                                    if self.dialect == "mysql" else statement)

    def close(self):
        self.db.close()

    @contextmanager
    def tx(self):
        if self.dialect == "mysql" and hasattr(self.db, "ping"):
            self.db.ping(reconnect=True)
        self.db.execute("BEGIN IMMEDIATE")
        try:
            yield
            self.db.execute("COMMIT")
        except BaseException:
            self.db.execute("ROLLBACK")
            raise

    def event(self, actor, action, sid=None, detail=None, trace=None):
        self.db.execute("INSERT INTO audit(ts,trace_id,actor,action,session_id,detail) VALUES(?,?,?,?,?,?)",
                        (self.clock(), trace or uuid.uuid4().hex, actor, action, sid,
                         json.dumps(detail or {}, separators=(",", ":"))))


    def capabilities(self):
        return [dict(row) for row in self.db.execute("SELECT * FROM adapter_capability ORDER BY id")]

    def capability(self, cid):
        row = self.db.execute("SELECT * FROM adapter_capability WHERE id=?", (cid,)).fetchone()
        if row is None:
            raise Problem("capability_not_found", 404)
        return dict(row)

    def register_capability(self, entry: dict, actor: str, rationale: str = "") -> dict:
        with self.tx():
            self._register(entry, actor, rationale)
        return self.capability(entry["id"])

    def _register(self, entry, actor, rationale=""):
        cid = str(entry.get("id") or "").strip()
        values = {
            "id": cid,
            "vendor": str(entry.get("vendor") or "").strip(),
            "model": str(entry.get("model") or "").strip(),
            "firmware": str(entry.get("firmware") or "").strip(),
            "adapter": str(entry.get("adapter") or "").strip(),
            "models": json.dumps([str(m) for m in (entry.get("models") or [])]),
            "firmware_min": str(entry.get("firmware_min") or "").strip(),
            "firmware_max": str(entry.get("firmware_max") or "").strip(),
        }
        declared = capability.parse_protocol_versions(entry.get("protocol_versions"))
        if declared is None:
            raise Problem("capability_incomplete", 400)
        values["protocol_versions"] = json.dumps(list(declared))
        try:
            shaping = capability.parse_input_shaping(entry.get("input_shaping"))
        except ValueError:
            raise Problem("capability_incomplete", 400) from None
        values["input_shaping"] = json.dumps(shaping) if shaping else "{}"
        try:
            logout_path = capability.parse_logout_path(entry.get("logout_path"))
        except ValueError:
            raise Problem("capability_incomplete", 400) from None
        values["logout_path"] = logout_path or ""
        if not cid or not all((values["vendor"], values["model"], values["adapter"])):
            raise Problem("capability_incomplete", 400)
        if not capability.window_parses(values):
            raise Problem("capability_incomplete", 400)
        if self.db.execute("SELECT 1 FROM adapter_capability WHERE id=?", (cid,)).fetchone():
            raise Problem("capability_exists", 409)
        self.db.execute(
            "INSERT INTO adapter_capability(id,vendor,model,firmware,adapter,status,expires,evidence,"
            "approver,console_impl,licence,concurrency_limit,models,firmware_min,firmware_max,"
            "protocol_versions,input_shaping,logout_path,approved_at,effective_from,review_due,"
            "status_reason,revision) "
            "VALUES(?,?,?,?,?,'draft',0,'','','','',1,?,?,?,?,?,?,0,0,0,'',0)",
            (values["id"], values["vendor"], values["model"], values["firmware"], values["adapter"],
             values["models"], values["firmware_min"], values["firmware_max"],
             values["protocol_versions"], values["input_shaping"], values["logout_path"]))
        self.event(actor, "capability_registered",
                   detail={"capability": cid, "adapter": values["adapter"], "rationale": rationale})

    def approve_capability(self, cid, *, actor, approver=None, evidence=None, licence=None,
                           console_impl=None, review_due=None, expires=None, effective_from=None,
                           concurrency_limit=None, rationale="", adapter=None, vendor=None,
                           model=None, models=None, firmware=None, firmware_min=None,
                           firmware_max=None) -> dict:
        with self.tx():
            self._approve(cid, actor=actor, approver=approver, evidence=evidence, licence=licence,
                          console_impl=console_impl, review_due=review_due, expires=expires,
                          effective_from=effective_from, concurrency_limit=concurrency_limit,
                          rationale=rationale, adapter=adapter, vendor=vendor, model=model,
                          models=models, firmware=firmware, firmware_min=firmware_min,
                          firmware_max=firmware_max)
        return self.capability(cid)

    def _approve(self, cid, *, actor, approver=None, evidence=None, licence=None,
                 console_impl=None, review_due=None, expires=None, effective_from=None,
                 concurrency_limit=None, rationale="", adapter=None, vendor=None, model=None,
                 models=None, firmware=None, firmware_min=None, firmware_max=None):
        row = self.capability(cid)
        if not capability.transition_allowed(row["status"], "verified"):
            raise Problem("capability_state", 409)
        merged = dict(row)
        for key, value in (("approver", approver), ("evidence", evidence), ("licence", licence),
                           ("console_impl", console_impl), ("review_due", review_due),
                           ("expires", expires), ("effective_from", effective_from),
                           ("concurrency_limit", concurrency_limit), ("adapter", adapter),
                           ("vendor", vendor), ("model", model), ("firmware", firmware),
                           ("firmware_min", firmware_min), ("firmware_max", firmware_max)):
            if value is not None:
                merged[key] = value
        if models is not None:
            merged["models"] = json.dumps([str(m) for m in models])
        now = self.clock()
        if not float(merged.get("effective_from") or 0):
            merged["effective_from"] = now
        gaps = capability.approval_gaps(merged)
        if gaps or not str(merged.get("adapter") or "").strip():
            raise Problem("capability_incomplete", 400)
        if not capability.window_parses(merged):
            raise Problem("capability_incomplete", 400)
        if float(merged["expires"]) <= now or float(merged["review_due"]) <= now:
            raise Problem("capability_incomplete", 400)
        if float(merged["effective_from"]) > float(merged["expires"]):
            raise Problem("capability_incomplete", 400)
        if int(merged["concurrency_limit"]) < 1:
            raise Problem("capability_incomplete", 400)
        self.db.execute(
            "UPDATE adapter_capability SET vendor=?,model=?,firmware=?,adapter=?,status='verified',"
            "expires=?,evidence=?,approver=?,console_impl=?,licence=?,concurrency_limit=?,models=?,"
            "firmware_min=?,firmware_max=?,approved_at=?,effective_from=?,review_due=?,"
            "status_reason='',revision=revision+1 WHERE id=?",
            (merged["vendor"], merged["model"], merged["firmware"], merged["adapter"],
             merged["expires"], merged["evidence"], merged["approver"], merged["console_impl"],
             merged["licence"], int(merged["concurrency_limit"]), merged["models"],
             merged["firmware_min"], merged["firmware_max"], now, merged["effective_from"],
             merged["review_due"], cid))
        self.event(actor, "capability_approved",
                   detail={"capability": cid, "previous": row["status"],
                           "approver": merged["approver"], "evidence": merged["evidence"],
                           "licence": merged["licence"], "console_impl": merged["console_impl"],
                           "review_due": merged["review_due"], "expires": merged["expires"],
                           "revision": int(row["revision"]) + 1, "rationale": rationale})

    def suspend_capability(self, cid, *, actor, reason, rationale="") -> dict:
        return self._withdraw(cid, actor=actor, target="suspended", reason=reason, rationale=rationale)

    def retire_capability(self, cid, *, actor, reason, rationale="") -> dict:
        return self._withdraw(cid, actor=actor, target="retired", reason=reason, rationale=rationale)

    def _withdraw(self, cid, *, actor, target, reason, rationale):
        if not str(reason or "").strip():
            raise Problem("capability_incomplete", 400)
        with self.tx():
            row = self.capability(cid)
            if not capability.transition_allowed(row["status"], target):
                raise Problem("capability_state", 409)
            self.db.execute("UPDATE adapter_capability SET status=?,status_reason=?,revision=revision+1 "
                            "WHERE id=?", (target, reason, cid))
            self.event(actor, f"capability_{target}",
                       detail={"capability": cid, "previous": row["status"],
                               "reason": reason, "rationale": rationale})
            sessions = self._withdraw_sessions(cid, actor, reason)
        return {"capability": self.capability(cid), "sessions": sessions}

    def _withdraw_sessions(self, cid, actor, reason):
        ended = []
        for asset in [row["id"] for row in self.db.execute(
                "SELECT id FROM asset WHERE capability_id=?", (cid,))]:
            for row in self.db.execute(
                    "SELECT id,status FROM session WHERE asset_id=? AND status IN "
                    "('pending','connecting','active','closing')", (asset,)).fetchall():
                status = "closed" if row["status"] == "pending" else "closing"
                self.db.execute("UPDATE session SET status=?,reason='capability_withdrawn',"
                                "version=version+1 WHERE id=?", (status, row["id"]))
                self.event(actor, "capability_session_withdrawn", row["id"],
                           {"capability": cid, "previous": row["status"], "reason": reason})
                self.release_confirmed(row["id"])
                ended.append(row["id"])
        return ended


    def put_grant(self, user_id: str, asset_id: str, expires: float) -> None:
        if self.dialect == "sqlite":
            self.db.execute(
                "INSERT INTO access_grant(user_id,asset_id,expires) VALUES(?,?,?) "
                "ON CONFLICT(user_id,asset_id) DO UPDATE SET expires=excluded.expires",
                (user_id, asset_id, expires))
        else:
            self.db.execute(
                "INSERT INTO access_grant(user_id,asset_id,expires) VALUES(?,?,?) "
                "ON DUPLICATE KEY UPDATE expires=VALUES(expires)",
                (user_id, asset_id, expires))

    def delete_grant(self, user_id: str, asset_id: str) -> None:
        self.db.execute("DELETE FROM access_grant WHERE user_id=? AND asset_id=?",
                        (user_id, asset_id))

    def delete_grants_for_asset(self, asset_id: str) -> None:
        self.db.execute("DELETE FROM access_grant WHERE asset_id=?", (asset_id,))

    def set_subject_authz(self, user_id: str, console_allowed: int, epoch: int) -> None:
        if self.dialect == "sqlite":
            self.db.execute(
                "INSERT INTO subject_authz(user_id,console_allowed,epoch) VALUES(?,?,?) "
                "ON CONFLICT(user_id) DO UPDATE SET console_allowed=excluded.console_allowed,"
                "epoch=excluded.epoch", (user_id, int(console_allowed), int(epoch)))
        else:
            self.db.execute(
                "INSERT INTO subject_authz(user_id,console_allowed,epoch) VALUES(?,?,?) "
                "ON DUPLICATE KEY UPDATE console_allowed=VALUES(console_allowed),epoch=VALUES(epoch)",
                (user_id, int(console_allowed), int(epoch)))

    def bump_subject_epoch(self, user_id: str, *, console_allowed: int | None = None) -> int:
        current_allowed, current_epoch = self.subject_state(user_id)
        new_epoch = current_epoch + 1
        new_allowed = current_allowed if console_allowed is None else int(console_allowed)
        self.set_subject_authz(user_id, new_allowed, new_epoch)
        return new_epoch

    def subject_state(self, user) -> tuple[int, int]:
        row = self.db.execute("SELECT console_allowed,epoch FROM subject_authz "
                              "WHERE user_id=?", (user,)).fetchone()
        if row is None:
            return 1, 0
        return int(row["console_allowed"]), int(row["epoch"])

    def grant_row(self, aid, user):
        row = self.db.execute("SELECT expires FROM access_grant "
                              "WHERE asset_id=? AND user_id=? ORDER BY expires DESC LIMIT 1",
                              (aid, user)).fetchone()
        if row is not None:
            return row
        if self.strict_grants:
            return None
        row = self.db.execute("SELECT expires FROM access_grant "
                              "WHERE asset_id=? AND user_id=? ORDER BY expires DESC LIMIT 1",
                              (aid, TENANT_GRANT)).fetchone()
        if row is not None:
            logger.warning("deprecated wildcard grant used: asset=%s user=%s "
                           "(run reconcile-data-plane, then enable strict_grants)", aid, user)
        return row

    def gate(self, aid, user):
        grant = self.grant_row(aid, user)
        row = self.db.execute("SELECT * FROM asset WHERE id=?", (aid,)).fetchone()
        if row is None or grant is None or grant["expires"] <= self.clock():
            raise Problem("permission_denied", 403)
        console_allowed, _ = self.subject_state(user)
        if not console_allowed:
            raise Problem("permission_denied", 403)
        asset = dict(row)
        asset["grant_expires"] = grant["expires"]
        cap = self.db.execute("SELECT * FROM adapter_capability WHERE id=?",
                              (row["capability_id"],)).fetchone()
        reason = capability.evaluate(dict(cap) if cap else None, asset, self.clock())
        if reason is None and not self._adapter_allowed(asset | {"adapter": cap["adapter"]}):
            reason = "adapter_not_enabled"
        declared = capability.parse_protocol_versions(cap["protocol_versions"]) if cap else ()
        try:
            shaping = capability.parse_input_shaping(cap["input_shaping"]) if cap else None
        except (ValueError, KeyError):
            shaping = None
        try:
            logout_path = capability.parse_logout_path(cap["logout_path"]) if cap else None
        except (ValueError, KeyError):
            logout_path = None
        allowed = asset | {"adapter": cap["adapter"] if cap else "",
                           "cap_expires": cap["expires"] if cap else 0.0,
                           "protocol_versions": declared or (),
                           "logout_path": logout_path,
                           "input_shaping": shaping}
        return allowed, reason

    def seed_mock(self, target: str, fingerprint: str, username: str, password: str):
        assert self.cipher is not None, "seeding credentials requires the encryption key"
        with self.tx():
            if not self.db.execute("SELECT 1 FROM adapter_capability WHERE id=?", ("mock-v1",)).fetchone():
                self._register({"id": "mock-v1", "vendor": "mock", "model": "test-console",
                                "firmware": "1", "adapter": "mock-v1"}, "local-bootstrap")
            self._approve("mock-v1", actor="local-bootstrap", approver="local-bootstrap",
                          evidence="tests/test_flow.py (synthetic device only)",
                          licence="synthetic fixture, no vendor terms",
                          console_impl="kvmhub/mock_bmc.py",
                          review_due=self.clock() + 86400 * 30,
                          expires=self.clock() + 86400 * 30)
            for aid, name in (("mock-1", "模拟控制台一"), ("mock-2", "模拟控制台二")):
                nonce = secrets.token_bytes(12)
                encrypted = nonce + self.cipher.encrypt(nonce, json.dumps({"username": username, "password": password}).encode(), aid.encode())
                self.db.execute("REPLACE INTO asset VALUES(?,?,?,?,?,?,?,?,?)",
                                (aid, name, "mock", "test-console", "1", "mock-v1", target, fingerprint, encrypted))
                self.db.execute("REPLACE INTO access_grant VALUES(?,?,?)",
                                ("local-admin", aid, self.clock() + 86400))

    def seed_passthrough(self, *, target: str, fingerprint: str, username: str, password: str,
                         approver: str, asset_id: str = "real-1",
                         name: str = "真机控制台（实验）",
                         vendor: str = "Supermicro (Inspur OEM)",
                         model: str = "X10DRT-PS / SA5248M4", firmware: str = "8.78",
                         capability_id: str = "supermicro-x10-passthrough",
                         protocol_versions: tuple[str, ...] = (),
                         input_shaping: dict | None = None,
                         logout_path: str | None = None,
                         evidence: str = "docs/implementation/evidence/real-bmc-kvm-phase2-20261111.json") -> None:
        assert self.cipher is not None, "seeding credentials requires the encryption key"
        with self.tx():
            if not self.db.execute("SELECT 1 FROM adapter_capability WHERE id=?", (capability_id,)).fetchone():
                self._register({"id": capability_id, "vendor": vendor, "model": model,
                                "firmware": firmware, "adapter": PASSTHROUGH_ADAPTER_ID,
                                "protocol_versions": list(protocol_versions),
                                **({"input_shaping": input_shaping} if input_shaping else {}),
                                **({"logout_path": logout_path} if logout_path else {})},
                               "local-bootstrap")
            self._approve(capability_id, actor="local-bootstrap", approver=approver,
                          evidence=evidence, licence="未取得厂商书面许可；仅同源代理转发，不分发",
                          console_impl="AST2100 / iKVM HTML5", review_due=self.clock() + 86400 * 30,
                          expires=self.clock() + 86400 * 30)
            nonce = secrets.token_bytes(12)
            encrypted = nonce + self.cipher.encrypt(
                nonce, json.dumps({"username": username, "password": password}).encode(), asset_id.encode())
            self.db.execute("REPLACE INTO asset VALUES(?,?,?,?,?,?,?,?,?)",
                            (asset_id, name, vendor, model, firmware, capability_id, target,
                             fingerprint, encrypted))
            self.db.execute("REPLACE INTO access_grant VALUES(?,?,?)",
                            ("local-admin", asset_id, self.clock() + 86400))

    def register_asset(self, *, asset_id: str, name: str, vendor: str, model: str,
                       firmware: str, capability_id: str, target: str, fingerprint: str,
                       username: str, password: str, user_id: str,
                       grant_ttl: float = 86400 * 30, actor: str = "platform-sync") -> None:
        if self.cipher is None:
            raise Problem("credential_unavailable", 503)
        if not all((asset_id, name, capability_id, target, user_id)):
            raise Problem("capability_incomplete", 400)
        digest = str(fingerprint or "").replace(":", "").strip().lower()
        if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
            raise Problem("fingerprint_invalid", 400)
        if self.db.execute("SELECT 1 FROM adapter_capability WHERE id=? AND status='verified'",
                           (capability_id,)).fetchone() is None:
            raise Problem("adapter_not_verified", 403)
        nonce = secrets.token_bytes(12)
        encrypted = nonce + self.cipher.encrypt(
            nonce, json.dumps({"username": username, "password": password}).encode(),
            asset_id.encode())
        with self.tx():
            self.db.execute("REPLACE INTO asset VALUES(?,?,?,?,?,?,?,?,?)",
                            (asset_id, name, vendor, model, firmware, capability_id,
                             target, digest, encrypted))
            self.db.execute("REPLACE INTO access_grant VALUES(?,?,?)",
                            (user_id, asset_id, self.clock() + grant_ttl))
            self.event(actor, "data_plane_asset_imported",
                       detail={"asset": asset_id, "capability": capability_id,
                               "user": user_id, "target": target})

    def assets(self, user):
        return [dict(r) for r in self.db.execute(
            "SELECT a.id,a.name FROM asset a JOIN access_grant g ON a.id=g.asset_id WHERE g.user_id=? AND g.expires>?",
            (user, self.clock()))]

    LIVE_STATES = ("pending", "connecting", "active", "closing")

    def rotate_asset_fingerprint(self, aid, *, fingerprint, actor, evidence, rationale=""):
        if not str(actor or "").strip() or not str(evidence or "").strip():
            raise Problem("rotation_incomplete", 400)
        digest = str(fingerprint or "").replace(":", "").strip().lower()
        if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
            raise Problem("fingerprint_invalid", 400)
        with self.tx():
            row = self.db.execute("SELECT id,fingerprint FROM asset WHERE id=?", (aid,)).fetchone()
            if row is None:
                raise Problem("asset_not_found", 404)
            if row["fingerprint"] == digest:
                raise Problem("fingerprint_unchanged", 409)
            self.db.execute("UPDATE asset SET fingerprint=? WHERE id=?", (digest, aid))
            live = self.db.execute(
                "SELECT COUNT(*) FROM session WHERE asset_id=? AND status IN (?,?,?,?)",
                (aid, *self.LIVE_STATES)).fetchone()[0]
            self.event(actor, "asset_fingerprint_rotated",
                       detail={"asset": aid, "old": row["fingerprint"][:12], "new": digest[:12],
                               "evidence": str(evidence).strip(), "rationale": rationale})
        return {"asset": aid, "old": row["fingerprint"][:12], "new": digest[:12],
                "live_sessions": live}

    def eligible(self, aid, user):
        asset, reason = self.gate(aid, user)
        if reason is not None:
            raise Problem("adapter_not_verified", 403)
        return asset

    def _adapter_allowed(self, row) -> bool:
        if row["adapter"] == "mock-v1":
            return True
        if row["adapter"] not in (PASSTHROUGH_ADAPTER_ID, IDRAC8_ADAPTER_ID,
                                  IDRAC_VNC_ADAPTER_ID, HUAWEI_IBMC_VNC_ADAPTER_ID,
                                  HUAWEI_IBMC_KVM_GATEWAY_ID):
            return False
        if row["target"] not in self.passthrough_targets:
            return False
        if row["adapter"] in (IDRAC_VNC_ADAPTER_ID, HUAWEI_IBMC_VNC_ADAPTER_ID,
                              HUAWEI_IBMC_KVM_GATEWAY_ID):
            import ipaddress
            from urllib.parse import urlsplit
            host = urlsplit(str(row["target"])).hostname
            try:
                address = ipaddress.ip_address(host)
            except (ValueError, TypeError):
                return False
            return any(address in network for network in self.bmc_allowed_networks)
        return True

    def get(self, sid):
        row = self.db.execute("SELECT * FROM session WHERE id=?", (sid,)).fetchone()
        if row is None:
            raise Problem("session_not_found", 404)
        return dict(row)

    def owned(self, sid, user):
        row = self.get(sid)
        if row["user_id"] != user:
            raise Problem("permission_denied", 403)
        return row

    def allocate(self, aid, user, worker, instance, trace, *, hard_cap: float | None = None):
        now = self.clock()
        with self.tx():
            asset = self.eligible(aid, user)
            if self.db.execute("SELECT 1 FROM asset_slot WHERE asset_id=?", (aid,)).fetchone():
                raise Problem("asset_busy", 409)
            sid = uuid.uuid4().hex
            hard = min(now + 4 * 3600, asset["grant_expires"], asset["cap_expires"])
            if hard_cap is not None:
                hard = min(hard, hard_cap)
            _, subject_epoch = self.subject_state(user)
            self.db.execute("INSERT INTO session(id,user_id,asset_id,worker_id,instance_id,jti,status,created,phase_until,lease_until,hard_until,epoch) "
                            "VALUES(?,?,?,?,?,?,'pending',?,?,?,?,?)",
                            (sid, user, aid, worker, instance, uuid.uuid4().hex, now, min(now + 60, hard), 0, hard, subject_epoch))
            try:
                self.db.execute("INSERT INTO asset_slot VALUES(?,?)", (aid, sid))
            except INTEGRITY_ERRORS:
                raise Problem("asset_busy", 409) from None
            self.event(user, "session_requested", sid, trace=trace)
        return self.get(sid)

    def pending_cleanups(self, now=None, *, threshold=300.0) -> list[dict]:
        current = self.clock() if now is None else now
        rows = self.db.execute(
            "SELECT s.id, s.worker_id, s.asset_id, s.reason, s.created, "
            "  (SELECT MAX(a.ts) FROM audit a WHERE a.session_id=s.id "
            "   AND a.action='session_finished') AS ended "
            "FROM session s WHERE s.cleanup='pending' "
            "AND s.status IN ('closed','failed','lost')").fetchall()
        out = []
        for row in rows:
            since = row["ended"] if row["ended"] is not None else row["created"]
            age = max(0.0, current - since)
            out.append({"sid": row["id"], "worker_id": row["worker_id"],
                        "asset_id": row["asset_id"], "reason": row["reason"],
                        "age_s": round(age, 1), "overdue": age >= threshold})
        return sorted(out, key=lambda item: item["age_s"], reverse=True)

    def release_confirmed(self, sid):
        row = self.get(sid)
        if row["status"] in ("closed", "failed", "lost") and row["cleanup"] in ("confirmed", "not_needed"):
            self.db.execute("DELETE FROM asset_slot WHERE session_id=?", (sid,))

    def exchange(self, claims, trace):
        sid = claims["sid"]
        with self.tx():
            row = self.get(sid)
            if any(row[k] != claims[c] for k, c in (("user_id", "sub"), ("asset_id", "aid"),
                   ("worker_id", "wid"), ("instance_id", "iid"), ("jti", "jti"))):
                raise Problem("invalid_ticket", 403)
            if row["status"] != "pending" or row["consumed"] or row["phase_until"] <= self.clock():
                raise Problem("ticket_consumed_or_expired", 409)
            asset = self.eligible(row["asset_id"], row["user_id"])
            now = self.clock()
            lease = min(now + self.lease_seconds, row["hard_until"])
            updated = self.db.execute(
                "UPDATE session SET consumed=1,status='connecting',cleanup='pending',"
                "version=version+1,phase_until=?,lease_until=? "
                "WHERE id=? AND consumed=0 AND status='pending'",
                (min(now+30,row["hard_until"]), lease, sid))
            if not updated.rowcount:
                raise Problem("ticket_consumed_or_expired", 409)
            self.event(row["worker_id"], "ticket_consumed", sid, trace=trace)
            self.event(row["worker_id"], "credential_access_intent", sid, trace=trace)
            blob = asset["credential"]
            result = {"target": asset["target"], "fingerprint": asset["fingerprint"],
                      "adapter": asset["adapter"], "lease_seconds": lease-now,
                      "hard_until": row["hard_until"],
                      "protocol_versions": list(asset["protocol_versions"]),
                      "input_shaping": asset.get("input_shaping"),
                      "logout_path": asset.get("logout_path")}
        try:
            if self.cipher is None:
                raise ValueError("this store was opened without the credential key")
            credentials = json.loads(self.cipher.decrypt(blob[:12], blob[12:], row["asset_id"].encode()))
        except Exception:
            with self.tx():
                self.db.execute("UPDATE session SET status='failed',cleanup='not_needed',"
                                "reason='credential_unavailable',version=version+1 WHERE id=?", (sid,))
                self.event(row["worker_id"], "credential_access_failed", sid, trace=trace)
                self.event(row["worker_id"], "slot_released_no_upstream", sid, trace=trace)
                self.release_confirmed(sid)
            raise Problem("credential_unavailable", 503) from None
        with self.tx():
            self.event(row["worker_id"], "credential_access_succeeded", sid, trace=trace)
        return result | credentials

    def worker_row(self, sid, worker, instance):
        row = self.get(sid)
        if (row["worker_id"], row["instance_id"]) != (worker, instance):
            raise Problem("instance_mismatch", 403)
        return row

    def renew(self, sid, worker, instance, activate=False, trace=None):
        try:
            return self._renew(sid, worker, instance, activate, trace)
        except _CapabilityLost:
            with self.tx():
                row = self.get(sid)
                if row["reason"] != "capability_withdrawn" and row["status"] in (
                        "pending", "connecting", "active", "closing"):
                    self.db.execute("UPDATE session SET reason='capability_withdrawn',"
                                    "version=version+1 WHERE id=?", (sid,))
                    self.event(worker, "capability_session_withdrawn", sid,
                               {"cause": "renew_gate_closed"})
            raise Problem("capability_withdrawn", 410) from None

    def _renew(self, sid, worker, instance, activate, trace):
        subject_revoked_reason = None
        with self.tx():
            row = self.worker_row(sid, worker, instance)
            now = self.clock()
            if (row["status"] not in (("connecting",) if activate else ("active",))
                    or row["lease_until"] <= now or row["hard_until"] <= now
                    or (activate and row["phase_until"] <= now)):
                raise Problem("session_revoked", 410)
            console_allowed, subject_epoch = self.subject_state(row["user_id"])
            if not console_allowed or int(row["epoch"]) < subject_epoch:
                subject_revoked_reason = "revoked" if not console_allowed else "role_downgraded"
                self.db.execute("UPDATE session SET status='closing',reason=?,version=version+1 "
                                "WHERE id=? AND status IN ('connecting','active')",
                                (subject_revoked_reason, sid))
                self.event(worker, "session_revoked_by_subject", sid,
                           {"epoch": int(row["epoch"]), "subject_epoch": subject_epoch,
                            "reason": subject_revoked_reason}, trace=trace)
            else:
                try:
                    asset = self.eligible(row["asset_id"], row["user_id"])
                except Problem as exc:
                    if exc.code == "adapter_not_verified":
                        raise _CapabilityLost() from None
                    raise
                until = min(now + self.lease_seconds, row["hard_until"],
                            asset["grant_expires"], asset["cap_expires"])
                expected = "connecting" if activate else "active"
                updated = self.db.execute(
                    "UPDATE session SET status='active',lease_until=?,version=version+1 "
                    "WHERE id=? AND status=? AND version=?",
                    (until, sid, expected, row["version"]))
                if not updated.rowcount:
                    raise Problem("session_revoked", 410)
                if activate:
                    self.event(worker, "session_active", sid, trace=trace)
        if subject_revoked_reason is not None:
            raise Problem("session_revoked", 410)
        return {"lease_seconds": until - now}

    def finish(self, sid, worker, instance, cleanup, reason, trace=None, evidence=None):
        if cleanup not in ("confirmed", "pending", "not_needed") or reason not in END_REASONS:
            raise Problem("invalid_report", 400)
        summary = audit_evidence(evidence)
        stored = json.dumps(summary, separators=(",", ":")) if summary else None
        with self.tx():
            row = self.worker_row(sid, worker, instance)
            if cleanup == "not_needed" and (reason != "exchange_failed" or row["status"] in ("active", "closing")):
                raise Problem("invalid_report", 400)
            status = row["status"] if row["status"] in ("failed", "lost", "closed") else "closed"
            effective = "confirmed" if row["cleanup"] == "confirmed" else cleanup
            if row["reason"] in ("capability_withdrawn", "role_downgraded") and reason == "revoked":
                reason = row["reason"]
            self.db.execute(
                "UPDATE session SET "
                "status=CASE WHEN status IN ('failed','lost','closed') THEN status ELSE ? END,"
                "cleanup=CASE WHEN cleanup='confirmed' THEN 'confirmed' ELSE ? END,"
                "reason=CASE WHEN reason='capability_withdrawn' THEN reason ELSE ? END,"
                "end_evidence=COALESCE(end_evidence,?),version=version+1 WHERE id=?",
                (status, effective, reason, stored, sid))
            final = self.get(sid)
            detail = {"cleanup": final["cleanup"], "reason": final["reason"]}
            if summary:
                detail["evidence"] = summary
            self.event(worker, "session_finished", sid, detail, trace=trace)
            self.release_confirmed(sid)

    def confirm_cleanup(self, sid, user, trace, *, manage=False):
        with self.tx():
            row = self.get(sid) if manage else self.owned(sid, user)
            if row["cleanup"] != "pending" or row["status"] not in ("closed", "failed", "lost"):
                raise Problem("cleanup_not_pending", 409)
            self.db.execute("UPDATE session SET cleanup='confirmed',reason='manual_release',"
                            "version=version+1 WHERE id=?", (sid,))
            self.event(user, "manual_slot_release", sid,
                       {"previous": "pending", "scope": "manage" if manage else "owner"},
                       trace=trace)
            self.release_confirmed(sid)

    def revoke(self, sid, user, trace):
        with self.tx():
            row = self.owned(sid, user)
            if row["status"] in ("pending", "connecting", "active"):
                status = "closed" if row["status"] == "pending" else "closing"
                self.db.execute("UPDATE session SET status=?,reason='revoked',version=version+1 WHERE id=?", (status, sid))
                self.event(user, "session_revoked", sid, trace=trace)
                self.release_confirmed(sid)

    def force_revoke(self, sid, actor, trace):
        with self.tx():
            row = self.get(sid)
            live = row["status"] in ("pending", "connecting", "active", "closing")
            if live:
                target = "closed" if row["status"] == "pending" else "closing"
                updated = self.db.execute(
                    "UPDATE session SET status=?,reason='revoked',version=version+1 "
                    "WHERE id=? AND status=?", (target, sid, row["status"]))
                if not updated.rowcount:
                    row = self.get(sid)
                    live = row["status"] in ("pending", "connecting", "active", "closing")
                else:
                    self.event(actor, "session_revoked", sid, trace=trace)
                    row = dict(row, status=target, reason="revoked")
                    if target == "closed":
                        self.release_confirmed(sid)
        return {"status": row["status"], "was_live": live,
                "asset_id": row["asset_id"], "worker_id": row["worker_id"]}

    def sweep(self):
        ended = []
        with self.tx():
            stale = self.db.execute(
                "SELECT s.id FROM session s JOIN asset_slot a ON a.session_id=s.id "
                "WHERE s.status IN ('closed','failed','lost') "
                "AND s.cleanup='not_needed'").fetchall()
            for r in stale:
                self.release_confirmed(r["id"])
            now = self.clock()
            for r in self.db.execute("SELECT * FROM session WHERE status IN ('pending','connecting','active','closing')").fetchall():
                status = None
                deadline_col = None
                deadline_at = None
                if r["status"] == "pending" and r["phase_until"] <= now:
                    status, deadline_col, deadline_at = "closed", "phase_until", r["phase_until"]
                elif r["status"] == "connecting" and r["phase_until"] <= now:
                    status, deadline_col, deadline_at = "failed", "phase_until", r["phase_until"]
                elif r["status"] in ("connecting", "active", "closing") and r["lease_until"] <= now:
                    status, deadline_col, deadline_at = "lost", "lease_until", r["lease_until"]
                if status:
                    updated = self.db.execute(
                        "UPDATE session SET status=?,reason='deadline',version=version+1 "
                        f"WHERE id=? AND status=? AND version=? AND {deadline_col}<=?",
                        (status, r["id"], r["status"], r["version"], deadline_at))
                    if not updated.rowcount:
                        continue
                    detail = {"status": status}
                    if r["hard_until"] <= now:
                        detail["cause"] = "hard_limit"
                    self.event("reaper", "session_deadline", r["id"], detail)
                    self.release_confirmed(r["id"])
                    ended.append(r["id"])
        return ended

    def public(self, sid, user):
        row = self.owned(sid, user)
        result = {k: row[k] for k in ("id", "asset_id", "status", "cleanup", "reason", "created", "hard_until")}
        result["end_evidence"] = json.loads(row["end_evidence"]) if row["end_evidence"] else None
        return result
