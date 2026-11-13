"""Transactional SQLite implementation for the single-Manager local PoC."""
import json
import secrets
import sqlite3
import time
import uuid
from contextlib import contextmanager

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import capability
from .common import PASSTHROUGH_ADAPTER_ID, Problem


SCHEMA = """
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
 protocol_versions TEXT NOT NULL DEFAULT '[]');
CREATE TABLE IF NOT EXISTS asset (
 id TEXT PRIMARY KEY, name TEXT NOT NULL, vendor TEXT NOT NULL, model TEXT NOT NULL,
 firmware TEXT NOT NULL, capability_id TEXT NOT NULL REFERENCES adapter_capability(id),
 target TEXT NOT NULL, fingerprint TEXT NOT NULL, credential BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS access_grant (
 user_id TEXT NOT NULL, asset_id TEXT NOT NULL REFERENCES asset(id), expires REAL NOT NULL,
 PRIMARY KEY(user_id,asset_id));
CREATE TABLE IF NOT EXISTS session (
 id TEXT PRIMARY KEY, user_id TEXT NOT NULL, asset_id TEXT NOT NULL REFERENCES asset(id),
 worker_id TEXT NOT NULL, instance_id TEXT NOT NULL, jti TEXT NOT NULL UNIQUE,
 consumed INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL, version INTEGER NOT NULL DEFAULT 0,
 created REAL NOT NULL, phase_until REAL NOT NULL, lease_until REAL NOT NULL,
 hard_until REAL NOT NULL, cleanup TEXT NOT NULL DEFAULT 'not_needed', reason TEXT);
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
}

END_REASONS = ("client_closed", "revoked", "capability_withdrawn", "upstream_error",
               "upstream_unresponsive", "lease_expired", "login_failed", "worker_shutdown",
               "exchange_failed",
               "client_message_denied", "client_message_malformed",
               "upstream_reconnect_failed")


class _CapabilityLost(Exception):
    pass


class Store:
    def __init__(self, path, key: bytes | None = None, clock=time.time, lease_seconds=30,
                 passthrough_targets: tuple[str, ...] = ()):
        self.db = sqlite3.connect(path, isolation_level=None, timeout=5)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)
        self._migrate()
        self.cipher = AESGCM(key) if key is not None else None
        self.clock, self.lease_seconds = clock, lease_seconds
        self.passthrough_targets = frozenset(passthrough_targets)

    def _migrate(self):
        present = {row["name"] for row in self.db.execute("PRAGMA table_info(adapter_capability)")}
        for name, ddl in CAPABILITY_COLUMNS.items():
            if name not in present:
                self.db.execute(f"ALTER TABLE adapter_capability ADD COLUMN {name} {ddl}")

    def close(self):
        self.db.close()

    @contextmanager
    def tx(self):
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
        if not cid or not all((values["vendor"], values["model"], values["adapter"])):
            raise Problem("capability_incomplete", 400)
        if not capability.window_parses(values):
            raise Problem("capability_incomplete", 400)
        if self.db.execute("SELECT 1 FROM adapter_capability WHERE id=?", (cid,)).fetchone():
            raise Problem("capability_exists", 409)
        self.db.execute(
            "INSERT INTO adapter_capability(id,vendor,model,firmware,adapter,status,expires,evidence,"
            "approver,console_impl,licence,concurrency_limit,models,firmware_min,firmware_max,"
            "protocol_versions,approved_at,effective_from,review_due,status_reason,revision) "
            "VALUES(?,?,?,?,?,'draft',0,'','','','',1,?,?,?,?,0,0,0,'',0)",
            (values["id"], values["vendor"], values["model"], values["firmware"], values["adapter"],
             values["models"], values["firmware_min"], values["firmware_max"],
             values["protocol_versions"]))
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

    def gate(self, aid, user):
        row = self.db.execute("SELECT a.*,g.expires AS grant_expires FROM asset a "
                              "JOIN access_grant g ON a.id=g.asset_id WHERE a.id=? AND g.user_id=?",
                              (aid, user)).fetchone()
        if row is None or row["grant_expires"] <= self.clock():
            raise Problem("permission_denied", 403)
        asset = dict(row)
        cap = self.db.execute("SELECT * FROM adapter_capability WHERE id=?",
                              (row["capability_id"],)).fetchone()
        reason = capability.evaluate(dict(cap) if cap else None, asset, self.clock())
        if reason is None and not self._adapter_allowed(asset | {"adapter": cap["adapter"]}):
            reason = "adapter_not_enabled"
        declared = capability.parse_protocol_versions(cap["protocol_versions"]) if cap else ()
        allowed = asset | {"adapter": cap["adapter"] if cap else "",
                           "cap_expires": cap["expires"] if cap else 0.0,
                           "protocol_versions": declared or ()}
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
                self.db.execute("INSERT OR REPLACE INTO asset VALUES(?,?,?,?,?,?,?,?,?)",
                                (aid, name, "mock", "test-console", "1", "mock-v1", target, fingerprint, encrypted))
                self.db.execute("INSERT OR REPLACE INTO access_grant VALUES(?,?,?)",
                                ("local-admin", aid, self.clock() + 86400))

    def seed_passthrough(self, *, target: str, fingerprint: str, username: str, password: str,
                         approver: str, asset_id: str = "real-1",
                         name: str = "真机控制台（实验）",
                         vendor: str = "Supermicro (Inspur OEM)",
                         model: str = "X10DRT-PS / SA5248M4", firmware: str = "8.78",
                         capability_id: str = "supermicro-x10-passthrough",
                         protocol_versions: tuple[str, ...] = (),
                         evidence: str = "docs/implementation/evidence/real-bmc-kvm-phase2-20261111.json") -> None:
        assert self.cipher is not None, "seeding credentials requires the encryption key"
        with self.tx():
            if not self.db.execute("SELECT 1 FROM adapter_capability WHERE id=?", (capability_id,)).fetchone():
                self._register({"id": capability_id, "vendor": vendor, "model": model,
                                "firmware": firmware, "adapter": PASSTHROUGH_ADAPTER_ID,
                                "protocol_versions": list(protocol_versions)},
                               "local-bootstrap")
            self._approve(capability_id, actor="local-bootstrap", approver=approver,
                          evidence=evidence, licence="未取得厂商书面许可；仅同源代理转发，不分发",
                          console_impl="AST2100 / iKVM HTML5", review_due=self.clock() + 86400 * 30,
                          expires=self.clock() + 86400 * 30)
            nonce = secrets.token_bytes(12)
            encrypted = nonce + self.cipher.encrypt(
                nonce, json.dumps({"username": username, "password": password}).encode(), asset_id.encode())
            self.db.execute("INSERT OR REPLACE INTO asset VALUES(?,?,?,?,?,?,?,?,?)",
                            (asset_id, name, vendor, model, firmware, capability_id, target,
                             fingerprint, encrypted))
            self.db.execute("INSERT OR REPLACE INTO access_grant VALUES(?,?,?)",
                            ("local-admin", asset_id, self.clock() + 86400))

    def assets(self, user):
        return [dict(r) for r in self.db.execute(
            "SELECT a.id,a.name FROM asset a JOIN access_grant g ON a.id=g.asset_id WHERE g.user_id=? AND g.expires>?",
            (user, self.clock()))]

    def eligible(self, aid, user):
        asset, reason = self.gate(aid, user)
        if reason is not None:
            raise Problem("adapter_not_verified", 403)
        return asset

    def _adapter_allowed(self, row) -> bool:
        if row["adapter"] == "mock-v1":
            return True
        return (row["adapter"] == PASSTHROUGH_ADAPTER_ID
                and row["target"] in self.passthrough_targets)

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

    def allocate(self, aid, user, worker, instance, trace):
        now = self.clock()
        with self.tx():
            asset = self.eligible(aid, user)
            if self.db.execute("SELECT 1 FROM asset_slot WHERE asset_id=?", (aid,)).fetchone():
                raise Problem("asset_busy", 409)
            sid = uuid.uuid4().hex
            hard = min(now + 4 * 3600, asset["grant_expires"], asset["cap_expires"])
            self.db.execute("INSERT INTO session(id,user_id,asset_id,worker_id,instance_id,jti,status,created,phase_until,lease_until,hard_until) "
                            "VALUES(?,?,?,?,?,?,'pending',?,?,?,?)",
                            (sid, user, aid, worker, instance, uuid.uuid4().hex, now, min(now + 60, hard), 0, hard))
            self.db.execute("INSERT INTO asset_slot VALUES(?,?)", (aid, sid))
            self.event(user, "session_requested", sid, trace=trace)
        return self.get(sid)

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
            self.db.execute("UPDATE session SET consumed=1,status='connecting',cleanup='pending',version=version+1,"
                            "phase_until=?,lease_until=? WHERE id=?", (min(now+30,row["hard_until"]), lease, sid))
            self.event(row["worker_id"], "ticket_consumed", sid, trace=trace)
            self.event(row["worker_id"], "credential_access_intent", sid, trace=trace)
            blob = asset["credential"]
            result = {"target": asset["target"], "fingerprint": asset["fingerprint"],
                      "adapter": asset["adapter"], "lease_seconds": lease-now,
                      "hard_until": row["hard_until"],
                      "protocol_versions": list(asset["protocol_versions"])}
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
        with self.tx():
            row = self.worker_row(sid, worker, instance)
            now = self.clock()
            if (row["status"] not in (("connecting",) if activate else ("active",))
                    or row["lease_until"] <= now or row["hard_until"] <= now
                    or (activate and row["phase_until"] <= now)):
                raise Problem("session_revoked", 410)
            try:
                asset = self.eligible(row["asset_id"], row["user_id"])
            except Problem as exc:
                if exc.code == "adapter_not_verified":
                    raise _CapabilityLost() from None
                raise
            until = min(now + self.lease_seconds, row["hard_until"], asset["grant_expires"], asset["cap_expires"])
            self.db.execute("UPDATE session SET status='active',lease_until=?,version=version+1 WHERE id=?", (until, sid))
            if activate:
                self.event(worker, "session_active", sid, trace=trace)
        return {"lease_seconds": until - now}

    def finish(self, sid, worker, instance, cleanup, reason, trace=None):
        if cleanup not in ("confirmed", "pending", "not_needed") or reason not in END_REASONS:
            raise Problem("invalid_report", 400)
        with self.tx():
            row = self.worker_row(sid, worker, instance)
            if cleanup == "not_needed" and (reason != "exchange_failed" or row["status"] in ("active", "closing")):
                raise Problem("invalid_report", 400)
            status = row["status"] if row["status"] in ("failed", "lost", "closed") else "closed"
            effective = "confirmed" if row["cleanup"] == "confirmed" else cleanup
            if row["reason"] == "capability_withdrawn" and reason == "revoked":
                reason = "capability_withdrawn"
            self.db.execute("UPDATE session SET status=?,cleanup=?,reason=?,version=version+1 WHERE id=?",
                            (status, effective, reason, sid))
            self.event(worker, "session_finished", sid, {"cleanup": effective, "reason": reason}, trace=trace)
            self.release_confirmed(sid)

    def confirm_cleanup(self, sid, user, trace):
        with self.tx():
            row = self.owned(sid, user)
            if row["cleanup"] != "pending" or row["status"] not in ("closed", "failed", "lost"):
                raise Problem("cleanup_not_pending", 409)
            self.db.execute("UPDATE session SET cleanup='confirmed',reason='manual_release',"
                            "version=version+1 WHERE id=?", (sid,))
            self.event(user, "manual_slot_release", sid, {"previous": "pending"}, trace=trace)
            self.release_confirmed(sid)

    def revoke(self, sid, user, trace):
        with self.tx():
            row = self.owned(sid, user)
            if row["status"] in ("pending", "connecting", "active"):
                status = "closed" if row["status"] == "pending" else "closing"
                self.db.execute("UPDATE session SET status=?,reason='revoked',version=version+1 WHERE id=?", (status, sid))
                self.event(user, "session_revoked", sid, trace=trace)
                self.release_confirmed(sid)

    def sweep(self):
        with self.tx():
            now = self.clock()
            for r in self.db.execute("SELECT * FROM session WHERE status IN ('pending','connecting','active','closing')").fetchall():
                status = None
                if r["status"] == "pending" and r["phase_until"] <= now:
                    status = "closed"
                elif r["status"] == "connecting" and r["phase_until"] <= now:
                    status = "failed"
                elif r["status"] in ("connecting", "active", "closing") and r["lease_until"] <= now:
                    status = "lost"
                if status:
                    self.db.execute("UPDATE session SET status=?,reason='deadline',version=version+1 WHERE id=?", (status, r["id"]))
                    self.event("reaper", "session_deadline", r["id"], {"status": status})
                    self.release_confirmed(r["id"])

    def public(self, sid, user):
        row = self.owned(sid, user)
        return {k: row[k] for k in ("id", "asset_id", "status", "cleanup", "reason", "created", "hard_until")}
