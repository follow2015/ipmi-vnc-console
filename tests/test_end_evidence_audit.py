"""M1: an ending's shape must survive all the way into the Manager's audit log."""
import asyncio
import base64
import json
import sqlite3
import time
import warnings
from pathlib import Path
from types import SimpleNamespace

import socket

import aiohttp
import pytest

with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    from fastapi.testclient import TestClient

from kvmhub import worker as worker_module
from kvmhub.common import BMC_BASE_URL, INTERNAL_PORT
from kvmhub.manager import build_apps
from kvmhub.store import Store
from kvmhub.telemetry import audit_evidence
from kvmhub.worker import Gateway, Runtime
from tools.bootstrap import generate


@pytest.fixture
def env(tmp_path):
    directory = generate(tmp_path / "identity")
    manager_cfg = json.loads((directory / "manager.json").read_text())
    manager_cfg["database"] = str(tmp_path / "manager.sqlite3")
    key = base64.b64decode(Path(manager_cfg["encryption_key"]).read_bytes())
    store = Store(manager_cfg["database"], key)
    store.db.close()
    store.db = sqlite3.connect(manager_cfg["database"], isolation_level=None, timeout=5,
                               check_same_thread=False)
    store.db.row_factory = sqlite3.Row
    store.seed_mock(BMC_BASE_URL, "aa" * 32, "u", "p")
    worker_cfg = json.loads((directory / "worker.json").read_text())
    yield SimpleNamespace(store=store, manager_cfg=manager_cfg,
                          worker_cfg=worker_cfg, directory=directory)
    store.close()


def session(env):
    row = env.store.allocate("mock-1", "local-admin", env.manager_cfg["worker_id"],
                             env.manager_cfg["instance_id"], "trace")
    return row["id"]


def audit_detail(env, sid):
    rows = list(env.store.db.execute(
        "SELECT detail FROM audit WHERE action='session_finished' AND session_id=? ORDER BY id", (sid,)))
    return [json.loads(r["detail"]) for r in rows]


def shape(**overrides):
    record = {
        "sid": "s" * 32, "started_at": "2026-11-14T18:00:00+08:00",
        "ended_at": "2026-11-14T18:00:02+08:00", "end_reason": "upstream_error",
        "cleanup": "pending", "duration_ms": 2000, "connections": 2, "reconnects": 1,
        "upstream_close_code": 1006, "client_bytes": 120, "server_bytes": 900,
        "key_events": 7, "peak_buffered_bytes": 4096, "recoveries": 1,
        "recovery_attempts": 2, "recovery_last_error": "bmc_auth_failed",
        "recovery_latency_ms": 740, "dropped_input": 3,
        "recovery_input_replayed": 1, "recovery_input_dropped": 0,
        "geometry_reloads": 1,
        "client_message_types": {"4": 7, "5": 7},
        "client_message_summary": "4:7,5:7",
        "denied": {"kind": 250, "length": 18},
    }
    record.update(overrides)
    return record



def test_audit_evidence_keeps_only_shape_fields():
    summary = audit_evidence(shape())
    assert summary["upstream_close_code"] == 1006
    assert summary["recovery_last_error"] == "bmc_auth_failed"
    assert summary["denied"] == {"kind": 250, "length": 18}
    assert summary["client_message_types"] == {"4": 7, "5": 7}
    assert summary["duration_ms"] == 2000 and summary["dropped_input"] == 3
    assert summary["geometry_reloads"] == 1
    for forbidden in ("sid", "started_at", "ended_at", "end_reason", "cleanup",
                      "client_message_summary", "password", "keys"):
        assert forbidden not in summary
    assert set(summary) == {
        "duration_ms", "connections", "reconnects", "upstream_close_code",
        "client_bytes", "server_bytes", "key_events", "peak_buffered_bytes",
        "recoveries", "recovery_attempts", "recovery_last_error",
        "recovery_latency_ms", "dropped_input", "client_message_types", "denied",
        "recovery_input_replayed", "recovery_input_dropped", "geometry_reloads",
    }


def test_audit_evidence_drops_untrusted_values_instead_of_coercing_them():
    summary = audit_evidence({
        "duration_ms": -5,
        "connections": True,
        "reconnects": "3",
        "upstream_close_code": 2 ** 80,
        "client_bytes": [1, 2],
        "recovery_last_error": "device at the lab says no",
        "denied": {"kind": 250, "length": 18, "payload": "secret"},
        "client_message_types": {"4": 7, "not-a-type": 3, "-1": 2, "4.5": 1, "256": 5},
        "sid": "s" * 32, "injected": {"anything": "goes"},
    })
    assert "duration_ms" not in summary and "connections" not in summary
    assert "reconnects" not in summary and "upstream_close_code" not in summary
    assert "client_bytes" not in summary and "recovery_last_error" not in summary
    assert summary["denied"] == {"kind": 250, "length": 18}
    assert summary["client_message_types"] == {"4": 7}
    assert "sid" not in summary and "injected" not in summary


def test_audit_evidence_bounds_the_audit_row():
    many = {str(k): 2 ** 31 - 1 for k in range(256)}
    summary = audit_evidence(shape(client_message_types=many))
    assert len(json.dumps(summary, separators=(",", ":"))) <= 1024
    assert len(summary.get("client_message_types", {})) <= 32
    assert audit_evidence("not a dict") == {}
    assert audit_evidence(None) == {}



def test_finish_persists_evidence_in_the_audit_log_and_the_session_row(env):
    sid = session(env)
    raw = shape(payload="hunter2", keys="SentinelSeq9")
    env.store.finish(sid, env.manager_cfg["worker_id"], env.manager_cfg["instance_id"],
                     "pending", "upstream_error", evidence=raw)
    detail = audit_detail(env, sid)[0]
    assert detail["cleanup"] == "pending" and detail["reason"] == "upstream_error"
    assert detail["evidence"]["upstream_close_code"] == 1006
    assert detail["evidence"] == audit_evidence(raw)
    assert "hunter2" not in json.dumps(detail) and "SentinelSeq9" not in json.dumps(detail)
    stored = json.loads(env.store.get(sid)["end_evidence"])
    assert stored == detail["evidence"]
    assert env.store.public(sid, "local-admin")["end_evidence"] == stored


def test_finish_without_evidence_keeps_the_old_report_shape(env):
    sid = session(env)
    env.store.finish(sid, env.manager_cfg["worker_id"], env.manager_cfg["instance_id"],
                     "confirmed", "client_closed")
    assert audit_detail(env, sid)[0] == {"cleanup": "confirmed", "reason": "client_closed"}
    assert env.store.get(sid)["end_evidence"] is None
    assert env.store.public(sid, "local-admin")["end_evidence"] is None


def test_a_late_duplicate_report_does_not_overwrite_the_first_ending(env):
    sid = session(env)
    worker, instance = env.manager_cfg["worker_id"], env.manager_cfg["instance_id"]
    env.store.finish(sid, worker, instance, "pending", "upstream_error",
                     evidence=shape(upstream_close_code=1006))
    env.store.finish(sid, worker, instance, "confirmed", "client_closed",
                     evidence=shape(upstream_close_code=4000))
    assert audit_detail(env, sid)[0]["evidence"]["upstream_close_code"] == 1006
    assert json.loads(env.store.get(sid)["end_evidence"])["upstream_close_code"] == 1006


async def test_internal_finish_endpoint_normalises_the_body(env, monkeypatch):
    from aiohttp.test_utils import TestClient, TestServer

    from kvmhub import internal_api

    sid = session(env)
    monkeypatch.setattr(internal_api, "check_worker_credentials", lambda *args, **kwargs: None)
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    app = internal_api.create_app(env.manager_cfg, env.store, expected_host=f"127.0.0.1:{port}")
    body = {"cleanup": "confirmed", "reason": "upstream_error",
            "evidence": {**shape(upstream_close_code=12592), "injected": "evil"}}
    async with TestClient(TestServer(app, port=port)) as client:
        response = await client.post(f"/internal/v1/sessions/{sid}/finish", json=body)
        assert response.status == 200, await response.text()
    detail = audit_detail(env, sid)[0]
    assert detail["evidence"]["upstream_close_code"] == 12592
    assert detail["evidence"] == audit_evidence(body["evidence"])
    assert "injected" not in json.dumps(detail)



async def _closed():
    return True


def _gateway_with_upstream(env, sid="sid"):
    gateway = Gateway(env.worker_cfg)
    sess = Runtime(sid, "hash", SimpleNamespace(close=_closed), time.monotonic() + 30)
    upstream = SimpleNamespace(
        as_dict=lambda: {"client_bytes": 42, "server_bytes": 99,
                         "client_message_types": {4: 3},
                         "recoveries": 1, "recovery_last_error": "bmc_auth_failed"},
        close_code=1006, client_key_events=3)
    sess.telemetry.note_connection(upstream)
    gateway.sessions[sid] = sess
    return gateway, sess


async def test_worker_finish_reports_the_end_shape_without_payload(env):
    gateway, sess = _gateway_with_upstream(env)
    sent = []

    async def capture(sid, operation, data=None):
        sent.append((operation, data))
        return {"ok": True}

    gateway.call = capture
    await gateway.finish(sess, "upstream_error")
    assert sent[0][0] == "finish"
    body = sent[0][1]
    assert body["cleanup"] == "confirmed" and body["reason"] == "upstream_error"
    assert body["evidence"]["upstream_close_code"] == 1006
    assert body["evidence"]["key_events"] == 3
    assert body["evidence"]["recovery_last_error"] == "bmc_auth_failed"
    assert "sid" not in body["evidence"] and "started_at" not in body["evidence"]
    assert "client_message_summary" not in body["evidence"]
    assert gateway.evidence.recent(1, mask=False)[0]["upstream_close_code"] == 1006


async def test_a_retry_resends_the_stored_evidence_unchanged(env, monkeypatch):
    clock = [100.0]
    monkeypatch.setattr(worker_module, "time", SimpleNamespace(monotonic=lambda: clock[0]))
    gateway, sess = _gateway_with_upstream(env)

    async def unavailable(*args, **kwargs):
        raise aiohttp.ClientConnectionError()

    gateway.call = unavailable
    await gateway.finish(sess, "upstream_error")
    pending = gateway.due_reports(clock[0] + 3600)[0][1]
    assert pending["evidence"]["upstream_close_code"] == 1006

    resent = []

    async def capture(sid, operation, data=None):
        resent.append(data)
        return {"ok": True}

    gateway.call = capture
    clock[0] = 4600.0
    task = asyncio.create_task(gateway.supervise())
    await asyncio.sleep(0.35)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert resent == [pending]
    assert resent[0]["evidence"]["upstream_close_code"] == 1006


async def test_report_without_evidence_still_uses_the_legacy_body(env):
    gateway = Gateway(env.worker_cfg)
    sent = []

    async def capture(sid, operation, data=None):
        sent.append(data)
        return {"ok": True}

    gateway.call = capture
    await gateway.report("sid", "not_needed", "exchange_failed")
    assert sent == [{"cleanup": "not_needed", "reason": "exchange_failed"}]


async def test_a_relay_offering_payload_leaves_none_in_the_manager_audit(env):
    sid = session(env)
    gateway, sess = _gateway_with_upstream(env, sid=sid)

    def noisy():
        return {"client_bytes": 42, "server_bytes": 99, "client_message_types": {4: 3},
                "recoveries": 1, "recovery_last_error": "bmc_auth_failed",
                "payload": b"password", "last_key": "Q", "sentinel": "Zx9Qv"}

    sess.telemetry.upstream.as_dict = noisy
    sent = []

    async def capture(sid, operation, data=None):
        sent.append(data)
        return {"ok": True}

    gateway.call = capture
    await gateway.finish(sess, "upstream_error")
    body = sent[0]
    env.store.finish(sid, env.manager_cfg["worker_id"], env.manager_cfg["instance_id"],
                     body["cleanup"], body["reason"], evidence=body["evidence"])
    durable = json.dumps(audit_detail(env, sid)[0]) + json.dumps(env.store.get(sid)["end_evidence"])
    assert "password" not in durable and "Zx9Qv" not in durable
    assert "last_key" not in durable and "payload" not in durable


async def test_worker_body_reaches_the_manager_audit(env):
    sid = session(env)
    gateway, sess = _gateway_with_upstream(env, sid=sid)
    sent = []

    async def capture(sid, operation, data=None):
        sent.append(data)
        return {"ok": True}

    gateway.call = capture
    await gateway.finish(sess, "upstream_error")
    body = sent[0]
    env.store.finish(sid, env.manager_cfg["worker_id"], env.manager_cfg["instance_id"],
                     body["cleanup"], body["reason"], evidence=body.get("evidence"))
    assert audit_detail(env, sid)[0]["evidence"]["upstream_close_code"] == 1006


def test_the_last_two_m1_shape_fields_reach_both_durable_copies(env):
    sid = session(env)
    summary = audit_evidence(shape(exception_type="OSError", since_last_rx_s=4.2))
    env.store.finish(sid, env.manager_cfg["worker_id"], env.manager_cfg["instance_id"],
                     "confirmed", "client_closed", evidence=summary)
    detail = audit_detail(env, sid)[0]["evidence"]
    assert detail["exception_type"] == "OSError"
    assert detail["since_last_rx_s"] == 4.2
    assert json.loads(env.store.get(sid)["end_evidence"]) == detail


def test_a_hostile_class_name_is_dropped_by_the_manager(env):
    sid = session(env)
    env.store.finish(sid, env.manager_cfg["worker_id"], env.manager_cfg["instance_id"],
                     "confirmed", "client_closed",
                     evidence={"exception_type": "device says Zx9Qv", "since_last_rx_s": -1})
    detail = audit_detail(env, sid)[0]
    assert "Zx9Qv" not in json.dumps(detail)
    assert "exception_type" not in detail.get("evidence", {})
    assert "since_last_rx_s" not in detail.get("evidence", {})
