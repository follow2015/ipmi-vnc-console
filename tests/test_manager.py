"""Manager-side regressions: operator release endpoint and safe HTML output."""
import base64
import json
import sqlite3
import warnings
from pathlib import Path

import pytest

with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    from fastapi.testclient import TestClient

from kvmhub.common import BMC_BASE_URL, UI_ORIGIN, end_reason_message
from kvmhub.manager import build_apps
from kvmhub.store import Store
from tools.bootstrap import generate


@pytest.fixture
def manager_app(tmp_path):
    directory = generate(tmp_path / "identity")
    cfg = json.loads((directory / "manager.json").read_text())
    cfg["database"] = str(tmp_path / "release.sqlite3")
    key = base64.b64decode(Path(cfg["encryption_key"]).read_bytes())
    store = Store(cfg["database"], key)
    store.db.close()
    store.db = sqlite3.connect(cfg["database"], isolation_level=None, timeout=5,
                               check_same_thread=False)
    store.db.row_factory = sqlite3.Row
    store.seed_mock(BMC_BASE_URL, "aa"*32, "u", "p")
    ui, _ = build_apps(cfg, store)
    yield ui, store, directory, cfg
    store.close()


def claims(row):
    return {"sid": row["id"], "sub": row["user_id"], "aid": row["asset_id"],
            "wid": row["worker_id"], "iid": row["instance_id"], "jti": row["jti"]}


def login(client, directory):
    origin = {"Origin": UI_ORIGIN}
    token = (directory / "login-token").read_text().strip()
    assert client.post("/api/login", headers=origin, json={"token": token}).status_code == 200
    csrf = client.get("/api/me").json()["csrf"]
    return {**origin, "X-CSRF-Token": csrf}


def test_manual_release_endpoint_is_csrf_protected_and_audited(manager_app):
    ui, store, directory, cfg = manager_app
    client = TestClient(ui, base_url=UI_ORIGIN)
    headers = login(client, directory)
    row = store.allocate("mock-1", "local-admin", cfg["worker_id"], cfg["instance_id"], "trace")
    store.exchange(claims(row), "trace")
    store.db.execute("UPDATE session SET status='failed',phase_until=0 WHERE id=?", (row["id"],))
    url = f'/api/sessions/{row["id"]}/release'
    assert client.post(url, headers={"Origin": headers["Origin"]}).status_code == 403
    assert client.post(url, headers=headers).status_code == 200
    assert store.get(row["id"])["cleanup"] == "confirmed"
    assert store.allocate("mock-1", "local-admin", cfg["worker_id"], cfg["instance_id"], "trace")["id"] != row["id"]
    events = list(store.db.execute("SELECT actor,action FROM audit WHERE action='manual_slot_release'"))
    assert len(events) == 1 and events[0]["actor"] == "local-admin"


def test_a_finished_session_explains_why_it_ended(manager_app):
    ui, store, directory, cfg = manager_app
    client = TestClient(ui, base_url=UI_ORIGIN)
    login(client, directory)
    row = store.allocate("mock-1", "local-admin", cfg["worker_id"], cfg["instance_id"], "trace")
    store.db.execute("UPDATE session SET status='closed',cleanup='confirmed',"
                     "reason='client_message_denied' WHERE id=?", (row["id"],))
    body = client.get("/").text
    assert "client_message_denied" in body
    assert end_reason_message("client_message_denied") in body


def test_index_escapes_session_fields(manager_app):
    ui, store, directory, cfg = manager_app
    client = TestClient(ui, base_url=UI_ORIGIN)
    login(client, directory)
    row = store.allocate("mock-1", "local-admin", cfg["worker_id"], cfg["instance_id"], "trace")
    store.db.execute("UPDATE session SET cleanup=? WHERE id=?", ("<script>alert(1)</script>", row["id"]))
    body = client.get("/").text
    assert "<script>alert(1)</script>" not in body
    assert "&lt;script&gt;" in body


def test_a_busy_asset_is_refused_with_a_sentence_not_a_code(manager_app):
    ui, store, directory, cfg = manager_app
    client = TestClient(ui, base_url=UI_ORIGIN)
    headers = login(client, directory)
    first = client.post("/api/assets/mock-1/sessions", headers=headers)
    assert first.status_code == 200
    second = client.post("/api/assets/mock-1/sessions", headers=headers)
    assert second.status_code == 409
    body = second.json()
    assert body["error"] == "asset_busy"
    assert body["message"] and "稍后重试" in body["message"]
    assert body["trace_id"], "the trace id must survive so support can follow the event"
