"""The kvm_quota_usage roll-up: derived from raw records, never double-written."""
from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from kvmhub.common import BMC_BASE_URL
from kvmhub.platform import services
from kvmhub.platform.api import create_app
from kvmhub.platform.config import Settings
from kvmhub.platform.db import bootstrap_platform_admin, init_schema, seed_roles, transaction
from kvmhub.platform.redis_state import MemoryState
from kvmhub.store import Store

KEY = b"0123456789abcdef0123456789abcdef"
ORIGIN = "http://testserver"
PERIOD = "2026-11"
START = datetime(2026, 11, 1, tzinfo=timezone.utc).timestamp()
NOW = datetime(2026, 11, 20, tzinfo=timezone.utc).timestamp()


@pytest.fixture
def rig(tmp_path):
    cfg = Settings(env="test", db_url=f"sqlite:///{tmp_path}/control.db", redis_url="",
                   credential_key=KEY, session_ttl=3600, lease_seconds=30,
                   bootstrap_admin=None, bootstrap_password=None, strict_prod=False)
    app = create_app(cfg, state=MemoryState())
    platform = app.state.platform

    plane_db = tmp_path / "plane.db"
    store = Store(str(plane_db), KEY)
    store.seed_mock(BMC_BASE_URL, "aa" * 32, "fixture-user", "fixture-password")
    store.close()

    with transaction(platform.factory) as db:
        init_schema(platform.engine)
        seed_roles(db)
        alpha = services.create_tenant(db, code="alpha", name="Alpha", actor="test")
        beta = services.create_tenant(db, code="beta", name="Beta", actor="test")
        services.create_tenant(db, code="gamma", name="Gamma", actor="test")
        services.create_user(db, "alpha-admin", "synthetic-password", "admin",
                             actor="test", tenant_id=alpha.id)
        bootstrap_platform_admin(db, "platform", "synthetic-password")
        services.upsert_asset(db, name="node-1", address="192.0.2.11",
                              actor="test", tenant_id=alpha.id)
        for sid, tenant_id in (("sid-a", alpha.id), ("sid-b", alpha.id), ("sid-c", beta.id)):
            services.audit(db, "test", "console_ticket_issued", tenant_id=tenant_id,
                           detail={"sid": sid}, now=START + 100)
    return SimpleNamespace(app=app, platform=platform, plane_db=plane_db,
                           alpha=alpha.id, beta=beta.id)


def seed_plane(rig):
    store = Store(str(rig.plane_db), KEY)
    try:
        sessions = (
            ("sid-a", START + 100, 3600, 1, START + 110, START + 230),
            ("sid-b", START + 100, 3600, 0, START + 110, START + 230),
            ("sid-c", START + 200, 300, 1, START + 205, START + 325),
            ("sid-foreign", START + 200, 300, 1, START + 205, START + 325),
        )
        for sid, created, hard, consumed, consumed_at, finished in sessions:
            store.db.execute(
                "INSERT INTO session(id,user_id,asset_id,worker_id,instance_id,jti,"
                "consumed,status,created,phase_until,lease_until,hard_until) "
                "VALUES(?,?,?,?,?,?,?,'closed',?,?,?,?)",
                (sid, "local-admin", "mock-1", "w1", "i1", sid + "-jti", consumed,
                 created, created + 60, created + 30, created + hard))
            store.db.execute(
                "INSERT INTO audit(ts,trace_id,actor,action,session_id,detail) "
                "VALUES(?,?,?,?,?,?)", (consumed_at, "t", "w1", "ticket_consumed", sid, "{}"))
            store.db.execute(
                "INSERT INTO audit(ts,trace_id,actor,action,session_id,detail) "
                "VALUES(?,?,?,?,?,?)", (finished, "t", "w1", "session_finished", sid, "{}"))
    finally:
        store.close()


def test_period_bounds_reject_a_local_or_impossible_month():
    for bad in ("", "2026-1", "2026-13", "2026/11", "26-11", "2026-11-01"):
        with pytest.raises(services.PlatformError, match="invalid_period"):
            services.period_bounds(bad)
    assert services.period_bounds(PERIOD) == (START, datetime(
        2026, 12, 1, tzinfo=timezone.utc).timestamp())


def test_rebuild_counts_only_exchanged_tickets_and_is_repeatable(rig):
    seed_plane(rig)
    with transaction(rig.platform.factory) as db:
        summary = services.rebuild_quota_usage(db, plane_db=str(rig.plane_db),
                                               period=PERIOD, now=NOW)
        first = services.quota_usage_view(db, PERIOD)
        again = services.rebuild_quota_usage(db, plane_db=str(rig.plane_db),
                                             period=PERIOD, now=NOW)
        second = services.quota_usage_view(db, PERIOD)
    assert summary == again
    assert [row["tenant_code"] for row in first] == ["alpha", "beta", "default", "gamma"]
    by_code = {row["tenant_code"]: row for row in first}
    assert (by_code["alpha"]["assets"], by_code["alpha"]["sessions"],
            by_code["alpha"]["minutes"]) == (1, 1, 2)
    assert (by_code["beta"]["assets"], by_code["beta"]["sessions"],
            by_code["beta"]["minutes"]) == (0, 1, 2)
    assert (by_code["gamma"]["assets"], by_code["gamma"]["sessions"],
            by_code["gamma"]["minutes"]) == (0, 0, 0)
    assert (by_code["default"]["sessions"], by_code["default"]["minutes"]) == (0, 0)
    assert first == second
    assert all(row["updated"] == NOW for row in second)


def test_api_reads_the_snapshot_on_the_platform_channel_only(rig):
    seed_plane(rig)
    with transaction(rig.platform.factory) as db:
        services.rebuild_quota_usage(db, plane_db=str(rig.plane_db),
                                     period=PERIOD, now=NOW)
    with TestClient(rig.app, base_url=ORIGIN) as client:
        assert client.post("/api/v2/platform/login", json={"username": "platform",
                                                           "password": "synthetic-password"}).status_code == 200
        rows = client.get(f"/api/v2/platform/quota-usage?period={PERIOD}")
        assert rows.status_code == 200, rows.text
        assert {row["tenant_code"] for row in rows.json()} == {"alpha", "beta", "default", "gamma"}
        assert client.get("/api/v2/platform/quota-usage?period=2026-99").status_code == 400
        client.cookies.clear()
        assert client.post("/api/v2/login", json={"username": "alpha-admin",
                                                  "password": "synthetic-password"}).status_code == 200
        refused = client.get(f"/api/v2/platform/quota-usage?period={PERIOD}")
        assert refused.status_code == 403
    rig.platform.engine.dispose()
