"""Real-MySQL concurrency contract for the data-plane Store."""
from __future__ import annotations

import concurrent.futures
import os
import threading
import uuid

import pytest

from kvmhub.common import Problem
from kvmhub.store import Store

DSN = os.environ.get("KVMHUB_TEST_MYSQL_DSN", "")
REQUIRE_MYSQL = os.environ.get("KVMHUB_REQUIRE_MYSQL", "").strip().lower() in ("1", "true", "yes")


@pytest.fixture(autouse=True)
def _mysql_gate():
    if not DSN:
        if REQUIRE_MYSQL:
            pytest.fail("KVMHUB_REQUIRE_MYSQL=1 but KVMHUB_TEST_MYSQL_DSN is not configured")
        pytest.skip("no real MySQL DSN (KVMHUB_TEST_MYSQL_DSN)")


@pytest.fixture
def store():
    s = Store(DSN, b"k" * 32)
    prefix = "t" + uuid.uuid4().hex[:12]
    user = prefix + "-u"
    aid1, aid2 = prefix + "-a", prefix + "-b"
    created = False
    try:
        s.seed_mock("127.0.0.1:5900", "0" * 64, "admin", "secret")
        for aid in (aid1, aid2):
            s.register_asset(asset_id=aid, name=aid, vendor="mock", model="test-console",
                             firmware="1", capability_id="mock-v1",
                             target="127.0.0.1:5900", fingerprint="0" * 64,
                             username="admin", password="placeholder-secret", user_id=user)
        created = True
        yield s, {"user": user, "assets": (aid1, aid2)}
    finally:
        if created:
            with s.tx():
                s.db.execute("DELETE FROM asset_slot WHERE asset_id IN (?,?)", (aid1, aid2))
                s.db.execute("DELETE FROM session WHERE user_id=?", (user,))
                s.db.execute("DELETE FROM access_grant WHERE user_id=? OR asset_id IN (?,?)",
                             (user, aid1, aid2))
                s.db.execute("DELETE FROM asset WHERE id IN (?,?)", (aid1, aid2))
        s.close()


def _claims(row):
    return {"sid": row["id"], "sub": row["user_id"], "aid": row["asset_id"],
            "wid": row["worker_id"], "iid": row["instance_id"], "jti": row["jti"]}


def test_concurrent_exchange_consumes_a_ticket_once(store):
    s, ids = store
    row = s.allocate(ids["assets"][0], ids["user"], "w1", "i1", "0" * 32)
    claims = _claims(row)
    barrier = threading.Barrier(2)

    def attempt():
        own = Store(DSN, b"k" * 32)
        barrier.wait()
        try:
            own.exchange(claims, "0" * 32)
            return "ok"
        except Problem as exc:
            return exc.code
        finally:
            own.close()

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: attempt(), range(2)))
    assert sorted(results) == ["ok", "ticket_consumed_or_expired"]


def test_renew_cannot_revive_a_revoked_session(store):
    s, ids = store
    asset = ids["assets"][0]
    row = s.allocate(asset, ids["user"], "w1", "i1", "0" * 32)
    s.exchange(_claims(row), "0" * 32)
    s.renew(row["id"], "w1", "i1", activate=True)
    assert s.get(row["id"])["status"] == "active"
    barrier = threading.Barrier(2)

    def renew():
        own = Store(DSN, b"k" * 32)
        barrier.wait()
        try:
            own.renew(row["id"], "w1", "i1")
            return "renewed"
        except Problem as exc:
            return exc.code
        finally:
            own.close()

    def revoke():
        own = Store(DSN, b"k" * 32)
        barrier.wait()
        try:
            own.force_revoke(row["id"], "test-admin", "0" * 32)
            return "revoked"
        finally:
            own.close()

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        f_renew = pool.submit(renew)
        f_revoke = pool.submit(revoke)
        f_renew.result()
        f_revoke.result()

    final = s.get(row["id"])["status"]
    assert final == "closing", "a renew must never re-activate a revoked row"


def test_sweep_decision_cannot_kill_a_renewed_lease(store):
    s, ids = store
    row = s.allocate(ids["assets"][0], ids["user"], "w1", "i1", "0" * 32)
    s.exchange(_claims(row), "0" * 32)
    sid = row["id"]
    s.db.execute("UPDATE session SET lease_until=? WHERE id=?", (1.0, sid))
    snapshot = Store(DSN, b"k" * 32, clock=lambda: 2.0)
    fresh = Store(DSN, b"k" * 32)
    try:
        with snapshot.tx():
            stale = snapshot.get(sid)
            assert stale["lease_until"] <= 2.0
            fresh.renew(sid, "w1", "i1")
            updated = snapshot.db.execute(
                "UPDATE session SET status='lost',reason='deadline',version=version+1 "
                f"WHERE id=? AND status=? AND version=? AND lease_until<=?",
                (sid, stale["status"], stale["version"], stale["lease_until"]))
            assert updated.rowcount == 0, "stale sweep decision must be rejected"
        assert s.get(sid)["status"] in ("active", "connecting")
    finally:
        snapshot.close()
        fresh.close()


def test_finish_keeps_confirmed_cleanup_under_a_late_pending(store):
    s, ids = store
    row = s.allocate(ids["assets"][0], ids["user"], "w1", "i1", "0" * 32)
    s.exchange(_claims(row), "0" * 32)
    s.renew(row["id"], "w1", "i1", activate=True)
    sid = row["id"]

    def finish(cleanup):
        own = Store(DSN, b"k" * 32)
        try:
            own.finish(sid, "w1", "i1", cleanup, "client_closed")
        finally:
            own.close()

    finish("confirmed")
    finish("pending")
    assert s.get(sid)["cleanup"] == "confirmed"
