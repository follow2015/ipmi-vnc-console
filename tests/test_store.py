import concurrent.futures
import sqlite3

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from kvmhub.common import BMC_BASE_URL, Problem, issue, verify
from kvmhub.store import Store


@pytest.fixture
def setup_store(tmp_path):
    now = [2_000_000_000.0]
    path = tmp_path / "test.sqlite"
    key = b"k" * 32
    store = Store(path, key, clock=lambda: now[0])
    store.seed_mock(BMC_BASE_URL, "aa"*32, "fixture-user", "fixture-password")
    yield store, now, path, key
    store.close()


def claims(row):
    return {"sid": row["id"], "sub": row["user_id"], "aid": row["asset_id"], "wid": row["worker_id"],
            "iid": row["instance_id"], "jti": row["jti"]}


def test_exchange_is_single_use_and_ciphertext_only(setup_store):
    store, now, path, key = setup_store
    row = store.allocate("mock-1", "local-admin", "w1", "i1", "trace")
    result = store.exchange(claims(row), "trace")
    assert result["password"] == "fixture-password"
    with pytest.raises(Problem, match="ticket_consumed"):
        store.exchange(claims(row), "trace")
    assert b"fixture-password" not in path.read_bytes()
    assert "fixture-password" not in str(list(store.db.execute("SELECT * FROM audit")))


def test_concurrent_allocation_uses_database_constraint(setup_store):
    store, now, path, key = setup_store

    def allocate():
        second = Store(path, key, clock=lambda: now[0])
        try:
            second.allocate("mock-1", "local-admin", "w1", "i1", "trace")
            return "ok"
        except Problem as exc:
            return exc.code
        finally:
            second.close()
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(lambda _: allocate(), range(2))) == ["asset_busy", "ok"]


@pytest.mark.parametrize("mutation", ["missing", "expired", "revoked", "mismatch", "unapproved_adapter"])
def test_capability_is_enforced_at_exchange(setup_store, mutation):
    store, now, *_ = setup_store
    row = store.allocate("mock-1", "local-admin", "w1", "i1", "trace")
    if mutation in ("missing", "revoked"):
        store.db.execute("UPDATE adapter_capability SET status='unverified'")
    elif mutation == "expired":
        store.db.execute("UPDATE adapter_capability SET expires=?", (now[0]-1,))
    elif mutation == "mismatch":
        store.db.execute("UPDATE asset SET firmware='2'")
    else:
        store.db.execute("UPDATE adapter_capability SET adapter='real-bmc'")
    with pytest.raises(Problem, match="adapter_not_verified"):
        store.exchange(claims(row), "trace")
    assert store.get(row["id"])["consumed"] == 0


def test_connecting_timeout_cannot_release_unknown_upstream(setup_store):
    store, now, *_ = setup_store
    row = store.allocate("mock-1", "local-admin", "w1", "i1", "trace")
    store.exchange(claims(row), "trace")
    now[0] += 31
    store.sweep()
    ended = store.get(row["id"])
    assert ended["status"] == "failed"
    assert ended["cleanup"] == "pending"
    with pytest.raises(Problem, match="asset_busy"):
        store.allocate("mock-1", "local-admin", "w1", "i1", "trace")
    store.finish(row["id"], "w1", "i1", "pending", "login_failed")
    with pytest.raises(Problem, match="asset_busy"):
        store.allocate("mock-1", "local-admin", "w1", "i1", "trace")
    store.finish(row["id"], "w1", "i1", "confirmed", "login_failed")
    assert store.allocate("mock-1", "local-admin", "w1", "i1", "trace")["id"] != row["id"]


def test_unexchanged_ticket_expires_and_releases_slot(setup_store):
    store, now, *_ = setup_store
    row = store.allocate("mock-1", "local-admin", "w1", "i1", "trace")
    now[0] += 61
    store.sweep()
    assert store.get(row["id"])["status"] == "closed"
    store.allocate("mock-1", "local-admin", "w1", "i1", "trace")


def test_revoke_blocks_activation_renewal_and_stale_instance(setup_store):
    store, now, *_ = setup_store
    row = store.allocate("mock-1", "local-admin", "w1", "i1", "trace")
    store.exchange(claims(row), "trace")
    store.revoke(row["id"], "local-admin", "trace")
    with pytest.raises(Problem, match="session_revoked"):
        store.renew(row["id"], "w1", "i1", activate=True)
    with pytest.raises(Problem, match="instance_mismatch"):
        store.finish(row["id"], "w1", "old", "confirmed", "revoked")
    assert store.get(row["id"])["cleanup"] == "pending"


def test_decryption_failure_releases_slot_when_no_upstream_was_possible(setup_store):
    store, now, *_ = setup_store
    row = store.allocate("mock-1", "local-admin", "w1", "i1", "trace")
    store.db.execute("UPDATE asset SET credential=?", (b"damaged",))
    with pytest.raises(Problem, match="credential_unavailable"):
        store.exchange(claims(row), "trace")
    ended = store.get(row["id"])
    assert ended["consumed"] == 1
    assert ended["status"] == "failed"
    assert ended["cleanup"] == "not_needed"
    assert store.allocate("mock-1", "local-admin", "w1", "i1", "trace")["id"] != row["id"]


def test_finish_accepts_not_needed_for_exchange_failure(setup_store):
    store, now, *_ = setup_store
    row = store.allocate("mock-1", "local-admin", "w1", "i1", "trace")
    store.exchange(claims(row), "trace")
    store.finish(row["id"], "w1", "i1", "not_needed", "exchange_failed")
    assert store.get(row["id"])["cleanup"] == "not_needed"
    assert store.allocate("mock-1", "local-admin", "w1", "i1", "trace")["id"] != row["id"]


@pytest.mark.parametrize("status", ["active", "closing"])
def test_not_needed_cannot_release_a_live_upstream(setup_store, status):
    store, *_ = setup_store
    row = store.allocate("mock-1", "local-admin", "w1", "i1", "trace")
    store.exchange(claims(row), "trace")
    store.renew(row["id"], "w1", "i1", activate=True)
    if status == "closing":
        store.revoke(row["id"], "local-admin", "trace")
    with pytest.raises(Problem, match="invalid_report"):
        store.finish(row["id"], "w1", "i1", "not_needed", "exchange_failed")
    assert store.get(row["id"])["status"] == status
    with pytest.raises(Problem, match="asset_busy"):
        store.allocate("mock-1", "local-admin", "w1", "i1", "trace")


def test_manual_release_frees_pending_slot_and_is_audited(setup_store):
    store, now, *_ = setup_store
    row = store.allocate("mock-1", "local-admin", "w1", "i1", "trace")
    store.exchange(claims(row), "trace")
    now[0] += 31
    store.sweep()
    assert store.get(row["id"])["cleanup"] == "pending"
    with pytest.raises(Problem, match="asset_busy"):
        store.allocate("mock-1", "local-admin", "w1", "i1", "trace")
    store.confirm_cleanup(row["id"], "local-admin", "release-trace")
    assert store.get(row["id"])["cleanup"] == "confirmed"
    assert store.allocate("mock-1", "local-admin", "w1", "i1", "trace")["id"] != row["id"]
    events = list(store.db.execute("SELECT actor,action,trace_id FROM audit WHERE action='manual_slot_release'"))
    assert len(events) == 1
    assert events[0]["actor"] == "local-admin" and events[0]["trace_id"] == "release-trace"


def test_manual_release_refuses_live_session_and_unknown_user(setup_store):
    store, now, *_ = setup_store
    row = store.allocate("mock-1", "local-admin", "w1", "i1", "trace")
    with pytest.raises(Problem, match="cleanup_not_pending"):
        store.confirm_cleanup(row["id"], "local-admin", "trace")
    store.exchange(claims(row), "trace")
    with pytest.raises(Problem, match="permission_denied"):
        store.confirm_cleanup(row["id"], "intruder", "trace")


def test_user_authorization_and_audit_append_only(setup_store):
    store, now, *_ = setup_store
    with pytest.raises(Problem, match="permission_denied"):
        store.allocate("mock-1", "intruder", "w1", "i1", "trace")
    row = store.allocate("mock-1", "local-admin", "w1", "i1", "trace")
    with pytest.raises(Problem, match="permission_denied"):
        store.public(row["id"], "intruder")
    with pytest.raises(sqlite3.IntegrityError, match="append only"):
        store.db.execute("DELETE FROM audit")


def test_ticket_requires_instance_claims_and_signature():
    import time
    key = Ed25519PrivateKey.generate()
    row = {"id": "s", "user_id": "u", "asset_id": "a", "worker_id": "w1", "instance_id": "i1",
           "jti": "j", "hard_until": time.time()+3600}
    ticket = issue(key, row, time.time())
    assert verify(key.public_key(), ticket, "w1", "i1")["sid"] == "s"
    with pytest.raises(Problem, match="invalid_ticket"):
        verify(key.public_key(), ticket, "w1", "i2")
    with pytest.raises(Problem, match="invalid_ticket"):
        verify(Ed25519PrivateKey.generate().public_key(), ticket, "w1", "i1")
