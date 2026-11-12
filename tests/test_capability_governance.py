"""The compatibility matrix as a control, not a table (design §7)."""
import sqlite3
from pathlib import Path

import pytest

from kvmhub.common import BMC_BASE_URL, PASSTHROUGH_ADAPTER_ID, Problem
from kvmhub.store import Store

DAY = 86400.0
TARGET = "https://127.0.0.1:10443"
FINGERPRINT = "ab" * 32


@pytest.fixture
def env(tmp_path):
    now = [2_000_000_000.0]
    path = tmp_path / "gov.sqlite"
    key = b"k" * 32
    store = Store(path, key, clock=lambda: now[0], passthrough_targets=(TARGET,))
    yield store, now, path, key
    store.close()


def claims(row):
    return {"sid": row["id"], "sub": row["user_id"], "aid": row["asset_id"],
            "wid": row["worker_id"], "iid": row["instance_id"], "jti": row["jti"]}


def seed_real(store, **overrides):
    options = dict(target=TARGET, fingerprint=FINGERPRINT, username="u", password="p",
                   approver="albert", capability_id="x10", asset_id="a1", model="X10DRT-PS / SA5248M4",
                   firmware="8.78")
    options.update(overrides)
    store.seed_passthrough(**options)


def test_draft_is_registered_but_not_exchangeable(env):
    store, now, *_ = env
    store.register_capability({"id": "x10", "vendor": "Supermicro (Inspur OEM)",
                               "model": "X10DRT-PS / SA5248M4", "firmware": "8.78",
                               "adapter": PASSTHROUGH_ADAPTER_ID}, "albert", "walkthrough")
    assert store.capability("x10")["status"] == "draft"
    seed_real(store)
    store.suspend_capability("x10", actor="albert", reason="drill")
    _asset, reason = store.gate("a1", "local-admin")
    assert reason == "not_verified"
    with pytest.raises(Problem, match="adapter_not_verified"):
        store.allocate("a1", "local-admin", "w1", "i1", "trace")


def test_registration_refuses_a_second_entry_with_the_same_id(env):
    store, *_ = env
    entry = {"id": "x10", "vendor": "v", "model": "m", "adapter": PASSTHROUGH_ADAPTER_ID}
    store.register_capability(entry, "albert")
    with pytest.raises(Problem, match="capability_exists"):
        store.register_capability(entry, "albert")


@pytest.mark.parametrize("field", ["approver", "evidence", "licence", "console_impl"])
def test_approval_without_a_named_input_is_refused(env, field):
    store, now, *_ = env
    store.register_capability({"id": "x10", "vendor": "Supermicro (Inspur OEM)",
                               "model": "X10DRT-PS / SA5248M4", "firmware": "8.78",
                               "adapter": PASSTHROUGH_ADAPTER_ID}, "albert")
    args = {"actor": "albert", "approver": "albert", "evidence": "docs/x.json",
            "licence": "未取得书面许可", "console_impl": "AST2100",
            "review_due": now[0] + DAY, "expires": now[0] + DAY}
    args[field] = ""
    with pytest.raises(Problem, match="capability_incomplete"):
        store.approve_capability("x10", **args)
    assert store.capability("x10")["status"] == "draft"


@pytest.mark.parametrize("review_due,expires", [
    (0, DAY),
    (-DAY, DAY),
    (DAY, 0),
    (DAY, -DAY),
])
def test_approval_refuses_dates_that_are_already_stale(env, review_due, expires):
    store, now, *_ = env
    store.register_capability({"id": "x10", "vendor": "v", "model": "m",
                               "firmware": "8.78", "adapter": PASSTHROUGH_ADAPTER_ID}, "albert")
    with pytest.raises(Problem, match="capability_incomplete"):
        store.approve_capability("x10", actor="albert", approver="albert", evidence="e",
                                 licence="l", console_impl="c",
                                 review_due=now[0] + review_due, expires=now[0] + expires)


def test_approval_records_who_signed_it(env):
    store, now, *_ = env
    seed_real(store, approver="operator-a")
    entry = store.capability("x10")
    assert entry["status"] == "verified"
    assert entry["approver"] == "operator-a"
    detail = store.db.execute("SELECT detail FROM audit WHERE action='capability_approved'").fetchone()[0]
    assert "operator-a" in detail and "real-bmc-kvm-phase2" in detail


def test_review_overdue_closes_the_gate_without_rewriting_status(env):
    store, now, *_ = env
    seed_real(store)
    store.approve_capability("x10", actor="albert", approver="albert", evidence="e",
                             licence="l", console_impl="c",
                             review_due=now[0] + DAY, expires=now[0] + 365 * DAY)
    store.db.execute("UPDATE access_grant SET expires=?", (now[0] + 400 * DAY,))
    now[0] += 2 * DAY
    asset, reason = store.gate("a1", "local-admin")
    assert reason == "review_overdue"
    assert store.capability("x10")["status"] == "verified"
    with pytest.raises(Problem, match="adapter_not_verified"):
        store.allocate("a1", "local-admin", "w1", "i1", "trace")


def test_firmware_outside_the_approved_window_is_refused(env):
    store, now, *_ = env
    seed_real(store)
    store.approve_capability("x10", actor="albert", approver="albert", evidence="e",
                             licence="l", console_impl="c", firmware="",
                             firmware_min="8.70", firmware_max="8.79",
                             review_due=now[0] + DAY, expires=now[0] + DAY)
    assert store.gate("a1", "local-admin")[1] is None
    store.db.execute("UPDATE asset SET firmware='8.90'")
    assert store.gate("a1", "local-admin")[1] == "firmware_out_of_range"


def test_suspension_ends_the_live_session_and_keeps_the_slot(env):
    store, now, *_ = env
    store.seed_mock(BMC_BASE_URL, "aa" * 32, "u", "p")
    row = store.allocate("mock-1", "local-admin", "w1", "i1", "trace")
    store.exchange(claims(row), "trace")
    store.renew(row["id"], "w1", "i1", activate=True)

    result = store.suspend_capability("mock-v1", actor="albert", reason="firmware_upgraded")
    assert result["sessions"] == [row["id"]]
    live = store.get(row["id"])
    assert live["status"] == "closing" and live["reason"] == "capability_withdrawn"
    assert store.db.execute("SELECT 1 FROM asset_slot WHERE session_id=?", (row["id"],)).fetchone()
    with pytest.raises(Problem):
        store.allocate("mock-1", "local-admin", "w1", "i1", "trace")
    with pytest.raises(Problem, match="session_revoked"):
        store.renew(row["id"], "w1", "i1")
    store.finish(row["id"], "w1", "i1", "confirmed", "revoked")
    ended = store.get(row["id"])
    assert ended["status"] == "closed" and ended["reason"] == "capability_withdrawn"
    with pytest.raises(Problem, match="adapter_not_verified"):
        store.allocate("mock-1", "local-admin", "w1", "i1", "trace")


def test_expiry_under_a_live_session_is_reported_as_its_own_reason(env):
    store, now, *_ = env
    store.seed_mock(BMC_BASE_URL, "aa" * 32, "u", "p")
    store.approve_capability("mock-v1", actor="albert", approver="albert", evidence="e",
                             licence="l", console_impl="c",
                             review_due=now[0] + 3600, expires=now[0] + 30 * DAY)
    row = store.allocate("mock-1", "local-admin", "w1", "i1", "trace")
    store.exchange(claims(row), "trace")
    store.renew(row["id"], "w1", "i1", activate=True)

    now[0] += 3700
    store.db.execute("UPDATE session SET lease_until=? WHERE id=?", (now[0] + 30, row["id"]))
    with pytest.raises(Problem, match="capability_withdrawn"):
        store.renew(row["id"], "w1", "i1")
    assert store.get(row["id"])["reason"] == "capability_withdrawn"
    store.finish(row["id"], "w1", "i1", "confirmed", "capability_withdrawn")
    assert store.get(row["id"])["status"] == "closed"


def test_pending_session_is_closed_and_released_without_a_worker(env):
    store, now, *_ = env
    store.seed_mock(BMC_BASE_URL, "aa" * 32, "u", "p")
    row = store.allocate("mock-1", "local-admin", "w1", "i1", "trace")
    store.suspend_capability("mock-v1", actor="albert", reason="drill")
    ended = store.get(row["id"])
    assert ended["status"] == "closed" and ended["reason"] == "capability_withdrawn"
    assert ended["cleanup"] == "not_needed"
    assert store.db.execute("SELECT 1 FROM asset_slot WHERE session_id=?", (row["id"],)).fetchone() is None


def test_withdrawal_respects_the_transition_table(env):
    store, now, *_ = env
    store.register_capability({"id": "x10", "vendor": "v", "model": "m",
                               "firmware": "8.78", "adapter": PASSTHROUGH_ADAPTER_ID}, "albert")
    with pytest.raises(Problem, match="capability_state"):
        store.suspend_capability("x10", actor="albert", reason="drill")
    store.retire_capability("x10", actor="albert", reason="replaced")
    with pytest.raises(Problem, match="capability_state"):
        store.retire_capability("x10", actor="albert", reason="again")
    with pytest.raises(Problem, match="capability_state"):
        store.approve_capability("x10", actor="albert", approver="a", evidence="e",
                                 licence="l", console_impl="c",
                                 review_due=now[0] + DAY, expires=now[0] + DAY)


def test_withdrawal_requires_a_recorded_reason(env):
    store, *_ = env
    seed_real(store)
    with pytest.raises(Problem, match="capability_incomplete"):
        store.suspend_capability("x10", actor="albert", reason="   ")


def test_renewal_extends_dates_and_keeps_a_history(env):
    store, now, *_ = env
    seed_real(store)
    store.approve_capability("x10", actor="albert", approver="operator-b", evidence="docs/y.json",
                             licence="same", console_impl="AST2100",
                             review_due=now[0] + 60 * DAY, expires=now[0] + 60 * DAY)
    entry = store.capability("x10")
    assert entry["revision"] == 2 and entry["approver"] == "operator-b"
    assert entry["expires"] == now[0] + 60 * DAY
    actions = [row[0] for row in store.db.execute(
        "SELECT action FROM audit WHERE action LIKE 'capability_%' ORDER BY id")]
    assert actions.count("capability_approved") == 2


def test_a_legacy_row_has_to_be_reapproved(env, tmp_path):
    path = tmp_path / "legacy.sqlite"
    db = sqlite3.connect(path)
    db.executescript("""
    CREATE TABLE adapter_capability (
     id TEXT PRIMARY KEY, vendor TEXT NOT NULL, model TEXT NOT NULL, firmware TEXT NOT NULL,
     adapter TEXT NOT NULL, status TEXT NOT NULL, expires REAL NOT NULL,
     evidence TEXT NOT NULL, approver TEXT NOT NULL);
    """)
    db.execute("INSERT INTO adapter_capability VALUES(?,?,?,?,?,?,?,?,?)",
               ("old", "Supermicro (Inspur OEM)", "X10DRT-PS / SA5248M4", "8.78",
                PASSTHROUGH_ADAPTER_ID, "verified", 4_000_000_000.0, "docs/old.json", "someone"))
    db.commit()
    db.close()

    store = Store(path, None, clock=lambda: 2_000_000_000.0, passthrough_targets=(TARGET,))
    try:
        entry = store.capability("old")
        assert entry["licence"] == "" and entry["review_due"] == 0.0
        store.db.execute("INSERT INTO asset VALUES(?,?,?,?,?,?,?,?,?)",
                         ("a1", "old", "Supermicro (Inspur OEM)", "X10DRT-PS / SA5248M4", "8.78",
                          "old", TARGET, FINGERPRINT, b"x"))
        store.db.execute("INSERT INTO access_grant VALUES(?,?,?)",
                         ("local-admin", "a1", 3_000_000_000.0))
        assert store.gate("a1", "local-admin")[1] == "unapproved"
    finally:
        store.close()


def test_the_matrix_can_be_edited_without_the_credential_key(env):
    store, now, path, key = env
    store.seed_mock(BMC_BASE_URL, "aa" * 32, "u", "p")
    row = store.allocate("mock-1", "local-admin", "w1", "i1", "trace")
    store.close()

    reader = Store(path, None, clock=lambda: now[0])
    try:
        assert reader.capabilities() and reader.capability("mock-v1")["approver"] == "local-bootstrap"
        with pytest.raises(Problem, match="credential_unavailable"):
            reader.exchange(claims(row), "trace")
        failed = reader.get(row["id"])
        assert failed["status"] == "failed" and failed["cleanup"] == "not_needed"
    finally:
        reader.close()


def test_only_the_store_may_write_the_matrix():
    root = Path(__file__).resolve().parents[1] / "kvmhub"
    writes, importers = [], []
    for path in sorted(root.rglob("*.py")):
        if path.name == "store.py":
            continue
        text = path.read_text(encoding="utf-8")
        if any(sql in text for sql in ("UPDATE adapter_capability", "INTO adapter_capability",
                                       "DELETE FROM adapter_capability")):
            writes.append(path.name)
        if "from . import capability" in text or "kvmhub.capability" in text:
            importers.append(path.name)
    assert writes == [], f"capability rows must only be written in store.py: {writes}"
    assert importers == [], f"only store.py may apply the policy: {importers}"


def test_no_http_route_exposes_the_matrix():
    path = Path(__file__).resolve().parents[1] / "kvmhub" / "manager.py"
    assert "capability" not in path.read_text(encoding="utf-8")
