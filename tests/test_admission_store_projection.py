"""G0 shadow projection: immutable snapshots, CAS current pointer, no plaintext."""
import json

import pytest

from kvmhub.common import Problem
from kvmhub.store import Store

KEY = b"k" * 32
ASSET = "asset-1"
DOMAIN = "admission-canary"
GENERATION = "gen-alpha"
POLICY = "policy-1"


def make_store(tmp_path, *, name="plane.db", generation=GENERATION):
    store = Store(tmp_path / name, KEY, clock=lambda: 2_000_000_000.0)
    store.generation = generation
    return store


def snapshot(note="hunter2"):
    return {
        "adapter": "rfb-vnc",
        "endpoint_json": '{"host":"192.0.2.20","port":5900}',
        "secret_ref": "cred-1",
        "secret_revision": 3,
        "schema": "v2",
        "note": note,
    }


def put(store, revision, digest, *, schema="v2", generation=GENERATION, policy=POLICY,
        payload=None):
    return store.put_connection_snapshot(
        ASSET, revision, payload if payload is not None else snapshot(),
        digest=digest, domain_id=DOMAIN, generation=generation,
        policy_fingerprint=policy)


def test_same_revision_digest_is_idempotent(tmp_path):
    store = make_store(tmp_path)
    digest = "a" * 64
    first = put(store, 4, digest)
    second = put(store, 4, digest)
    assert first == second
    count = store.db.execute(
        "SELECT COUNT(*) FROM connection_snapshot WHERE asset_id=? AND revision=?",
        (ASSET, 4)).fetchone()[0]
    assert count == 1
    state = store.projection_state(ASSET)
    assert state["current_revision"] == 4
    assert state["current_digest"] == digest


def test_stale_revision_cannot_overwrite_current(tmp_path):
    store = make_store(tmp_path)
    put(store, 4, "a" * 64)
    assert store.ack_projection(ASSET, 4, digest="a" * 64) is True
    put(store, 2, "b" * 64)
    state = store.projection_state(ASSET)
    assert state["current_revision"] == 4
    assert state["current_digest"] == "a" * 64
    assert store.ack_projection(ASSET, 2, digest="b" * 64) is False


def test_same_revision_different_digest_is_rejected_and_counted(tmp_path):
    store = make_store(tmp_path)
    put(store, 5, "c" * 64)
    before = store.projection_conflicts
    with pytest.raises(Problem) as exc:
        put(store, 5, "d" * 64)
    assert exc.value.code == "connection_snapshot_conflict"
    assert store.projection_conflicts == before + 1
    state = store.projection_state(ASSET)
    assert state["current_revision"] == 5
    assert state["current_digest"] == "c" * 64


def test_tombstone_is_a_higher_revision_and_marks_projection_revoked(tmp_path):
    store = make_store(tmp_path)
    put(store, 5, "e" * 64)
    assert store.ack_projection(ASSET, 5, digest="e" * 64) is True
    tombstone = snapshot()
    tombstone["schema"] = "tombstone"
    put(store, 6, "f" * 64, schema="tombstone", payload=tombstone)
    state = store.projection_state(ASSET)
    assert state["current_revision"] == 6
    assert state["status"] == "revoked"
    assert state["usable"] is False


def test_first_projection_pins_the_generation_for_a_fresh_store(tmp_path):
    store = Store(tmp_path / "plane.db", KEY, clock=lambda: 2_000_000_000.0)
    assert store._generation_explicit is False
    put(store, 1, "3" * 64)
    assert store.generation == GENERATION
    assert store.ack_projection(ASSET, 1, digest="3" * 64) is True
    state = store.projection_state(ASSET)
    assert state["usable"] is True
    assert state["reason"] is None


def test_restored_old_store_with_different_generation_is_unusable(tmp_path):
    store = make_store(tmp_path)
    put(store, 1, "1" * 64)
    assert store.ack_projection(ASSET, 1, digest="1" * 64) is True
    restored = make_store(tmp_path, generation="gen-restored")
    state = restored.projection_state(ASSET)
    assert state["usable"] is False
    assert state["reason"] == "generation_mismatch"


def test_snapshot_plaintext_never_reaches_disk_or_return_value(tmp_path):
    store = make_store(tmp_path)
    result = put(store, 1, "2" * 64)
    assert "hunter2" not in json.dumps(result)
    assert b"hunter2" not in (tmp_path / "plane.db").read_bytes()
    rows = [tuple(row) for row in store.db.execute("SELECT * FROM connection_snapshot")]
    assert "hunter2" not in repr(rows)

    store.close()
