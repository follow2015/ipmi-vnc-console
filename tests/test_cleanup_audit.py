"""H4: an unconfirmed cleanup needs an age, a threshold and an exit code."""
import json

from kvmhub.common import BMC_BASE_URL
from kvmhub.store import Store
from tools.cleanup_audit import collect, main, render

NOW = 2_000_000_000.0


def make_store(tmp_path):
    store = Store(tmp_path / "audit.sqlite", b"k" * 32, clock=lambda: NOW)
    store.seed_mock(BMC_BASE_URL, "aa" * 32, "u", "p")
    return store


def ended_session(store, *, cleanup, reason="client_closed", aid="mock-1"):
    row = store.allocate(aid, "local-admin", "w1", "i1", "trace")
    store.finish(row["id"], "w1", "i1", cleanup, reason)
    return row["id"]


def test_a_confirmed_cleanup_is_not_reported(tmp_path):
    store = make_store(tmp_path)
    try:
        ended_session(store, cleanup="confirmed")
        assert store.pending_cleanups(now=NOW + 10) == []
    finally:
        store.close()


def test_a_pending_cleanup_reports_its_age_and_turns_overdue(tmp_path):
    store = make_store(tmp_path)
    try:
        sid = ended_session(store, cleanup="pending", reason="upstream_error")
        fresh = store.pending_cleanups(now=NOW + 30, threshold=300)[0]
        assert fresh["sid"] == sid and fresh["age_s"] == 30.0 and fresh["overdue"] is False
        old = store.pending_cleanups(now=NOW + 301, threshold=300)[0]
        assert old["overdue"] is True
    finally:
        store.close()


def test_the_age_comes_from_the_append_only_finish_row(tmp_path):
    store = make_store(tmp_path)
    try:
        ended_session(store, cleanup="pending")
        assert store.pending_cleanups(now=NOW + 5)[0]["age_s"] == 5.0
    finally:
        store.close()


def test_a_live_session_is_not_counted(tmp_path):
    store = make_store(tmp_path)
    try:
        store.allocate("mock-1", "local-admin", "w1", "i1", "trace")
        assert store.pending_cleanups(now=NOW + 999) == []
    finally:
        store.close()


def test_the_report_and_text_render_carry_the_alert(tmp_path):
    store = make_store(tmp_path)
    try:
        ended_session(store, cleanup="pending", reason="upstream_unresponsive")
        report = collect(store, threshold=60)
        assert report["count"] == 1 and report["overdue"] == 0
        item = report["items"][0]
        assert item["worker_id"] == "w1" and item["reason"] == "upstream_unresponsive"
        assert "pending" in render(report)
    finally:
        store.close()


def test_the_cli_exit_code_is_what_a_monitor_reads(tmp_path):
    store = make_store(tmp_path)
    path = str(tmp_path / "audit.sqlite")
    try:
        ended_session(store, cleanup="pending")
    finally:
        store.close()
    code = main(["--database", path, "--overdue-after", "0", "--json"])
    assert code == 2
    assert main(["--database", path, "--overdue-after", "99999"]) == 0
