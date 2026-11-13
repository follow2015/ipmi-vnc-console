"""Coverage for the bounded console reconnect and the driver's self-recovery."""
from __future__ import annotations

import ast
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from kvmhub.worker import CONSOLE_JS, REAL_CONSOLE_JS, Gateway
from tools import console_ops
from tools.bootstrap import generate

ROOT = Path(__file__).resolve().parents[1]
HARNESS = ROOT / "tests" / "fixtures" / "console_recovery_harness.cjs"
DRIVER = ROOT / "tools" / "console_ops.cjs"


def _script_constants():
    tree = ast.parse((ROOT / "kvmhub" / "worker.py").read_text(encoding="utf-8"))
    values = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and getattr(node.targets[0], "id", "") in (
                "CONSOLE_JS", "REAL_CONSOLE_JS"):
            values[node.targets[0].id] = node.value.value
    return values["CONSOLE_JS"], values["REAL_CONSOLE_JS"]


@pytest.fixture(scope="module")
def harness_result(tmp_path_factory):
    node = shutil.which("node")
    if not node:
        pytest.skip("node is not installed")
    mock_js, real_js = _script_constants()
    directory = tmp_path_factory.mktemp("console-js")
    mock_path = directory / "mock.js"
    real_path = directory / "real.js"
    mock_path.write_text(mock_js, encoding="utf-8")
    real_path.write_text(real_js, encoding="utf-8")
    completed = subprocess.run([node, str(HARNESS), str(mock_path), str(real_path)],
                               capture_output=True, text=True, timeout=30, check=True)
    return json.loads(completed.stdout)


def test_console_scripts_reconnect_bounded(harness_result):
    data = harness_result

    assert data["mock"]["initial"] == 1
    assert data["mock"]["delays"] == [0, 400, 900]
    assert data["mock"]["total_sockets"] == 4
    assert data["mock"]["exhausted"] is True
    assert data["mock"]["health_state"] == "exhausted"
    assert "重新申请" in data["mock"]["status"]

    assert data["real"]["delays"] == [0, 400, 900]
    assert data["real"]["health_states"] == [
        "reconnecting", "reconnecting", "reconnecting", "exhausted"]
    assert data["real"]["reloads"] == 3
    assert data["real"]["exhausted"] is True
    assert data["real"]["status"].startswith("连接已断开，自动重连已用尽")
    assert "重连已用尽" in REAL_CONSOLE_JS
    assert data["real"]["fetch_urls"] == ["/_platform/limits"] * 2
    assert data["real"]["last_connected"] == 1


def test_explicit_close_never_reconnects(harness_result):
    data = harness_result
    assert data["mock_close"]["total_sockets"] == 1
    assert data["mock_close"]["health_state"] == "closed"
    assert data["mock_close"]["fetches"] == 1
    assert data["mock_close"]["status"] == "会话已结束"
    assert data["real_close"]["reloads"] == 0
    assert data["real_close"]["health_state"] == "closed"
    assert data["real_close"]["fetch_urls"] == ["/_platform/limits", "/_platform/close"]
    assert data["real_close"]["status"] == "会话已结束"


def test_revoked_session_is_explained_and_not_connected(harness_result):
    signed_out = harness_result["real_signed_out"]
    assert signed_out["total_rfbs"] == 0
    assert signed_out["fetch_urls"] == ["/_platform/limits"]
    assert signed_out["status"].startswith("会话已结束或已失效")


def test_connection_limit_answered_before_connecting(harness_result):
    at_limit = harness_result["real_at_limit"]
    assert at_limit["total_rfbs"] == 0
    assert "连接已达上限" in at_limit["status"]


def test_successful_reconnect_resets_consecutive_attempts(harness_result):
    recovery = harness_result["real_recovery"]
    assert recovery["afterNormal"] == {
        "health_state": "normal", "recovered": 1, "attempts": 0}
    assert recovery["next_delay"] == 0
    assert recovery["next_attempts"] == 1


def test_reconnect_grace_is_configurable_and_capped(tmp_path):
    cfg = json.loads((generate(tmp_path / "identity") / "worker.json").read_text())
    assert Gateway(cfg).RECONNECT_GRACE == 8.0
    cfg["reconnect_grace_seconds"] = 2.5
    assert Gateway(cfg).RECONNECT_GRACE == 2.5
    cfg["reconnect_grace_seconds"] = 999
    assert Gateway(cfg).RECONNECT_GRACE == 30.0, "a dead client must not pin a slot forever"
    cfg["reconnect_grace_seconds"] = -1
    assert Gateway(cfg).RECONNECT_GRACE == 0.1
    cfg["reconnect_grace_seconds"] = "not-a-number"
    assert Gateway(cfg).RECONNECT_GRACE == 8.0


def test_plan_retry_only_replays_a_lost_session():
    resume = [{"key": "e"}, {"shot": "after"}]
    assert console_ops.plan_retry(
        {"errors": ["vnc_session_lost:exhausted:{}"], "resume": resume}, 1, 2) == resume
    assert console_ops.plan_retry(
        {"errors": ["browser_timeout"], "resume": resume}, 2, 2) == resume
    assert console_ops.plan_retry(
        {"errors": ["vnc_session_lost:timeout"], "resume": resume}, 3, 2) is None
    assert console_ops.plan_retry(
        {"errors": ["vnc_session_lost:timeout"], "resume": []}, 1, 2) is None
    assert console_ops.plan_retry({"errors": ["unknown action: foo"], "resume": resume}, 1, 2) is None
    assert console_ops.plan_retry({"errors": ["asset_busy"], "resume": resume}, 1, 2) is None
    assert console_ops.plan_retry(None, 1, 2) is None


def test_driver_probes_health_and_reports_a_resume_point():
    source = DRIVER.read_text(encoding="utf-8")
    assert "__kvm_health" in source
    assert "vnc_session_lost:" in source
    assert "makeResume" in source
    assert "KVM_HEALTH_EVERY" in source and "KVM_RECOVER_MS" in source
    assert "KVM_ATTEMPT" in source, "retries must not overwrite the first attempt's frames"
    assert "rfb_state !== 'normal'" in source
    assert "canvas.width + 'x' + canvas.height" in source
    for comparison in ("canvas.width <", "canvas.height <", "canvas.width >", "canvas.height >"):
        assert comparison not in source, f"{comparison} 把画布尺寸变成了断线判据"
    assert "session_rebuild_blocked_by_cleanup_pending" in (ROOT / "tools" / "console_ops.py").read_text(encoding="utf-8")
