"""The soft keyboard is grouped into pages with big keys on a phone sheet."""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from kvmhub import worker
from kvmhub.platform import text_input

ROOT = Path(__file__).resolve().parents[1]
HARNESS = ROOT / "tests" / "fixtures" / "softkey_tabs.cjs"


def _run(directory: Path) -> dict:
    node = __import__("shutil").which("node")
    if not node:
        pytest.skip("node is not installed")
    html = worker.REAL_CONSOLE_HTML.replace(
        '<script src="/_platform/console.js"></script>',
        "<script>" + worker.REAL_CONSOLE_JS + "</script>")
    (directory / "page.html").write_text(html, encoding="utf-8")
    (directory / "keymap.json").write_text(
        json.dumps(text_input.keymap_document(), ensure_ascii=False), encoding="utf-8")
    import os
    env = dict(os.environ)
    pw = ROOT / ".local-playwright" / "node_modules" / "playwright-core"
    if pw.exists():
        env["KVM_PLAYWRIGHT"] = str(pw)
    chromium = Path.home() / "AppData" / "Local" / "ms-playwright" / "chromium-1254" / "chrome-win64" / "chrome.exe"
    if chromium.exists():
        env["KVM_CHROMIUM"] = str(chromium)
    completed = subprocess.run(
        [node, str(HARNESS), "--html", str(directory / "page.html"),
         "--keymap", str(directory / "keymap.json")],
        capture_output=True, text=True, timeout=90, check=True, env=env)
    return json.loads(completed.stdout)


def test_softkey_pages_switch_and_modifiers_latch(tmp_path):
    result = _run(tmp_path)
    assert result["errors"] == []
    steps = result["steps"]
    default, symbols, func, ctrl = steps

    assert default["page"] == "chars"
    assert default["activeTab"] == "字符"
    assert default["visibleRowPages"] == ["chars"]
    assert default["visibleKeyCount"] >= 40

    assert symbols["page"] == "symbols"
    assert symbols["activeTab"] == "符号"
    assert symbols["visibleRowPages"] == ["symbols"]
    assert symbols["visibleKeyCount"] < default["visibleKeyCount"]

    assert func["page"] == "func"
    assert func["activeTab"] == "功能"
    assert func["visibleRowPages"] == ["func"]
    assert func["visibleKeyCount"] <= 14

    assert "Ctrl" in ctrl["modState"]
    assert "再点一个键" in ctrl["modState"]
    assert ctrl["modStateOn"] is True

    assert ctrl["brokenKeys"] >= 1
    assert ctrl["verifiedKeys"] >= 10
