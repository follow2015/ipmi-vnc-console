"""One shared bottom-sheet layout must keep the picture fully visible at every"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from kvmhub import worker
from kvmhub.platform import text_input
from tools.browser_e2e import _find_chromium, _find_playwright

ROOT = Path(__file__).resolve().parents[1]
HARNESS = ROOT / "tests" / "fixtures" / "sheet_layout.cjs"


@pytest.fixture(scope="module")
def page_files(tmp_path_factory):
    node = shutil.which("node")
    playwright = os.environ.get("KVM_PLAYWRIGHT") or _find_playwright()
    chrome = os.environ.get("KVM_CHROMIUM") or _find_chromium()
    if not (node and playwright and chrome):
        pytest.skip("browser harness (node/playwright-core/chromium) is unavailable")
    env = dict(os.environ, KVM_PLAYWRIGHT=str(playwright), KVM_CHROMIUM=str(chrome))
    d = tmp_path_factory.mktemp("sheet-layout")
    html = worker.REAL_CONSOLE_HTML.replace(
        '<script src="/_platform/console.js"></script>',
        "<script>" + worker.REAL_CONSOLE_JS + "</script>")
    (d / "page.html").write_text(html, encoding="utf-8")
    (d / "keymap.json").write_text(
        json.dumps(text_input.keymap_document(), ensure_ascii=False), encoding="utf-8")
    return node, d, env


@pytest.mark.parametrize("name,width,height,touch", [
    ("desktop", 1280, 900, False),
    ("tablet", 1024, 768, True),
    ("phone", 390, 844, True),
])
def test_picture_stays_visible_above_sheet(page_files, name, width, height, touch):
    node, d, env = page_files
    completed = subprocess.run(
        [node, str(HARNESS),
         "--html", str(d / "page.html"), "--keymap", str(d / "keymap.json"),
         "--width", str(width), "--height", str(height),
         "--touch", "1" if touch else "0"],
        capture_output=True, text=True, timeout=90, check=True, env=env)
    report = json.loads(completed.stdout)
    assert report["errors"] == []
    before, after = report["before"], report["after"]

    view_w = after["viewportW"]
    assert before["stage"]["w"] == view_w
    assert after["sheetOpen"] is True
    assert after["panel"]["w"] == view_w
    assert after["stage"]["w"] == view_w
    assert after["canvas"]["b"] <= after["stage"]["b"] + 2, \
        f"picture hidden behind the sheet at {name}: canvas {after['canvas']['b']} stage {after['stage']['b']}"
    assert after["stage"]["b"] <= after["panel"]["t"] + 2, \
        f"stage overlaps the sheet at {name}"
    assert after["keyboardFirst"] is True
    assert after["visibleKeyCount"] >= 40
