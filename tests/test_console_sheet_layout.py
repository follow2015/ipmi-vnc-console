"""Floating keyboard geometry, independent picture scale, drag and resize checks."""
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
    ("landscape", 844, 390, True),
    ("wide", 1920, 1080, False),
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
    assert after["stage"] == before["stage"], "opening keyboard must not resize the stage"
    assert after["canvas"] == before["canvas"], "opening keyboard must not change the picture scale"
    assert after["panel"]["l"] >= 0 and after["panel"]["t"] >= 0
    assert after["panel"]["r"] <= width + 1 and after["panel"]["b"] <= height + 1
    assert after["keyboardFirst"] is True
    assert after["visibleKeyCount"] >= 40
    assert not after["pageOverflows"], "keyboard scrolling must stay inside the keybed"
    assert after["endKeyReachable"], "Backspace remains reachable by scrolling the keyboard"
    for row in after["keyRows"]:
        assert row["sameLine"], "physical keyboard rows must not wrap"
        assert row["labelsFit"], "key labels must not be clipped"
        assert row["height"] > 10, "uniform scaling preserves key proportions"
    widget = report["widget"]
    assert widget["scaled"]["canvas"] == widget["before"]["canvas"]
    ratio = widget["scaled"]["scale"] / widget["before"]["scale"]
    assert widget["scaled"]["w"] / widget["before"]["w"] == pytest.approx(ratio, abs=0.01)
    assert widget["scaled"]["h"] / widget["before"]["h"] == pytest.approx(ratio, abs=0.01)
    assert abs(widget["dragged"]["x"] - widget["scaled"]["x"]) > 2 or \
        abs(widget["dragged"]["y"] - widget["scaled"]["y"]) > 2
    assert all(widget[state]["inside"] for state in ("scaled", "dragged", "resized", "reset"))
