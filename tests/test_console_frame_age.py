"""The page must be able to say whether the picture is still being fed."""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from kvmhub import worker
from kvmhub.platform import text_input
from tools.browser_e2e import _find_chromium, _find_playwright

FIXTURE = Path(__file__).with_name("fixtures") / "frame_age.cjs"


def _chrome():
    explicit = os.environ.get("KVM_CHROMIUM")
    if explicit and Path(explicit).exists():
        return explicit
    found = _find_chromium()
    if found:
        return found
    candidate = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
    return candidate if Path(candidate).exists() else None


def test_the_header_has_the_indicator_and_explains_what_it_means():
    html = worker.REAL_CONSOLE_HTML
    assert 'id="frame-age"' in html
    start = html.index('id="frame-age"')
    assert "静止" in html[start:start + 400]
    assert "主机自己停住" in html[start:start + 400]


def test_the_page_counts_arrivals_on_the_browser_socket():
    js = worker.REAL_CONSOLE_JS
    assert "watchFrames" in js
    assert "addEventListener('message'" in js
    assert "链路" in js
    assert "_websocket" in js
    assert "onmessage" in js
    assert "setInterval" in js, "the label has to age without any new traffic"


def test_the_indicator_marks_a_long_silence_without_calling_it_a_failure():
    js = worker.REAL_CONSOLE_JS
    assert "stale" in js
    assert "15" in js
    assert "链路" in worker.REAL_CONSOLE_HTML or "链路" in js


@pytest.mark.parametrize("retry", [False, True])
def test_the_indicator_goes_quiet_and_recovers(retry):
    playwright = os.environ.get("KVM_PLAYWRIGHT") or _find_playwright()
    chrome = _chrome()
    node = shutil.which("node")
    if not (playwright and chrome and node):  # pragma: no cover - machine dependent
        pytest.skip("playwright-core + chromium are required for the activity check")

    directory = Path(tempfile.mkdtemp(prefix="kvmhub-age-"))
    try:
        html = worker.REAL_CONSOLE_HTML.replace(
            '<script src="/_platform/console.js"></script>',
            "<script>" + worker.REAL_CONSOLE_JS + "</script>",
        )
        (directory / "page.html").write_text(html, encoding="utf-8")
        (directory / "keymap.json").write_text(
            json.dumps(text_input.keymap_document(), ensure_ascii=False), encoding="utf-8")
        env = dict(os.environ, KVM_PLAYWRIGHT=playwright, KVM_CHROMIUM=chrome)
        result = subprocess.run(
            [node, str(FIXTURE),
             "--html", str(directory / "page.html"),
             "--keymap", str(directory / "keymap.json"), "--retry", "1" if retry else "0"],
            capture_output=True, text=True, timeout=120, env=env,
        )
        assert result.returncode == 0, result.stderr[-2000:]
        report = json.loads(result.stdout)
    finally:
        shutil.rmtree(directory, ignore_errors=True)

    assert report["errors"] == []
    assert report["health"]["state"] == "normal"
    assert report["health"]["exhausted"] is False
    if retry:
        assert report["health"]["recovered"] == 1
    steps = {step["step"]: step for step in report["steps"]}
    assert steps["just-connected"]["text"] == "链路 正常"
    assert re.fullmatch(r"链路 [23]s 未收到数据", steps["quiet-2s"]["text"]), \
        steps["quiet-2s"]["text"]
    assert steps["after-update"]["text"] == "链路 正常", "an update must reset the count"
    assert re.fullmatch(r"链路 [01]s 未收到数据|链路 正常", steps["quiet-again"]["text"]), \
        steps["quiet-again"]["text"]
