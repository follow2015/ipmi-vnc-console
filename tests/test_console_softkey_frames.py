"""The page's soft keyboard must build the frames the Python reference builds."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from kvmhub import worker
from kvmhub.platform import text_input
from tools.browser_e2e import _find_chromium, _find_playwright

FIXTURE = Path(__file__).with_name("fixtures") / "softkey_frames.cjs"

CASES = [
    {"label": "one letter", "keys": ["a"]},
    {"label": "shift latched onto a letter", "keys": ["lshift", "a"]},
    {"label": "shift latched onto a digit", "keys": ["lshift", "1"]},
    {"label": "enter", "keys": ["enter"]},
    {"label": "arrow up", "keys": ["up"]},
    {"label": "ctrl-alt-del macro", "macro": "Ctrl+Alt+Del"},
    {"label": "ctrl-c macro", "macro": "Ctrl+C"},
]


def _chrome():
    explicit = os.environ.get("KVM_CHROMIUM")
    if explicit and Path(explicit).exists():
        return explicit
    found = _find_chromium()
    if found:
        return found
    for candidate in ("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",):
        if Path(candidate).exists():
            return candidate
    return None


def _cases_with_frames(style: str = "insyde18") -> list[dict]:
    doc = text_input.keymap_document()
    macros = {macro["label"]: macro["keys"] for macro in doc["macros"]}
    prepared = []
    for case in CASES:
        tokens = case.get("keys") or macros[case["macro"]]
        frames = [list(frame) for frame, _ in text_input.chord_frames(tokens, style=style)]
        prepared.append(dict(case, tokens=tokens, frames=frames))
    return prepared


def _run_browser_frames(style: str) -> tuple[dict, list[dict]]:
    playwright = os.environ.get("KVM_PLAYWRIGHT") or _find_playwright()
    chrome = _chrome()
    node = shutil.which("node")
    if not (playwright and chrome and node):  # pragma: no cover - machine dependent
        pytest.skip("playwright-core + chromium are required for the frame check")

    directory = Path(tempfile.mkdtemp(prefix="kvmhub-frames-"))
    try:
        html = worker.REAL_CONSOLE_HTML.replace(
            '<script src="/_platform/console.js"></script>',
            "<script>" + worker.REAL_CONSOLE_JS + "</script>",
        )
        assert "softkeySend" not in html
        (directory / "page.html").write_text(html, encoding="utf-8")
        (directory / "keymap.json").write_text(
            json.dumps(text_input.keymap_document(), ensure_ascii=False), encoding="utf-8")
        cases = _cases_with_frames(style)
        (directory / "cases.json").write_text(json.dumps(cases), encoding="utf-8")

        env = dict(os.environ, KVM_PLAYWRIGHT=playwright, KVM_CHROMIUM=chrome)
        result = subprocess.run(
            [node, str(FIXTURE),
             "--html", str(directory / "page.html"),
             "--keymap", str(directory / "keymap.json"),
             "--cases", str(directory / "cases.json"),
             "--protocol", style,
             "--shot", str(directory / "softkey.png")],
            capture_output=True, text=True, timeout=180, env=env,
        )
        assert result.returncode == 0, result.stderr[-2000:]
        return json.loads(result.stdout), cases
    finally:
        shutil.rmtree(directory, ignore_errors=True)


def test_the_page_builds_the_same_frames_as_the_python_reference():
    report, cases = _run_browser_frames("insyde18")
    assert report["errors"] == [], "the console page threw while clicking keys"
    by_label = {item["label"]: item for item in report["results"]}
    for case in cases:
        got = by_label[case["label"]]
        assert got["problem"] is None, f"{case['label']}: {got['problem']}"
        assert got["sent"] == case["frames"], f"{case['label']}: frame mismatch"

    ui = report["ui"]
    assert ui["key_buttons"] == worker.REAL_CONSOLE_HTML.count('data-send="')
    assert ui["macros"] == [macro["label"] for macro in text_input.keymap_document()["macros"]]
    assert ui["levels"].get("unverified"), "named keys must not claim verification"
    assert ui["panel_height"] > 150, "the keyboard drew nothing"


def test_standard_vnc_session_builds_8_byte_keysym_frames():
    report, cases = _run_browser_frames("standard8")
    assert report["errors"] == [], "the console page threw while clicking keys"
    by_label = {item["label"]: item for item in report["results"]}
    for case in cases:
        got = by_label[case["label"]]
        assert got["problem"] is None, f"{case['label']}: {got['problem']}"
        assert got["sent"] == case["frames"], f"{case['label']}: frame mismatch"
        for frame in got["sent"]:
            assert len(frame) == 8 and frame[0] == 4, (case["label"], frame)
