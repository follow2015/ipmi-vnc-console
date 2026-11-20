"""Phone-width console must open at a readable zoom, not a whole-frame fit."""
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

FIXTURE = Path(__file__).with_name("fixtures") / "mobile_fit.cjs"


def _rule(html: str, selector: str) -> str:
    start = html.index(selector + "{")
    return html[start:html.index("}", start)]


def test_phone_hint_and_two_finger_scope_are_present():
    html = worker.REAL_CONSOLE_HTML
    js = worker.REAL_CONSOLE_JS
    assert 'id="phone-hint"' in html
    assert "pointer-events:none" in _rule(html, "#phone-hint")
    assert "phoneMode" in js and "touchstart" in js and "touchmove" in js
    assert "stopPropagation" in js and "passive: false" in js, \
        "two-finger gestures must not leak into noVNC's single-finger path"


def test_phone_opens_readable_and_pinches_to_larger():
    playwright = os.environ.get("KVM_PLAYWRIGHT") or _find_playwright()
    chrome = os.environ.get("KVM_CHROMIUM") or _find_chromium()
    node = shutil.which("node")
    if not (playwright and chrome and node):  # pragma: no cover - machine dependent
        pytest.skip("playwright-core + chromium are required for the fit check")

    directory = Path(tempfile.mkdtemp(prefix="kvmhub-mobilefit-"))
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
            [node, str(FIXTURE), "--html", str(directory / "page.html"),
             "--keymap", str(directory / "keymap.json"), "--shot", str(directory / "fit.png")],
            capture_output=True, text=True, timeout=180, env=env,
        )
        assert result.returncode == 0, result.stderr[-2000:]
        report = json.loads(result.stdout)
    finally:
        shutil.rmtree(directory, ignore_errors=True)

    assert report["errors"] == []
    first, pinched = report["steps"]

    assert first["coarse"] is True
    assert first["canvas"]["bitmapW"] == 1024 and first["canvas"]["bitmapH"] == 768
    assert first["stage"]["scale"] >= 0.6, f"phone opened too small: {first['stage']['scale']}"
    assert first["canvas"]["cssW"] >= 600, f"canvas too narrow: {first['canvas']['cssW']}"
    assert first["stage"]["overflow"] == "auto"
    assert first["stage"]["justify"] in ("flex-start", "flow-start")
    assert first["mouseScale"] == pytest.approx(first["stage"]["scale"], abs=0.001)
    assert first["zoom"].endswith("%") and "64" in first["zoom"]

    assert pinched["stage"]["scale"] > first["stage"]["scale"]
    assert pinched["stage"]["scale"] <= 1.0
    assert pinched["mouseScale"] == pytest.approx(pinched["stage"]["scale"], abs=0.001)
