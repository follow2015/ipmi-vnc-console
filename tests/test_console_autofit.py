"""Both halves of the console page must be whole, at every window size."""
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

FIXTURE = Path(__file__).with_name("fixtures") / "autofit.cjs"


def _chrome():
    explicit = os.environ.get("KVM_CHROMIUM")
    if explicit and Path(explicit).exists():
        return explicit
    found = _find_chromium()
    if found:
        return found
    candidate = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
    return candidate if Path(candidate).exists() else None


def _rule(html: str, selector: str) -> str:
    start = html.index(selector + "{")
    return html[start:html.index("}", start)]


def test_the_height_handle_is_gone():
    html = worker.REAL_CONSOLE_HTML
    js = worker.REAL_CONSOLE_JS
    assert 'id="splitter"' not in html, "the handle is what squeezed one half or the other"
    assert "row-resize" not in html
    assert "kvmhub.input.height" not in js, "a remembered height has nothing to apply to"
    assert "setPointerCapture" not in js


def test_the_input_panel_is_one_shared_bottom_sheet():
    rule = _rule(worker.REAL_CONSOLE_HTML, "#inputpanel")
    html = worker.REAL_CONSOLE_HTML
    assert "position:fixed" in rule and "bottom:0" in rule, \
        "the panel is a fixed bottom sheet by default"
    assert "left:0;right:0" in rule, "the expanded sheet spans the full width by default"
    assert "--dock-w" not in html, "keyboard rows use the window width"
    assert ":root{--sheet-h:min(46vh,354px)}" in html, \
        "one variable drives the sheet height on every resolution"
    assert "body.sheet-open #stage{margin-bottom:var(--sheet-h)}" in html, \
        "the picture gives up exactly the sheet's height so nothing is covered"
    assert "flex:0 0 44px" not in html and "flex-basis:300px" not in html, \
        "no left-dock second layout remains"
    body_rule = _rule(html, "#input-body")
    assert "max-height" not in body_rule, f"a cap is what clipped the keyboard: {body_rule}"
    assert "<aside id=\"inputpanel\"" in html, "the panel is a sibling of the picture column"


def test_the_picture_area_does_not_scroll_either():
    rule = _rule(worker.REAL_CONSOLE_HTML, "#stage")
    assert "overflow:hidden" in rule, f"a scrollbar here means a cropped picture: {rule}"
    assert "align-items:center" in rule and "justify-content:center" in rule
    assert "overflow:hidden" in _rule(worker.REAL_CONSOLE_HTML, "body")
    assert "@media (max-height:560px){body{overflow:auto}" in worker.REAL_CONSOLE_HTML


def test_the_page_scales_through_the_clients_own_autoscale():
    js = worker.REAL_CONSOLE_JS
    assert "_display.autoscale(" in js, "use the served client's fit, not hand arithmetic"
    assert "autoscale(availW, availH, true)" in js, "downscale only: a small framebuffer stays 1:1"
    assert "_mouse._scale" in js, "the returned ratio is what the pointer path divides by"
    start = js.index("function fitPicture()")
    body = js[start:js.index("watchStageSize", start)]
    assert "canvas.width" not in body and "canvas.height" not in body


def test_the_fit_follows_the_layout():
    js = worker.REAL_CONSOLE_JS
    assert "ResizeObserver" in js and "observer.observe(stage)" in js, \
        "opening the keyboard changes the stage, so the fit has to follow it"
    assert "window.addEventListener('resize', fitPicture)" in js
    assert "fitPicture();" in js[js.index("onFBResize"):js.index("onFBResize") + 400], \
        "the bitmap size is only known after the first framebuffer update"


def test_the_zoom_readout_is_only_shown_when_the_picture_shrank():
    js = worker.REAL_CONSOLE_JS
    assert "画面 ' + Math.round(lastScale * 100) + '%'" in js
    assert "lastScale < 0.995" in js, "1:1 needs no label"


def test_both_halves_fit_at_every_window_size():
    playwright = os.environ.get("KVM_PLAYWRIGHT") or _find_playwright()
    chrome = _chrome()
    node = shutil.which("node")
    if not (playwright and chrome and node):  # pragma: no cover - machine dependent
        pytest.skip("playwright-core + chromium are required for the fit check")

    directory = Path(tempfile.mkdtemp(prefix="kvmhub-autofit-"))
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
             "--keymap", str(directory / "keymap.json"),
             "--shot", str(directory / "fit.png")],
            capture_output=True, text=True, timeout=180, env=env,
        )
        assert result.returncode == 0, result.stderr[-2000:]
        report = json.loads(result.stdout)
    finally:
        shutil.rmtree(directory, ignore_errors=True)

    assert report["errors"] == []
    steps = {step["step"]: step for step in report["steps"]}

    for name, step in steps.items():
        assert step["panel"]["bottom"] <= step["viewport"]["height"] + 0.5, name
        assert step["panel"]["scrollHeight"] <= step["panel"]["clientHeight"] + 1, name
        assert step["canvas"]["right"] <= step["stage"]["right"] + 1, name
        assert step["canvas"]["bottom"] <= step["stage"]["bottom"] + 1, name
        assert step["canvas"]["left"] >= step["stage"]["left"] - 1, name
        assert step["canvas"]["top"] >= step["stage"]["top"] - 1, name
        assert (step["canvas"]["bitmapWidth"], step["canvas"]["bitmapHeight"]) == (1024, 768), name
        assert step["scale"] == pytest.approx(step["expected"], abs=0.02), name
        assert step["mouseScale"] == pytest.approx(step["scale"], abs=0.001), name
        assert step["pageScrollHeight"] <= step["viewport"]["height"] + 1, name

    collapsed = steps["900-keyboard-collapsed"]
    opened = steps["900-keyboard-open"]
    assert collapsed["keyboardOpen"] is False and opened["keyboardOpen"] is True, \
        "the soft keyboard body toggles while the dock stays put"
    assert opened["canvas"]["bottom"] <= opened["stage"]["bottom"] + 1, \
        "even with the keyboard open the picture stays whole"

    short = steps["720-keyboard-open"]
    assert short["scale"] < 0.995, "a short window really shrinks the picture"
    assert short["zoom"] and short["zoom"].endswith("%"), "the shrink is labelled"

    short = steps["720-keyboard-open"]
    assert short["scale"] < opened["scale"], "less window means a smaller picture"
    assert short["canvas"]["cssHeight"] <= short["stage"]["height"] + 1

    roomy = steps["1000-keyboard-open"]
    assert roomy["scale"] >= opened["scale"], "more window never makes the picture smaller"
    assert roomy["scale"] <= 1.0, "downscale only: a roomy window stays at native pixels"
