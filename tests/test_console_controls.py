"""The console page's four operator-facing controls."""
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

FIXTURE = Path(__file__).with_name("fixtures") / "controls.cjs"


def _chrome():
    explicit = os.environ.get("KVM_CHROMIUM")
    if explicit and Path(explicit).exists():
        return explicit
    found = _find_chromium()
    if found:
        return found
    candidate = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
    return candidate if Path(candidate).exists() else None


def test_softkey_panel_has_no_provenance_tooltip():
    js = worker.REAL_CONSOLE_JS
    assert "data.note" not in js, "the keymap provenance note must not be shown as a tooltip"
    assert "getElementById('softkey').title" not in js


def test_input_block_starts_as_one_button():
    html = worker.REAL_CONSOLE_HTML
    js = worker.REAL_CONSOLE_JS
    assert '<aside id="inputpanel" class="collapsed show-keys">' in html, \
        "one shared panel, collapsed at first with the keyboard tab active"
    assert '<div id="work">' in html, "the picture owns its own column"
    assert 'id="input-toggle"' in html
    assert 'id="tab-keys"' in html and 'id="tab-paste"' in html, \
        "the sheet switches between keyboard and long command via two tabs"
    assert "#inputpanel.show-keys #pastebar,#inputpanel.show-paste #softkey{display:none}" in html, \
        "the two panes are mutually exclusive so the text box stays visible"
    assert "#inputpanel.collapsed #input-body{display:none}" in html
    assert "body.sheet-open #stage" not in html, "floating keyboard cannot shrink the picture"
    assert "inputPanel.classList.toggle('collapsed')" in js
    assert "classList.toggle('sheet-open'" in js, \
        "tracks widget visibility without resizing the stage"
    block = js[js.index("inputToggle.onclick"):js.index("skRoot.addEventListener")]
    assert "loadKeymap();" in block, "the first expansion is what loads the table"
    assert "inputOpened" in block, "and it must happen once, not on every toggle"


def test_a_live_console_no_longer_fetches_the_keymap():
    js = worker.REAL_CONSOLE_JS
    block = js[js.index("onUpdateState: function"):js.index("onMouseMove")]
    assert "loadKeymap()" not in block, \
        "watching a console must not download a table nobody uses"
    assert "skSync()" in block, "buttons still follow the connection state"


def test_zoom_button_switches_between_fit_and_raw_pixels():
    html = worker.REAL_CONSOLE_HTML
    js = worker.REAL_CONSOLE_JS
    assert 'id="zoom-mode"' in html and "画面自适应" in html
    assert "var zoomMode = 'oneone'" in js, "native pixels are the crisp default"
    assert "setZoomMode('oneone');" in js
    assert "zoomMode === 'oneone'" in js
    assert "stage.style.overflow = 'auto'" in js, "1:1 larger than the stage must scroll"
    assert "stage.style.justifyContent = 'flex-start'" in js, "centring would make the top unreachable"
    assert "canvas.style.width = ''" in js, "only CSS size changes; the bitmap stays the BMC's"
    assert "rfb._mouse._scale = 1" in js, "the pointer path must follow the new scale"
    fit = js[js.index("function fitPicture()"):js.index("function setZoomMode(")]
    assert "_display.autoscale(availW, availH, true)" in fit, "fit still uses the vendor tool"


def test_console_page_is_touch_friendly():
    html = worker.REAL_CONSOLE_HTML
    js = worker.REAL_CONSOLE_JS
    assert 'name="viewport"' in html and "width=device-width" in html
    assert "touch-action:none" in html, "touch gestures belong to noVNC, not the page"
    assert "@media (pointer:coarse)" in html
    assert "min-height:44px" in html, "tablet hit targets must be touch sized"
    assert "(pointer: coarse)" in js
    assert "setZoomMode('fit');" in js, "tablets open with the whole framebuffer visible"


def test_no_signal_comes_from_the_vendor_client():
    html = worker.REAL_CONSOLE_HTML
    js = worker.REAL_CONSOLE_JS
    assert 'id="nosignal" hidden' in html
    assert "无视频信号" in html and "系统可能未开机" in html
    assert "pointer-events:none" in html, "the overlay must not swallow mouse input"
    assert "这不是 VNC 链路故障" in html
    assert "onUpdateFps" in js and "noteNoSignal(fps, res)" in js
    assert "'No Signal'" in js and "res === 'Unknown'" in js
    assert "系统电源关闭" not in html, "the platform has no power-state API to justify that claim"


def test_only_the_address_is_published():
    html = worker.REAL_CONSOLE_HTML
    source = Path(worker.__file__).read_text(encoding="utf-8")
    assert 'id="asset-label"' in html
    assert "fetch('/_platform/meta'" in worker.REAL_CONSOLE_JS
    markers = ('if request.path == "/_platform/meta"',
               'if path == "/_platform/meta"')
    marker = next((m for m in markers if m in source), None)
    assert marker is not None, markers
    block = source[source.index(marker):source.index('if request.method != "GET"', source.index(marker))]
    assert '"address": label' in block
    assert 'getattr(sess, "display_address", "") or "控制台"' in block
    assert '"asset_id": getattr(sess, "asset_id", "")' in block
    code = "\n".join(line for line in block.splitlines()
                       if not line.lstrip().startswith("#")).lower()
    for secret in ("password", "ticket", "cookie", "fingerprint", "credential"):
        assert secret not in code, f"{secret} must never reach the page"


def test_the_page_script_parses():
    directory = Path(tempfile.mkdtemp(prefix="kvmhub-controls-syntax-"))
    try:
        target = directory / "console.js"
        target.write_text(worker.REAL_CONSOLE_JS, encoding="utf-8")
        result = subprocess.run(["node", "--check", str(target)], capture_output=True,
                                text=True, timeout=30)
        assert result.returncode == 0, result.stderr[-1200:]
    finally:
        shutil.rmtree(directory, ignore_errors=True)


def test_controls_behave_in_a_browser():
    playwright = os.environ.get("KVM_PLAYWRIGHT") or _find_playwright()
    chrome = _chrome()
    node = shutil.which("node")
    if not (playwright and chrome and node):  # pragma: no cover - machine dependent
        pytest.skip("playwright-core + chromium are required for the control check")

    directory = Path(tempfile.mkdtemp(prefix="kvmhub-controls-"))
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
             "--keymap", str(directory / "keymap.json")],
            capture_output=True, text=True, timeout=180, env=env,
        )
        assert result.returncode == 0, result.stderr[-2000:]
        report = json.loads(result.stdout)
    finally:
        shutil.rmtree(directory, ignore_errors=True)

    assert report["errors"] == []
    steps = {step["step"]: step for step in report["steps"]}

    initial = steps["initial"]
    assert initial["keymapRequests"] == 0, "no request before the first click"
    assert initial["inputBodyVisible"] is False
    assert initial["toggleVisible"] is True
    assert initial["panelCollapsed"] is True
    assert initial["sheetOpen"] is False
    assert initial["stageWidth"] == 1280, "collapsed sheet leaves the full width"
    assert initial["label"] == "192.0.2.11"
    assert initial["title"].endswith("192.0.2.11")
    assert initial["scale"] == pytest.approx(1.0, abs=0.001), "crisp 1:1 on first paint"
    assert initial["zoom"] == "100%"
    assert initial["cssWidth"] == 1024 and initial["cssHeight"] == 768
    assert initial["stageOverflow"] == "auto", "a small window scrolls at 1:1"

    fit = steps["fit"]
    assert fit["sheetOpen"] is False
    assert fit["scale"] < 0.995, "fit shows the whole framebuffer when asked"
    assert fit["stageOverflow"] != "auto"
    assert fit["zoom"].endswith("%")

    nosignal = steps["nosignal"]
    assert nosignal["overlayVisible"] is True
    assert "无视频信号" in nosignal["overlayText"]
    assert steps["signal"]["overlayVisible"] is False

    oneone = steps["oneone"]
    assert oneone["sheetOpen"] is False
    assert oneone["scale"] == pytest.approx(1.0, abs=0.001)
    assert oneone["mouseScale"] == pytest.approx(1.0, abs=0.001)
    assert oneone["cssWidth"] == 1024 and oneone["cssHeight"] == 768
    assert oneone["stageOverflow"] == "auto"
    assert oneone["stageScrollHeight"] > oneone["stageClientHeight"]
    assert oneone["zoom"] == "100%"

    opened = steps["opened"]
    assert opened["keymapRequests"] == 1
    assert opened["inputBodyVisible"] is True
    assert opened["keyEnabled"] is True
    assert opened["panelCollapsed"] is False
    assert opened["sheetOpen"] is True
    assert opened["panelWidth"] > 200, "the expanded sheet shows the keyboard"
    assert opened["scale"] == pytest.approx(oneone["scale"], abs=0.001)
    assert opened["stageWidth"] == oneone["stageWidth"]
    assert opened["mouseScale"] == pytest.approx(opened["scale"], abs=0.001), \
        "pointer mapping tracks the sheet-time scale exactly"

    closed = steps["closed"]
    assert closed["sheetOpen"] is False
    assert closed["scale"] == pytest.approx(1.0, abs=0.001), \
        "closing the sheet restores the operator's 100% choice"
    assert closed["mouseScale"] == pytest.approx(1.0, abs=0.001)
