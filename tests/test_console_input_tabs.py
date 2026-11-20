"""The input sheet's two tabs must each be usable at every resolution."""
import json
import os
import subprocess
from pathlib import Path

import pytest

from kvmhub import worker
from kvmhub.platform import text_input

FIXTURE = Path(__file__).parent / "fixtures" / "input_tabs.cjs"


def _node_env():
    env = dict(os.environ)
    pw = os.environ.get("KVM_PLAYWRIGHT")
    chrome = os.environ.get("KVM_CHROMIUM")
    if not pw:
        local = Path(__file__).parent.parent / ".local-playwright" / "node_modules" / "playwright-core"
        if local.exists():
            env["KVM_PLAYWRIGHT"] = str(local)
    if not chrome:
        for base in (os.environ.get("LOCALAPPDATA"), os.environ.get("HOME", "")):
            if not base:
                continue
            candidates = list(Path(base, "ms-playwright").glob("chromium-*/chrome-win64/chrome.exe"))
            if not candidates:
                candidates = list(Path(base, "ms-playwright").glob("chromium-*/chrome-linux/chrome"))
            if candidates:
                env["KVM_CHROMIUM"] = str(candidates[0])
                break
    return env


@pytest.mark.parametrize("width,height,touch", [
    (1280, 900, False),
    (390, 844, True),
])
def test_long_command_box_is_visible_and_usable(tmp_path, width, height, touch):
    env = _node_env()
    if "KVM_PLAYWRIGHT" not in env or "KVM_CHROMIUM" not in env:
        pytest.skip("Playwright / Chromium not provisioned")

    html = worker.REAL_CONSOLE_HTML.replace(
        '<script src="/_platform/console.js"></script>',
        "<script>" + worker.REAL_CONSOLE_JS + "</script>")
    (tmp_path / "page.html").write_text(html, encoding="utf-8")
    (tmp_path / "keymap.json").write_text(
        json.dumps(text_input.keymap_document(), ensure_ascii=False), encoding="utf-8")

    proc = subprocess.run(
        ["node", str(FIXTURE),
         "--html", str(tmp_path / "page.html"),
         "--keymap", str(tmp_path / "keymap.json"),
         "--width", str(width), "--height", str(height),
         "--touch", "1" if touch else "0"],
        capture_output=True, text=True, env=env, timeout=90)
    assert proc.returncode == 0, proc.stderr
    report = json.loads(proc.stdout)

    on_keys = report["onKeys"]
    assert on_keys["keysTabOn"] is True and on_keys["pasteTabOn"] is False
    assert on_keys["softkeyVisible"] is True and on_keys["pasteVisible"] is False
    assert on_keys["visibleKeyCount"] > 0

    on_paste = report["onPaste"]
    assert on_paste["pasteTabOn"] is True and on_paste["keysTabOn"] is False
    assert on_paste["pasteVisible"] is True and on_paste["softkeyVisible"] is False
    assert on_paste["textareaInViewport"] is True, \
        f"text area fell outside the viewport at {width}x{height}: {on_paste['textarea']}"
    assert on_paste["textareaInsidePanel"] is True

    typed = report["typed"]
    assert typed["value"] == "ls -la /tmp"
    assert typed["focused"] == "paste-text"
    assert typed["sendDisabled"] is False
    assert report["errors"] == []
