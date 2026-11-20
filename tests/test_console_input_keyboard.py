"""Manual typing into the long-command box must survive the vendor keyboard grab."""
import json
import os
import subprocess
from pathlib import Path

import pytest

from kvmhub import worker
from kvmhub.platform import text_input

FIXTURE = Path(__file__).parent / "fixtures" / "input_key_isolation.cjs"


def _node_env():
    env = dict(os.environ)
    if "KVM_PLAYWRIGHT" not in env:
        local = Path(__file__).parent.parent / ".local-playwright" / "node_modules" / "playwright-core"
        if local.exists():
            env["KVM_PLAYWRIGHT"] = str(local)
    if "KVM_CHROMIUM" not in env:
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


def test_manual_typing_isolates_from_vendor_keyboard_grab(tmp_path):
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
         "--keymap", str(tmp_path / "keymap.json")],
        capture_output=True, text=True, env=env, timeout=90)
    assert proc.returncode == 0, proc.stderr
    report = json.loads(proc.stdout)

    assert report["canvasReached"], \
        "the remote keyboard path (canvas -> document) must stay intact"
    assert report["typed"]["value"] == "ls -la /tmp", \
        "manual typing must insert characters into the textarea"
    assert report["typed"]["docKeys"] == [], \
        "text-field keystrokes must not bubble to the vendor noVNC handler"
    assert report["sendDisabled"] is False
    assert report["errors"] == []
