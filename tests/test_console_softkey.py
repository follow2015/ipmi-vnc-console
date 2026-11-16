"""The on-screen keyboard must send the same frames the text box already proved."""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile

import pytest

from kvmhub import insyde_messages, worker
from kvmhub.platform import text_input

NAMED_KEYS = [
    "esc", "tab", "caps", "bksp", "enter", "space",
    "lshift", "rshift", "lctrl", "rctrl", "lalt", "ralt", "lwin",
    "home", "end", "del", "ins", "pgup", "pgdn",
    "up", "down", "left", "right",
] + [f"f{i}" for i in range(1, 13)]

MACRO_LABELS = [
    "Ctrl+Alt+Del", "Ctrl+C", "Ctrl+D", "Ctrl+L", "Ctrl+Z", "Ctrl+A",
    "Ctrl+E", "Ctrl+U", "Ctrl+K", "Ctrl+W", "Ctrl+R", "Ctrl+\\",
    "Ctrl+Alt+F1", "Ctrl+Alt+F2", "Ctrl+Alt+F3", "Alt+F2", "Tab", "Esc",
]


def _doc() -> dict:
    return text_input.keymap_document()


def test_keymap_carries_the_named_key_table():
    keys = _doc()["keys"]
    for name in NAMED_KEYS:
        assert name in keys, f"page draws {name!r} but the table has no usage for it"
        assert isinstance(keys[name], int)


def test_named_keys_are_plausible_hid_usages_and_do_not_collide():
    keys = _doc()["keys"]
    for name, usage in keys.items():
        assert 0x04 <= usage <= 0xE7, f"{name} = 0x{usage:02X} is outside page 0x07"
    assert len(set(keys.values())) == len(keys), "duplicate usage in the key table"


def test_named_keys_agree_with_the_character_table_where_they_overlap():
    doc = _doc()
    plain, keys = doc["plain"], doc["keys"]
    assert keys["enter"] == plain["\n"] == 0x28
    assert keys["tab"] == plain["\t"] == 0x2B
    assert keys["space"] == plain[" "] == 0x2C
    assert keys["esc"] == plain["\x1b"] == 0x29
    assert keys["bksp"] == plain["\x08"] == 0x2A
    assert doc["left_shift"] == keys["lshift"] == text_input.LEFT_SHIFT


def test_macros_are_declared_keys_only_and_keep_the_reference_order():
    doc = _doc()
    macros = doc["macros"]
    assert [m["label"] for m in macros] == MACRO_LABELS
    resolvable = set(doc["keys"]) | set(doc["plain"]) | set(doc["shifted"])
    for macro in macros:
        assert macro["keys"], macro["label"]
        for token in macro["keys"]:
            assert token in resolvable, f"{macro['label']} names unknown key {token!r}"
        assert len(macro["keys"]) >= 1
    assert all(any(t not in doc["modifiers"] for t in m["keys"]) for m in macros)


def test_modifier_list_matches_the_table():
    doc = _doc()
    assert set(doc["modifiers"]) == {"lctrl", "lshift", "lalt", "lwin",
                                     "rctrl", "rshift", "ralt"}
    for name in doc["modifiers"]:
        assert name in doc["keys"]


def test_a_chord_produces_paired_frames_the_gateway_can_parse():
    doc = _doc()
    frames = text_input.chord_frames(["lctrl", "lalt", "del"])
    assert frames
    assert all(len(frame) == 18 for frame, _ in frames)
    for frame, _ in frames:
        assert insyde_messages.parse_key_event(frame) is not None
    assert sum(1 for f, _ in frames if f[2] == 1) == sum(1 for f, _ in frames if f[2] == 0)
    assert frames[0][0] == insyde_messages.build_key_event(doc["keys"]["lctrl"], True)
    assert frames[-1][0] == insyde_messages.build_key_event(doc["keys"]["lctrl"], False)


def test_a_chord_can_carry_a_shifted_character():
    doc = _doc()
    frames = text_input.chord_frames(["lctrl", "|"])
    down = [f for f, _ in frames if f[2] == 1]
    assert insyde_messages.build_key_event(doc["left_shift"], True) in down
    assert insyde_messages.build_key_event(doc["plain"]["\\"], True) in down


def _served_tokens(html: str) -> list[str]:
    return re.findall(r'data-send="([^"]+)"', html)


def test_the_page_draws_only_keys_the_table_declares():
    doc = _doc()
    tokens = _served_tokens(worker.REAL_CONSOLE_HTML)
    assert tokens, "no soft keys in the page"
    resolvable = set(doc["keys"]) | set(doc["plain"]) | set(doc["shifted"])
    for token in tokens:
        assert token in resolvable, f"page draws {token!r}, table cannot send it"
    drawn = set(tokens)
    for name in NAMED_KEYS:
        assert name in drawn, f"page does not draw {name!r}"
    for mod in doc["modifiers"]:
        assert f'data-send="{mod}" data-mod="1"' in worker.REAL_CONSOLE_HTML or \
            re.search(rf'data-send="{mod}"[^>]*data-mod', worker.REAL_CONSOLE_HTML), \
            f"{mod} must be a latch, not a one-shot key"


def test_the_page_has_the_panel_wiring():
    html = worker.REAL_CONSOLE_HTML
    assert 'id="softkey"' in html
    assert 'id="sk-macros"' in html
    assert 'id="sk-status"' in html
    assert 'id="softkey-toggle"' in html
    assert "ClientCutText" not in html
    js = worker.REAL_CONSOLE_JS
    assert "/_platform/keymap" in js
    assert "pasteKeymap.macros" in js
    assert "pasteKeymap.keys" in js
    assert js.count("new RFB(") == 1


def test_the_page_explains_the_canvas_shift_defect():
    assert "Shift" in worker.REAL_CONSOLE_HTML
    assert "画面上直接键入" in worker.REAL_CONSOLE_HTML


def test_the_console_javascript_parses():
    node = shutil.which("node")
    if not node:  # pragma: no cover - depends on the machine
        pytest.skip("node not available")
    directory = tempfile.mkdtemp(prefix="kvmhub-js-")
    try:
        for name, source in (("real_console.js", worker.REAL_CONSOLE_JS),
                             ("console.js", worker.CONSOLE_JS)):
            path = os.path.join(directory, name)
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(source)
            result = subprocess.run([node, "--check", path],
                                    capture_output=True, text=True, timeout=60)
            assert result.returncode == 0, f"{name} does not parse:\n{result.stderr}"
    finally:
        shutil.rmtree(directory, ignore_errors=True)


def test_keymap_document_stays_json_serialisable_with_the_new_sections():
    doc = _doc()
    assert json.loads(json.dumps(doc, ensure_ascii=False)) == doc
