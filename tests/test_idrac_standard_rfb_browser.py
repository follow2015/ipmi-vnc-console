"""P0 fixes for the standard RFB (VNC-over-TCP) browser path."""
from __future__ import annotations

import json
import shutil
import struct
import subprocess
from pathlib import Path

import pytest

from kvmhub import worker
from kvmhub.platform import text_input

RFB_JS = Path(worker.__file__).parent / "static" / "novnc" / "include" / "rfb.js"
FIXTURE = Path(__file__).with_name("fixtures") / "rfb_pixel_format.cjs"
BGRX32 = "2018000100ff00ff00ff100800000000"



def test_bundle_emits_the_agreed_bgrx32_set_pixel_format():
    node = shutil.which("node")
    if not node:  # pragma: no cover - machine dependent
        pytest.skip("node is required to execute the shipped rfb.js")
    result = subprocess.run(
        [node, str(FIXTURE), "--rfb", str(RFB_JS)],
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, result.stderr[-1000:]
    report = json.loads(result.stdout)
    assert report["length"] == 20
    assert report["hex"][8:] == BGRX32
    assert report["hex"][:8] == "00000000"


def test_standard_branch_requests_pixel_format_but_vendor_branches_do_not():
    source = RFB_JS.read_text(encoding="utf-8")
    assert "setPixelFormat:function()" in source
    marker = "if(this._true_color&&!this._rfb_insydevnc&&!this._rfb_tightvnc){this._sock.send(RFB.messages.setPixelFormat())}"
    assert marker in source, "standard branch must negotiate the pixel format"
    idx = source.index(marker)
    fbu = source.index("fbUpdateRequests", idx)
    assert fbu - idx < 200, "SetPixelFormat must precede the first update request"


def test_standard_branch_does_not_misreport_video_only():
    source = RFB_JS.read_text(encoding="utf-8")
    marker = 'if(!this._rfb_insydevnc||this._AST.KbMsEnable)this._updateState("normal","Connect to: "+this._fb_name);'
    assert marker in source, "standard sessions must not report Video Only/view_only"



def test_keysym_translation_is_x11_not_hid_usage():
    assert text_input.char_keysym("a") == 0x61
    assert text_input.char_keysym("A") == 0x41
    assert text_input.char_keysym("1") == 0x31
    assert text_input.char_keysym("\n") == 0xFF0D
    assert text_input.token_keysym("enter") == 0xFF0D
    assert text_input.token_keysym("up") == 0xFF52
    assert text_input.token_keysym("lctrl") == 0xFFE3
    assert text_input.token_keysym("f1") == 0xFFBE


def test_standard8_key_frames_are_8_bytes_with_keysym_and_no_shift_pair():
    plan = text_input.plan_text("A1\n")
    frames = [frame for frame, _ in text_input.frame_stream(plan, style="standard8")]
    assert len(frames) == 6
    assert all(len(frame) == 8 for frame in frames)
    assert all(frame[0] == 4 for frame in frames)
    keysyms = [struct.unpack(">I", frame[4:8])[0] for frame in frames]
    assert keysyms == [0x41, 0x41, 0x31, 0x31, 0xFF0D, 0xFF0D]
    assert [f[1] for f in frames] == [1, 0] * 3
    assert all(f[2:4] == b"\x00\x00" for f in frames)


def test_standard8_chord_uses_x11_modifier_keysyms():
    frames = [frame for frame, _ in text_input.chord_frames(
        ["lctrl", "c"], style="standard8")]
    keysyms = [struct.unpack(">I", frame[4:8])[0] for frame in frames]
    assert keysyms == [0xFFE3, 0x63, 0x63, 0xFFE3]
    assert all(len(frame) == 8 for frame in frames)


def test_keymap_document_carries_keysyms_for_the_browser():
    doc = text_input.keymap_document()
    assert doc["frame_styles"] == ["insyde18", "standard8"]
    assert doc["char_keysym"]["a"] == 0x61
    assert doc["char_keysym"]["A"] == 0x41
    assert doc["key_keysym"]["enter"] == 0xFF0D
    assert doc["left_shift_keysym"] == 0xFFE1



def test_input_protocol_declared_per_adapter():
    from kvmhub.adapters.idrac_vnc import IdracVncAdapter
    from kvmhub.adapters.passthrough import PassthroughAdapter

    class Stub:
        pass

    vnc = object.__new__(IdracVncAdapter)
    assert worker.input_protocol_for_adapter(vnc) == "standard8"
    passthrough = object.__new__(PassthroughAdapter)
    assert worker.input_protocol_for_adapter(passthrough) == "insyde18"
    assert worker.input_protocol_for_adapter(Stub()) == "insyde18"


def test_meta_publishes_input_protocol_without_secrets():
    source = Path(worker.__file__).read_text(encoding="utf-8")
    marker = 'if path == "/_platform/meta"'
    assert marker in source
    block = source[source.index(marker):source.index('if request.method != "GET"', source.index(marker))]
    assert '"input_protocol": input_protocol_for_adapter(sess.adapter)' in block
    code = "\n".join(line for line in block.splitlines()
                     if not line.lstrip().startswith("#")).lower()
    for secret in ("password", "ticket", "cookie", "credential"):
        assert secret not in code


def test_console_js_builds_both_frame_formats():
    js = worker.REAL_CONSOLE_JS
    assert "var inputProtocol = 'insyde18'" in js
    assert "data.input_protocol === 'standard8'" in js
    assert "data.input_protocol === 'view_only'" in js
    assert "return [4, down ? 1 : 0, 0, 0," in js
    assert "var ks = typeof keysym === 'number' ? keysym : usage;" not in js
    assert "if (typeof keysym !== 'number') return null;" in js
    assert "if (f !== null)" in js
    assert "pasteKeymap.char_keysym" in js
    assert "pasteKeymap.key_keysym" in js
    assert "0, 0, 0, 0, 0, 0, 0, 0, 0]" in js


def test_view_only_session_emits_no_key_frames():
    js = worker.REAL_CONSOLE_JS
    assert "if (inputProtocol === 'view_only') return null;" in js
    assert "if (!frames.length) {" in js
