"""M2.0 Key-layout structural probe in tools/passthrough_browser.cjs."""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CJS = ROOT / "tools" / "passthrough_browser.cjs"

HARNESS = r'''
const m = require(process.argv[2]);
const out = {};
const key = new Uint8Array(18); key[0] = 4; key[2] = 1; key[8] = 0xE1;
const up = new Uint8Array(18); up[0] = 4; up[2] = 0; up[8] = 0xE1;
const pointer = new Uint8Array([5, 0, 1, 2, 0, 3]);
out.key_down = m.kvmLayoutRecord(key);
out.key_up = m.kvmLayoutRecord(up);
out.pointer = m.kvmLayoutRecord(pointer);
out.short_type4 = m.kvmLayoutRecord(new Uint8Array([4, 1]));
out.text = m.kvmLayoutRecord('plain text');
out.summary = m.kvmLayoutSummary([out.key_down, out.key_up, out.pointer,
                                   out.short_type4], false);
out.summary_empty = m.kvmLayoutSummary([], false);
out.summary_truncated = m.kvmLayoutSummary([out.key_down], true);
out.installer_source = m.installLayoutHook.toString();

const sent = [];
global.window = { __kvm: { _sock: { send: (d) => sent.push(d), __counted: false } } };
m.installLayoutHook({ layout: true, max: 2 });
global.window.__kvm._sock.send(key);
global.window.__kvm._sock.send(pointer);
global.window.__kvm._sock.send(new Uint8Array([4]));
out.hook = { sent_count: sent.length, bytes: global.window.__kvmSent,
             layout: global.window.__kvmLayout,
             truncated: global.window.__kvmLayoutTruncated,
             counted: global.window.__kvm._sock.__counted };

const sentOff = [];
global.window = { __kvm: { _sock: { send: (d) => sentOff.push(d), __counted: false } } };
m.installLayoutHook({ layout: false, max: 2 });
global.window.__kvm._sock.send(new Uint8Array([1, 2, 3]));
out.hook_off = { bytes: global.window.__kvmSent,
                 layout: global.window.__kvmLayout };

out.sequence = m.PROBE_KEY_SEQUENCE;
console.log(JSON.stringify(out));
'''


@pytest.fixture(scope="module")
def probe(tmp_path_factory):
    node = shutil.which("node")
    if not node:
        pytest.skip("node is not installed")
    harness = tmp_path_factory.mktemp("key-layout") / "harness.cjs"
    harness.write_text(HARNESS, encoding="utf-8")
    completed = subprocess.run([node, str(harness), CJS.as_posix()],
                                capture_output=True, text=True, timeout=30)
    assert completed.returncode == 0, completed.stderr
    return json.loads(completed.stdout)


def test_cjs_is_valid_javascript():
    node = shutil.which("node")
    if not node:
        pytest.skip("node is not installed")
    completed = subprocess.run([node, "--check", str(CJS)],
                               capture_output=True, text=True, timeout=30)
    assert completed.returncode == 0, completed.stderr



def test_key_record_is_pure_structure_without_the_key_code_value(probe):
    record = probe["key_down"]
    assert set(record) == {"length", "type", "down", "nonzero", "pad_zero"}
    assert record["length"] == 18 and record["type"] == 4 and record["down"] == 1
    assert record["nonzero"] == [0, 2, 8]
    assert str(0xE1) not in json.dumps(record)
    assert "data" not in record and "payload" not in record and "bytes" not in record


def test_released_key_drops_the_down_flag_from_the_nonzero_set(probe):
    record = probe["key_up"]
    assert record["down"] == 0
    assert record["nonzero"] == [0, 8]
    assert record["pad_zero"] is True


def test_non_key_messages_carry_only_length_and_type(probe):
    assert probe["pointer"] == {"length": 6, "type": 5}
    assert probe["short_type4"] == {"length": 2, "type": 4}
    assert probe["text"] == {"length": 10, "type": None}
    for record in (probe["pointer"], probe["short_type4"], probe["text"]):
        assert "down" not in record and "nonzero" not in record



def test_summary_reports_samples_down_distribution_and_nonzero_set(probe):
    summary = probe["summary"]
    assert summary["samples"] == 4
    assert summary["key_samples"] == 2
    assert summary["down_values"] == {"1": 1, "0": 1}
    assert summary["nonzero_positions"] == [0, 2, 8]
    assert summary["pad_all_zero"] is True
    assert summary["truncated"] is False
    assert 8 not in summary["pad_positions"]


def test_summary_does_not_invent_a_pad_verdict_without_key_samples(probe):
    assert probe["summary_empty"]["key_samples"] == 0
    assert probe["summary_empty"]["pad_all_zero"] is None


def test_summary_records_truncation_honestly(probe):
    assert probe["summary_truncated"]["truncated"] is True



def test_hook_captures_structure_and_truncates_at_the_cap(probe):
    hook = probe["hook"]
    assert hook["sent_count"] == 3
    assert hook["bytes"] == 25
    assert len(hook["layout"]) == 2
    assert hook["truncated"] is True
    assert hook["counted"] is True
    assert all(set(r) <= {"length", "type", "down", "nonzero", "pad_zero"}
               for r in hook["layout"])


def test_hook_with_probe_off_keeps_byte_counting_and_stores_nothing(probe):
    off = probe["hook_off"]
    assert off["bytes"] == 3
    assert off["layout"] == []


def test_hook_is_csp_safe_with_no_in_page_eval(probe):
    source = probe["installer_source"]
    assert "function kvmLayoutRecord(data)" in source
    assert "new Function" not in source
    assert "eval(" not in source



def test_probe_key_sequence_is_the_fixed_harmless_set(probe):
    assert probe["sequence"] == ["a", "Shift+a", "Escape", "ArrowRight"]


def test_source_wires_the_env_flags_and_result_field():
    source = CJS.read_text(encoding="utf-8")
    assert "KVM_KEY_LAYOUT_PROBE" in source
    assert "KVM_PROBE_KEYS" in source
    assert "window.__kvmLayout" in source
    assert "result.key_layout" in source
    assert "installLayoutHook" in source


def test_probe_sequence_forbids_dangerous_keys_and_long_presses():
    source = CJS.read_text(encoding="utf-8")
    line = next(l for l in source.splitlines()
                if "PROBE_KEY_SEQUENCE =" in l and "process.env" not in l
                and "const PROBE_KEY_SEQUENCE" in l)
    for forbidden in ("Enter", "Control+Alt", "Delete", "F2"):
        assert forbidden not in line
    assert "keyboard.down(part).catch" in source
    assert "keyboard.up(part).catch" in source
    assert "parts.slice().reverse()" in source
    assert "waitForTimeout(PROBE_KEY_GAP_MS)" in source
    assert "hold" not in line
