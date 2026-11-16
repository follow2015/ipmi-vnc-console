"""M5: structural trace recording and synthetic replay stay payload-free."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from tools.trace_record import (
    EVENT_FIELDS,
    FORBIDDEN_FRAME_KEYS,
    TRACE_ENV,
    FrameRecorder,
    frame_shape,
    main,
    make_event,
    parse_frames,
    recording_enabled,
)
from tests.support import replay_bmc
from tests.support.replay_bmc import (
    Replayer,
    check_timing,
    handshake_frames,
    recorded_type_sequence,
    replay,
    stream_type_sequence,
    synthetic_payload,
)

ROOT = Path(__file__).resolve().parents[1]
SCANNER = ROOT / "scripts" / "scan-secrets.py"

PAYLOAD_MARKER = "STRUCTURAL-PAYLOAD-CANARY-9c1f"

SAMPLE = [
    {"direction": "s2c", "t_rel_ms": 10.0, "type_byte": 0, "length": 24},
    {"direction": "c2s", "t_rel_ms": 25.5, "type_byte": 4, "length": 8},
    {"direction": "c2s", "t_rel_ms": 40.0, "type_byte": 5, "length": 6},
    {"direction": "s2c", "t_rel_ms": 60.25, "type_byte": 0, "length": 128},
]


class _FakeClock:

    def __init__(self) -> None:
        self.now = 100.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def _jsonl(frames) -> str:
    return "\n".join(json.dumps(frame) for frame in frames)



def test_make_event_has_only_the_four_structural_fields():
    event = make_event("c2s", 12.3456, 4, 8)
    assert set(event) == set(EVENT_FIELDS)
    assert event == {"direction": "c2s", "t_rel_ms": 12.346,
                     "type_byte": 4, "length": 8}
    assert "payload" not in event and "data" not in event


def test_frame_shape_reduces_a_payload_string_to_shape_only():
    event = frame_shape("prefix-" + PAYLOAD_MARKER, "c2s", 5.0)
    assert set(event) == set(EVENT_FIELDS)
    assert event["type_byte"] == ord("p")
    assert event["length"] == len("prefix-" + PAYLOAD_MARKER)
    assert PAYLOAD_MARKER not in json.dumps(event)


def test_recorder_never_retains_payload():
    recorder = FrameRecorder(clock=_FakeClock(), enabled=True, env={})
    blob = bytes([4]) + PAYLOAD_MARKER.encode() + bytes(40)
    event = recorder.record("c2s", blob)
    assert event["type_byte"] == 4
    assert event["length"] == len(blob)
    text = recorder.to_json()
    assert PAYLOAD_MARKER not in text
    assert all(set(item) == set(EVENT_FIELDS) for item in recorder.events)
    assert recorder.as_records()["payload_recorded"] is False


def test_recording_is_off_without_the_env_var(monkeypatch):
    monkeypatch.delenv(TRACE_ENV, raising=False)
    assert recording_enabled() is False
    recorder = FrameRecorder(clock=_FakeClock())
    assert recorder.enabled is False
    assert recorder.record("c2s", b"\x04" + PAYLOAD_MARKER.encode()) is None
    assert recorder.events == []


def test_recording_is_on_only_when_explicitly_enabled(monkeypatch):
    monkeypatch.setenv(TRACE_ENV, "1")
    assert recording_enabled() is True
    recorder = FrameRecorder(clock=_FakeClock())
    assert recorder.record("c2s", b"\x04") is not None
    assert len(recorder.events) == 1


def test_parse_frames_refuses_payload_bearing_keys():
    bad = dict(SAMPLE[0])
    bad["payload"] = PAYLOAD_MARKER
    lines = (_jsonl(SAMPLE) + "\n" + json.dumps(bad)).splitlines()
    with pytest.raises(ValueError, match="payload-bearing"):
        parse_frames(lines)


def test_parse_frames_emits_only_structural_events():
    events = parse_frames(_jsonl(SAMPLE).splitlines())
    assert events == [make_event(**frame) for frame in SAMPLE]
    assert all(set(event) == set(EVENT_FIELDS) for event in events)
    assert PAYLOAD_MARKER not in json.dumps(events)



def test_replay_type_sequence_matches_the_record():
    events = parse_frames(_jsonl(SAMPLE).splitlines())
    frames = replay(events)
    assert stream_type_sequence(frames) == recorded_type_sequence(events)
    assert recorded_type_sequence(events) == [0, 4, 5, 0]


def test_synthetic_payload_matches_recorded_type_and_length():
    for event in SAMPLE:
        data = synthetic_payload(event)
        assert len(data) == event["length"]
        if data:
            assert data[0] == event["type_byte"]
    assert synthetic_payload(SAMPLE[1]) == synthetic_payload(SAMPLE[1])
    assert synthetic_payload({"type_byte": 4, "length": 0}) == b""


def test_replayed_stream_timing_is_within_tolerance():
    events = parse_frames(_jsonl(SAMPLE).splitlines())
    frames = replay(events)
    assert check_timing(events, frames, tolerance_ms=0.5) is True
    clock = _FakeClock()
    observed = Replayer(frames, clock=clock, sleep=clock.advance).run()
    stream = [row for row in observed if row["phase"] == "stream"]
    assert [row["type_byte"] for row in stream] == recorded_type_sequence(events)
    for event, row in zip(events, stream):
        assert abs(row["t_rel_ms"] - event["t_rel_ms"]) <= 0.5


def test_check_timing_rejects_a_dropped_or_shifted_frame():
    events = parse_frames(_jsonl(SAMPLE).splitlines())
    frames = [frame for frame in replay(events) if frame.phase == "handshake"]
    assert check_timing(events, frames, tolerance_ms=0.5) is False


def test_handshake_bytes_are_desensitised():
    frames = handshake_frames()
    assert frames and all(frame.phase == "handshake" for frame in frames)
    blob = b"".join(frame.data for frame in frames)
    assert PAYLOAD_MARKER.encode() not in blob
    assert replay_bmc.GREETING.startswith(b"RFB ")
    assert replay_bmc.AUTH_CHALLENGE == b"Z" * 24
    assert replay_bmc.AUTH_RESULT == b"\x00\x00\x00\x00"



def test_scanner_style_check_record_file_has_no_sentinel(tmp_path):
    clock = _FakeClock()
    recorder = FrameRecorder(clock=clock, enabled=True, env={})
    blob = bytes([4]) + PAYLOAD_MARKER.encode() + bytes(32)
    recorder.record("c2s", blob)
    recorder.record("s2c", bytes(20))
    path = recorder.write(tmp_path / "trace.json")
    text = path.read_text(encoding="utf-8")

    assert PAYLOAD_MARKER not in text
    for key in FORBIDDEN_FRAME_KEYS:
        assert f'"{key}"' not in text
    doc = json.loads(text)
    assert doc["payload_recorded"] is False
    assert all(set(event) == set(EVENT_FIELDS) for event in doc["events"])

    spec = importlib.util.spec_from_file_location("_kvm_scan_secrets", SCANNER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.scan_file(path, text) == []


def test_cli_requires_optin_and_writes_structural_records(tmp_path, monkeypatch):
    source = tmp_path / "frames.jsonl"
    source.write_text(_jsonl(SAMPLE) + "\n", encoding="utf-8")
    out = tmp_path / "out.json"

    monkeypatch.delenv(TRACE_ENV, raising=False)
    assert main(["--input", str(source), "--out", str(out)]) == 2
    assert not out.exists()

    monkeypatch.setenv(TRACE_ENV, "1")
    assert main(["--input", str(source), "--out", str(out)]) == 0
    text = out.read_text(encoding="utf-8")
    assert PAYLOAD_MARKER not in text
    doc = json.loads(text)
    assert doc["event_count"] == len(SAMPLE)
    assert doc["payload_recorded"] is False
    assert all(set(event) == set(EVENT_FIELDS) for event in doc["events"])


def test_cli_refuses_a_frame_carrying_payload(tmp_path, monkeypatch):
    bad = dict(SAMPLE[0])
    bad["payload"] = PAYLOAD_MARKER
    source = tmp_path / "frames.jsonl"
    source.write_text(json.dumps(bad) + "\n", encoding="utf-8")
    out = tmp_path / "out.json"
    monkeypatch.setenv(TRACE_ENV, "1")
    assert main(["--input", str(source), "--out", str(out)]) == 2
    assert not out.exists()
