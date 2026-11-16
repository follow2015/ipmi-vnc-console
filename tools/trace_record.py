"""Lab-only recorder of passthrough console *structure*, never payload."""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

TRACE_ENV = "KVM_TRACE_RECORD"
TRACE_FORMAT = "kvm-structural-trace/1"

DIRECTIONS = ("c2s", "s2c")

EVENT_FIELDS = ("direction", "t_rel_ms", "type_byte", "length")

FORBIDDEN_FRAME_KEYS = frozenset({
    "payload", "data", "bytes", "frame", "raw", "content", "text", "secret",
    "password", "passwd", "pwd", "credential", "ticket", "value",
})


def recording_enabled(env: dict | None = None) -> bool:
    source = os.environ if env is None else env
    value = str(source.get(TRACE_ENV, "")).strip().lower()
    return value in ("1", "true", "yes", "on")


def make_event(direction: str, t_rel_ms: float, type_byte: int, length: int) -> dict:
    if direction not in DIRECTIONS:
        raise ValueError(f"direction must be one of {DIRECTIONS}, got {direction!r}")
    if isinstance(type_byte, bool) or not isinstance(type_byte, int) or not 0 <= type_byte <= 255:
        raise ValueError("type_byte must be an integer in 0..255")
    if isinstance(length, bool) or not isinstance(length, int) or length < 0:
        raise ValueError("length must be a non-negative integer")
    try:
        relative = float(t_rel_ms)
    except (TypeError, ValueError) as exc:
        raise ValueError("t_rel_ms must be a number") from exc
    if relative < 0:
        raise ValueError("t_rel_ms must be non-negative")
    return {"direction": direction, "t_rel_ms": round(relative, 3),
            "type_byte": type_byte, "length": length}


def frame_shape(data, direction: str, t_rel_ms: float) -> dict:
    if isinstance(data, str):
        data = data.encode("utf-8", "replace")
    type_byte = data[0] if data else 0
    length = len(data)
    return make_event(direction, t_rel_ms, int(type_byte), length)


class FrameRecorder:

    def __init__(self, *, clock=None, enabled: bool | None = None, env: dict | None = None):
        self._clock = clock or time.monotonic
        self._enabled = recording_enabled(env) if enabled is None else bool(enabled)
        self._start = self._clock()
        self._events: list[dict] = []

    @property
    def enabled(self) -> bool:
        return self._enabled

    def record(self, direction: str, data) -> dict | None:
        if not self._enabled:
            return None
        elapsed_ms = max(0.0, (self._clock() - self._start) * 1000.0)
        event = frame_shape(data, direction, elapsed_ms)
        self._events.append(event)
        return event

    @property
    def events(self) -> list[dict]:
        return [dict(event) for event in self._events]

    def as_records(self) -> dict:
        return records_dict(self.events)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.as_records(), indent=indent, ensure_ascii=False)

    def write(self, path) -> Path:
        target = Path(path)
        target.write_text(self.to_json() + "\n", encoding="utf-8")
        return target


def parse_frames(lines) -> list[dict]:
    events: list[dict] = []
    for number, raw in enumerate(lines, 1):
        line = raw.strip() if isinstance(raw, str) else str(raw).strip()
        if not line or line.startswith("#"):
            continue
        try:
            frame = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"line {number}: not valid JSON: {exc}") from exc
        if not isinstance(frame, dict):
            raise ValueError(f"line {number}: expected a JSON object")
        smuggled = sorted(set(frame) & FORBIDDEN_FRAME_KEYS)
        if smuggled:
            raise ValueError(f"line {number}: payload-bearing keys refused: {smuggled}")
        try:
            direction = frame["direction"]
            relative = float(frame["t_rel_ms"])
            type_byte = int(frame["type_byte"])
            length = int(frame["length"])
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError(
                f"line {number}: needs direction/t_rel_ms/type_byte/length ({exc})") from exc
        events.append(make_event(direction, relative, type_byte, length))
    return events


def records_dict(events: list[dict]) -> dict:
    return {"format": TRACE_FORMAT, "payload_recorded": False,
            "event_count": len(events), "events": list(events)}


def records_json(events: list[dict], indent: int = 2) -> str:
    return json.dumps(records_dict(events), indent=indent, ensure_ascii=False)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Record passthrough console frame structure (lab only, no payload).",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--input", default="-",
                        help="JSON-lines frame headers; '-' reads stdin (default)")
    parser.add_argument("--out", default="-",
                        help="output JSON path; '-' writes stdout (default)")
    args = parser.parse_args(argv)

    if not recording_enabled():
        print(f"error: recording is opt-in; set {TRACE_ENV}=1 to enable", file=sys.stderr)
        return 2

    if args.input == "-":
        lines = sys.stdin.read().splitlines()
    else:
        try:
            lines = Path(args.input).read_text(encoding="utf-8").splitlines()
        except OSError as exc:
            print(f"error: cannot read --input: {exc}", file=sys.stderr)
            return 2

    try:
        events = parse_frames(lines)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    text = records_json(events) + "\n"
    if args.out == "-":
        sys.stdout.write(text)
    else:
        try:
            Path(args.out).write_text(text, encoding="utf-8")
        except OSError as exc:
            print(f"error: cannot write --out: {exc}", file=sys.stderr)
            return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
