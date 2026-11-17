"""M2.1–2.3: gateway-side input shaping, off unless a capability enables it."""
from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any

from .insyde_messages import build_key_event, parse_key_event

_RANGE = {
    "min_hold_ms": (0, 500),
    "min_gap_ms": (0, 200),
    "max_keys_per_s": (0, 200),
    "queue_limit": (16, 1024),
}
_DEFAULTS = {"min_hold_ms": 0, "min_gap_ms": 0, "max_keys_per_s": 0,
            "queue_limit": 256, "release_on_close": True}


class InputOverflow(Exception):

    code = "input_overflow"


@dataclass(frozen=True)
class InputShapingConfig:
    min_hold_ms: int = 0
    min_gap_ms: int = 0
    max_keys_per_s: int = 0
    queue_limit: int = 256
    release_on_close: bool = True
    declared: bool = False

    @property
    def enabled(self) -> bool:
        return self.declared and (
            bool(self.min_hold_ms or self.min_gap_ms or self.max_keys_per_s)
            or self.release_on_close)

    @classmethod
    def parse(cls, raw: Any) -> InputShapingConfig | None:
        if raw is None or raw == "" or raw == {}:
            return None
        if isinstance(raw, str):
            try:
                parsed = json.loads(raw)
            except ValueError as exc:
                raise ValueError("input_shaping_malformed") from exc
        elif isinstance(raw, dict):
            parsed = dict(raw)
        else:
            raise ValueError("input_shaping_malformed")
        if not isinstance(parsed, dict):
            raise ValueError("input_shaping_malformed")
        if not parsed:
            return None
        unknown = set(parsed) - set(_DEFAULTS)
        if unknown:
            raise ValueError("input_shaping_unknown_field")
        values = dict(_DEFAULTS)
        for key, (low, high) in _RANGE.items():
            if key not in parsed:
                continue
            value = parsed[key]
            if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
                raise ValueError(f"input_shaping_invalid_{key}")
            values[key] = value
        if "release_on_close" in parsed:
            if not isinstance(parsed["release_on_close"], bool):
                raise ValueError("input_shaping_invalid_release_on_close")
            values["release_on_close"] = parsed["release_on_close"]
        values["declared"] = True
        return cls(**values)

    def as_dict(self) -> dict[str, Any]:
        return {key: getattr(self, key) for key in _DEFAULTS}


@dataclass(frozen=True)
class _Queued:
    message: bytes
    due_at: float


class InputShaper:

    def __init__(self, cfg: InputShapingConfig, clock=time.monotonic) -> None:
        self.cfg = cfg
        self.clock = clock
        self._queue: list[_Queued] = []
        self._pressed: dict[int, float] = {}
        self._emitted_pressed: set[int] = set()
        self._next_key_at = 0.0

    @property
    def pending(self) -> int:
        return len(self._queue)

    @property
    def pressed_keys(self) -> frozenset[int]:
        return frozenset(self._pressed)

    def next_due(self) -> float | None:
        return self._queue[0].due_at if self._queue else None

    def _gap(self) -> float:
        gaps = [self.cfg.min_gap_ms / 1000.0]
        if self.cfg.max_keys_per_s:
            gaps.append(1.0 / self.cfg.max_keys_per_s)
        return max(gaps)

    def _enqueue(self, message: bytes, due_at: float) -> None:
        if len(self._queue) >= self.cfg.queue_limit:
            raise InputOverflow()
        self._queue.append(_Queued(message, due_at))

    def _emitted(self, message: bytes) -> bytes:
        event = parse_key_event(message)
        if event is not None:
            if event.down:
                self._emitted_pressed.add(event.key)
            else:
                self._emitted_pressed.discard(event.key)
        return message

    def feed(self, message: bytes) -> list[bytes]:
        now = self.clock()
        out = self.drain(now)
        event = parse_key_event(message)
        if event is None:
            if self._queue:
                self._enqueue(message, self._queue[-1].due_at)
            else:
                out.append(message)
            return out

        if event.down:
            earliest = now
        else:
            press_at = self._pressed.pop(event.key, None)
            earliest = (press_at + self.cfg.min_hold_ms / 1000.0
                        if press_at is not None else now)

        due = max(now, earliest, self._next_key_at)
        if event.down:
            self._pressed[event.key] = due
        if self._queue or due > now + 1e-9:
            self._enqueue(message, due)
            self._next_key_at = due + self._gap()
        else:
            out.append(self._emitted(message))
            self._next_key_at = now + self._gap()
        return out

    def drain(self, now: float | None = None) -> list[bytes]:
        current = self.clock() if now is None else now
        out: list[bytes] = []
        while self._queue and self._queue[0].due_at <= current:
            out.append(self._emitted(self._queue.pop(0).message))
        return out

    def release_all(self) -> list[bytes]:
        if not self.cfg.release_on_close:
            return []
        out = [build_key_event(key, False)
               for key in sorted(set(self._pressed) | self._emitted_pressed)]
        self._pressed.clear()
        self._emitted_pressed.clear()
        self._queue.clear()
        return out
