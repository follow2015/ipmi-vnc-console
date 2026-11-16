"""Synthetic replay of a structural trace, for M5 timing/type-sequence tests."""
from __future__ import annotations

import struct
from dataclasses import dataclass

GREETING = b"RFB 055.008\n"
SECURITY_TYPES = bytes([1, 16])
AUTH_CHALLENGE = b"Z" * 24
AUTH_RESULT = struct.pack(">I", 0)
SERVER_INIT = (
    struct.pack(">HHBBBBHHHBBB3xI", 1024, 768, 32, 24, 0, 1,
                255, 255, 255, 8, 8, 8, 4)
    + b"fake"
)

_HANDSHAKE_BLOBS = (GREETING, SECURITY_TYPES, AUTH_CHALLENGE, AUTH_RESULT, SERVER_INIT)


@dataclass(frozen=True)
class Frame:

    phase: str
    t_rel_ms: float
    type_byte: int
    length: int
    data: bytes


def handshake_frames() -> list[Frame]:
    frames: list[Frame] = []
    for index, blob in enumerate(_HANDSHAKE_BLOBS):
        frames.append(Frame("handshake", float(index),
                             blob[0] if blob else 0, len(blob), blob))
    return frames


def synthetic_payload(event: dict) -> bytes:
    length = int(event["length"])
    type_byte = int(event["type_byte"])
    if length <= 0:
        return b""
    if length == 1:
        return bytes([type_byte & 0xFF])
    body = bytes(((index * 31 + 7) & 0xFF) for index in range(length - 1))
    return bytes([type_byte & 0xFF]) + body


def replay(events: list[dict]) -> list[Frame]:
    frames = list(handshake_frames())
    for event in events:
        data = synthetic_payload(event)
        frames.append(Frame("stream", float(event["t_rel_ms"]),
                            data[0] if data else 0, len(data), data))
    return frames


def recorded_type_sequence(events: list[dict]) -> list[int]:
    return [int(event["type_byte"]) for event in events]


def stream_type_sequence(frames: list[Frame]) -> list[int]:
    return [frame.type_byte for frame in frames if frame.phase == "stream"]


def check_timing(events: list[dict], frames: list[Frame], tolerance_ms: float = 5.0) -> bool:
    stream = [frame for frame in frames if frame.phase == "stream"]
    if len(stream) != len(events):
        return False
    return all(
        abs(frame.t_rel_ms - float(event["t_rel_ms"])) <= tolerance_ms
        for event, frame in zip(events, stream)
    )


class Replayer:

    def __init__(self, frames: list[Frame], *, clock=None, sleep=None):
        self.frames = sorted(frames, key=lambda frame: frame.t_rel_ms)
        self.clock = clock
        self.sleep = sleep

    def run(self) -> list[dict]:
        if self.clock is None:
            raise ValueError("Replayer needs an injected clock for deterministic timing")
        start = self.clock()
        observed: list[dict] = []
        for frame in self.frames:
            target = start + frame.t_rel_ms / 1000.0
            wait = target - self.clock()
            if wait > 0:
                if self.sleep is None:
                    raise ValueError("Replayer needs an injected sleep to advance the clock")
                self.sleep(wait)
            observed.append({
                "phase": frame.phase,
                "t_rel_ms": round((self.clock() - start) * 1000.0, 3),
                "type_byte": frame.type_byte,
                "length": frame.length,
            })
        return observed
