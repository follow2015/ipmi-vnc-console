"""M2.0: the wire layout of the measured Insyde client's key/pointer events."""
from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Any

KEY_EVENT_TYPE = 4
POINTER_EVENT_TYPE = 5
KEY_EVENT_SIZE = 18
POINTER_EVENT_SIZE = 18
MAX_UINT32 = 2 ** 32 - 1
MAX_UINT16 = 2 ** 16 - 1


@dataclass(frozen=True)
class InsydeKeyEvent:
    down: bool
    key: int

    def to_bytes(self) -> bytes:
        return build_key_event(self.key, self.down)


@dataclass(frozen=True)
class InsydePointerEvent:
    mask: int
    x: int
    y: int

    def to_bytes(self) -> bytes:
        return build_pointer_event(self.x, self.y, self.mask)


def _bytes(data: Any) -> bytes | None:
    if isinstance(data, (bytes, bytearray, memoryview)):
        return bytes(data)
    return None


def build_key_event(key: int, down: bool) -> bytes:
    if isinstance(key, bool) or not isinstance(key, int) or not 0 <= key <= MAX_UINT32:
        raise ValueError("key must be a uint32")
    if not isinstance(down, bool):
        raise ValueError("down must be a bool")
    return (struct.pack(">BBBHI", KEY_EVENT_TYPE, 0, int(down), 0, key)
            + b"\x00" * 9)


def parse_key_event(data: Any) -> InsydeKeyEvent | None:
    raw = _bytes(data)
    if raw is None or len(raw) != KEY_EVENT_SIZE or raw[0] != KEY_EVENT_TYPE:
        return None
    if raw[1] != 0 or raw[3:5] != b"\x00\x00" or raw[9:] != b"\x00" * 9:
        return None
    if raw[2] not in (0, 1):
        return None
    key = struct.unpack(">I", raw[5:9])[0]
    return InsydeKeyEvent(down=bool(raw[2]), key=key)


def build_pointer_event(x: int, y: int, mask: int) -> bytes:
    for name, value, cap in (("x", x, MAX_UINT16), ("y", y, MAX_UINT16),
                             ("mask", mask, 255)):
        if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= cap:
            raise ValueError(f"{name} must be within 0..{cap}")
    return (struct.pack(">BBBHH", POINTER_EVENT_TYPE, 0, mask, x, y)
            + b"\x00" * 11)


def parse_pointer_event(data: Any) -> InsydePointerEvent | None:
    raw = _bytes(data)
    if raw is None or len(raw) != POINTER_EVENT_SIZE or raw[0] != POINTER_EVENT_TYPE:
        return None
    if raw[1] != 0 or raw[7:] != b"\x00" * 11:
        return None
    mask, x, y = struct.unpack(">BHH", raw[2:7])
    return InsydePointerEvent(mask=mask, x=x, y=y)


def is_key_release(data: Any) -> bool:
    event = parse_key_event(data)
    return event is not None and not event.down
