"""Translate standard RFB browser input into Huawei iBMC private KVM frames."""
from __future__ import annotations

import struct
from dataclasses import dataclass, field

from . import huawei_kvm_protocol as P
from .platform.text_input import _KEYS, _PLAIN, _SHIFTED, _X11_KEYSYM_BY_USAGE

MOD_LCTRL = 0x01
MOD_RCTRL = 0x10
MOD_LSHIFT = 0x02
MOD_RSHIFT = 0x20
MOD_LALT = 0x04
MOD_RALT = 0x40
MOD_LWIN = 0x08
MOD_RWIN = 0x80

_USAGE_TO_MODIFIER = {
    0xE0: MOD_LCTRL, 0xE4: MOD_RCTRL,
    0xE1: MOD_LSHIFT, 0xE5: MOD_RSHIFT,
    0xE2: MOD_LALT, 0xE6: MOD_RALT,
    0xE3: MOD_LWIN,
}

_USAGE_BY_KEYSYM: dict[int, int] = {
    keysym: usage for usage, keysym in _X11_KEYSYM_BY_USAGE.items()
}

_USAGE_BY_CHAR: dict[int, tuple[int, bool]] = {}
for _ch, _usage in _PLAIN.items():
    _USAGE_BY_CHAR[ord(_ch)] = (_usage, False)
for _ch, _base in _SHIFTED.items():
    _USAGE_BY_CHAR[ord(_ch)] = (_PLAIN[_base], True)
for _upper in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
    _USAGE_BY_CHAR[ord(_upper)] = (_PLAIN[_upper.lower()], True)

HID_USAGES = frozenset(
    set(_PLAIN.values()) | set(_KEYS.values()) | set(_USAGE_TO_MODIFIER)
)

MAX_CLIENT_BUFFER = 1024 * 1024
_ABSOLUTE_MAX = 3000


def keysym_to_usage(keysym: int) -> tuple[int, bool] | None:
    usage = _USAGE_BY_KEYSYM.get(keysym)
    if usage is not None:
        return usage, False
    if 0 <= keysym <= 0x10FFFF:
        return _USAGE_BY_CHAR.get(keysym)
    return None


def _map_buttons(rfb_mask: int) -> int:
    out = 0
    if rfb_mask & 0x01:
        out |= 0x01
    if rfb_mask & 0x02:
        out |= 0x04
    if rfb_mask & 0x04:
        out |= 0x02
    return out & 0xFF


@dataclass
class InputStats:
    keys: int = 0
    pointers: int = 0
    packets: int = 0
    forwarded: int = 0
    ignored: int = 0
    unmapped: int = 0
    errors: int = 0


class BrowserInputTranslator:

    def __init__(self, tag_id: int, width: int, height: int) -> None:
        self.tag_id = tag_id
        self.width = max(1, int(width))
        self.height = max(1, int(height))
        self.modifiers = 0
        self.stats = InputStats()
        self._buf = bytearray()

    def feed(self, data: bytes) -> list[bytes]:
        if not data:
            return []
        self._buf.extend(data)
        if len(self._buf) > MAX_CLIENT_BUFFER:
            self.stats.ignored += len(self._buf)
            self._buf.clear()
            return []

        out: list[bytes] = []
        while self._buf:
            size = self._message_size()
            if size is None:
                del self._buf[:1]
                self.stats.ignored += 1
                continue
            if len(self._buf) < size:
                break
            message = bytes(self._buf[:size])
            del self._buf[:size]
            packet = self._translate(message)
            if packet is not None:
                out.append(packet)
        return out

    def _message_size(self) -> int | None:
        msg = self._buf[0]
        if msg == 0:
            return 20
        if msg == 2:
            if len(self._buf) < 4:
                return 4
            return 4 + 4 * int.from_bytes(self._buf[2:4], "big")
        if msg == 3:
            return 10
        if msg == 4:
            return 18 if self._is_insyde_key() else 8
        if msg == 5:
            return 18 if self._is_insyde_pointer() else 6
        if msg == 6:
            if len(self._buf) < 8:
                return 8
            return 8 + int.from_bytes(self._buf[4:8], "big")
        return None

    def _is_insyde_key(self) -> bool:
        b = self._buf
        if len(b) < 18 or b[1] != 0 or b[2] not in (0, 1) or b[3] != 0 or b[4] != 0:
            return False
        return int.from_bytes(b[5:9], "big") in HID_USAGES

    def _is_insyde_pointer(self) -> bool:
        b = self._buf
        return len(b) >= 18 and b[1] == 0 and not any(b[7:18])

    def _translate(self, message: bytes) -> bytes | None:
        kind = message[0]
        if kind == 4:
            return self._translate_key(message)
        if kind == 5:
            return self._translate_pointer(message)
        self.stats.ignored += 1
        return None

    def _translate_key(self, message: bytes) -> bytes | None:
        try:
            if self._is_insyde_key_frame(message):
                usage = int.from_bytes(message[5:9], "big")
                down = bool(message[2])
                shift = False
            else:
                keysym = int.from_bytes(message[4:8], "big")
                mapped = keysym_to_usage(keysym)
                if mapped is None:
                    self.stats.unmapped += 1
                    return None
                usage, shift = mapped
                down = bool(message[1])
        except (IndexError, ValueError):
            self.stats.errors += 1
            return None

        bit = _USAGE_TO_MODIFIER.get(usage)
        if bit is not None:
            if down:
                self.modifiers |= bit
            else:
                self.modifiers &= ~bit
            modifiers = self.modifiers
            key_usage = 0
        else:
            modifiers = self.modifiers | (MOD_LSHIFT if down and shift else 0)
            key_usage = usage if down else 0

        try:
            packet = P.keyboard_packet(self.tag_id, modifiers & 0xFF, key_usage)
        except ValueError:
            self.stats.errors += 1
            return None
        self.stats.keys += 1
        self.stats.packets += 1
        return packet

    @staticmethod
    def _is_insyde_key_frame(message: bytes) -> bool:
        return (len(message) == 18 and message[1] == 0
                and message[2] in (0, 1) and message[3] == 0
                and message[4] == 0
                and int.from_bytes(message[5:9], "big") in HID_USAGES)

    def _translate_pointer(self, message: bytes) -> bytes | None:
        insyde = len(message) == 18 and message[1] == 0 and not any(message[7:18])
        try:
            if insyde:
                mask = message[2]
                x = int.from_bytes(message[3:5], "big")
                y = int.from_bytes(message[5:7], "big")
            else:
                mask = message[1]
                x = int.from_bytes(message[2:4], "big")
                y = int.from_bytes(message[4:6], "big")
        except (IndexError, ValueError):
            self.stats.errors += 1
            return None

        x = min(max(x, 0), self.width)
        y = min(max(y, 0), self.height)
        scaled_x = int(x * _ABSOLUTE_MAX / self.width)
        scaled_y = int(y * _ABSOLUTE_MAX / self.height)
        try:
            packet = P.mouse_packet(self.tag_id, scaled_x, scaled_y, _map_buttons(mask))
        except ValueError:
            self.stats.errors += 1
            return None
        self.stats.pointers += 1
        self.stats.packets += 1
        return packet


def packet_command(packet: bytes) -> int:
    if len(packet) < 11 or packet[:3] != P.SYNC:
        return -1
    return packet[10]
