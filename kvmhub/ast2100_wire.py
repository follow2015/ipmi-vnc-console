"""Translate the measured AST2100 vendor wire to and from standard RFB."""
from __future__ import annotations

import struct
from collections.abc import Callable

from .ast2100_keymap import AST2100_KEYMAP, XK_CAPS_LOCK
from .ast2100_protocol import (MAX_CURSOR_DIMENSION, MAX_NAME_BYTES,
                               SERVER_INIT_EXTENSION_BYTES, SERVER_INIT_FIXED_BYTES)
from .insyde_messages import build_key_event, build_pointer_event
from .rfb_server import RFB_PIXEL_FORMAT_32BPP
from .rfb_upstream import framebuffer_update_request

ENCODING_AST2100 = 87
PSEUDO_DESKTOP_SIZE = -223
CURSOR_TAG = -0x41535443

GREETING_003 = "RFB 003.008"
GREETING_055 = "RFB 055.008"
MOUSE_SYNC = bytes([7, 0x07, 0xC0])
CURSOR_REQUEST = b"\x19"

MAX_RECTS = 64
MAX_PAYLOAD = 16 * 1024 * 1024
MAX_CURSOR_SIDE = MAX_CURSOR_DIMENSION
VENDOR_ONLY_MESSAGES = {22: 1 + 1, 26: 1, 53: 1, 54: 1, 55: 1 + 3,
                        57: 1 + 4 + 4 + 256, 60: 1, 65: 1}
VENDOR_WIDTH_LIMIT = 1920
VENDOR_HEIGHT_LIMIT = 1280
FALLBACK_SIZE = (640, 480)


class Ast2100StreamError(ValueError):

    def __init__(self, code: str, **shape: int | str) -> None:
        super().__init__(code)
        self.code = code
        self.shape = shape


def standard_server_init(raw: bytes) -> bytes:
    if len(raw) < SERVER_INIT_FIXED_BYTES:
        raise Ast2100StreamError("ast2100_stream_desync", kind="server_init")
    width, height = struct.unpack_from(">HH", raw, 0)
    (name_length,) = struct.unpack_from(">I", raw, 20)
    end = SERVER_INIT_FIXED_BYTES + name_length
    rest = len(raw) - end
    if name_length > MAX_NAME_BYTES or rest not in (0, SERVER_INIT_EXTENSION_BYTES):
        raise Ast2100StreamError("ast2100_stream_desync", kind="server_init",
                                 name_length=name_length, extension=rest)
    return (struct.pack(">HH", width, height) + RFB_PIXEL_FORMAT_32BPP
            + raw[20:end])


class Ast2100ServerStream:

    def __init__(self) -> None:
        self._buf = bytearray()
        self._width = 0
        self._height = 0
        self.message_types: dict[int, int] = {}
        self.encodings: dict[int, int] = {}
        self.frames = 0
        self.on_frame: Callable[[], None] | None = None

    def feed(self, data: bytes) -> bytes:
        self._buf.extend(data)
        out = bytearray()
        while True:
            item = self._next()
            if item is None:
                break
            out += item
        return bytes(out)

    def reset(self) -> None:
        self._buf.clear()

    @property
    def frame_size(self) -> tuple[int, int]:
        return (self._width or FALLBACK_SIZE[0], self._height or FALLBACK_SIZE[1])

    def _seen(self, kind: int) -> None:
        self.message_types[kind] = self.message_types.get(kind, 0) + 1

    def _next(self) -> bytes | None:
        buf = self._buf
        if not buf:
            return None
        kind = buf[0]
        if kind == 0:
            return self._framebuffer_update()
        if kind == 2:
            del buf[:1]
            self._seen(kind)
            return b"\x02"
        if kind == 3:
            return self._cut_text()
        if kind == 4:
            return self._cursor()
        size = VENDOR_ONLY_MESSAGES.get(kind)
        if size is None:
            raise Ast2100StreamError("ast2100_stream_unsupported", kind=kind)
        if len(buf) < size:
            return None
        del buf[:size]
        self._seen(kind)
        return b""

    def _framebuffer_update(self) -> bytes | None:
        buf = self._buf
        if len(buf) < 4:
            return None
        rects = int.from_bytes(buf[2:4], "big")
        if buf[1] != 0 or not 1 <= rects <= MAX_RECTS:
            raise Ast2100StreamError("ast2100_stream_desync", kind=0, rects=rects)
        offset = 4
        emitted: list[bytes] = []
        for _ in range(rects):
            if len(buf) < offset + 20:
                return None
            x, y, width, height, encoding, _mode, length = struct.unpack_from(
                ">HHHHiII", buf, offset)
            if encoding != ENCODING_AST2100:
                raise Ast2100StreamError("ast2100_stream_unsupported",
                                         kind=0, encoding=encoding)
            if length > MAX_PAYLOAD:
                raise Ast2100StreamError("ast2100_stream_desync", kind=0, length=length)
            end = offset + 20 + length
            if len(buf) < end:
                return None
            if width > VENDOR_WIDTH_LIMIT or height > VENDOR_HEIGHT_LIMIT:
                width = self._width or FALLBACK_SIZE[0]
                height = self._height or FALLBACK_SIZE[1]
            if (width, height) != (self._width, self._height):
                emitted.append(struct.pack(">HHHHi", 0, 0, width, height,
                                           PSEUDO_DESKTOP_SIZE))
                self._width, self._height = width, height
            emitted.append(struct.pack(">HHHHi", x, y, width, height, ENCODING_AST2100)
                           + bytes(buf[offset + 12:end]))
            offset = end
            self._seen(0)
            self.encodings[encoding] = self.encodings.get(encoding, 0) + 1
        del buf[:offset]
        self.frames += 1
        if self.on_frame is not None:
            self.on_frame()
        return bytes([0, 0]) + struct.pack(">H", len(emitted)) + b"".join(emitted)

    def _cut_text(self) -> bytes | None:
        buf = self._buf
        if len(buf) < 8:
            return None
        length = int.from_bytes(buf[4:8], "big")
        if length > MAX_PAYLOAD:
            raise Ast2100StreamError("ast2100_stream_desync", kind=3, length=length)
        if len(buf) < 8 + length:
            return None
        out = bytes(buf[:8 + length])
        del buf[:8 + length]
        self._seen(3)
        return out

    def _cursor(self) -> bytes | None:
        buf = self._buf
        if len(buf) < 21:
            return None
        x, y, width, height, valid = struct.unpack_from(">5I", buf, 1)
        if valid not in (0, 1):
            raise Ast2100StreamError("ast2100_stream_desync", kind=4, valid=valid)
        if valid != 1:
            del buf[:21]
            self._seen(4)
            return b""
        if not width or not height or width > MAX_CURSOR_SIDE or height > MAX_CURSOR_SIDE:
            raise Ast2100StreamError("ast2100_stream_unsupported",
                                     kind=4, width=width, height=height)
        size = 25 + width * height * 2
        if len(buf) < size:
            return None
        pattern = buf[25:size]
        rgba = bytearray(width * height * 4)
        for index in range(width * height):
            low, high = pattern[2 * index], pattern[2 * index + 1]
            if low or high:
                rgba[4 *index] = (high & 0x0F) << 4
                rgba[4 * index + 1] = (low >> 4) << 4
                rgba[4 * index + 2] = (low & 0x0F) << 4
                rgba[4 * index + 3] = 0xFF
        del buf[:size]
        self._seen(4)
        return (struct.pack(">BBH", 0, 0, 1)
                + struct.pack(">HHHHi", 0, 0, width, height, CURSOR_TAG)
                + struct.pack(">HH", min(x, 0xFFFF), min(y, 0xFFFF)) + rgba)


class Ast2100ClientStream:

    def __init__(self, version: str) -> None:
        self.version = version
        self._after_frame = False
        self._caps_lk = False
        self.dropped_keys = 0

    def note_frame(self) -> None:
        self._after_frame = True

    @property
    def opening(self) -> bytes:
        return MOUSE_SYNC if self.version == GREETING_055 else b""

    def translate(self, message: bytes) -> list[bytes]:
        kind = message[0]
        if kind in (0, 2):
            return []
        if kind == 3:
            out = [message]
            if self._after_frame and self.version == GREETING_003:
                out.append(CURSOR_REQUEST)
            self._after_frame = False
            return out
        if kind == 4:
            down = bool(message[1])
            keysym = int.from_bytes(message[4:8], "big")
            usage = AST2100_KEYMAP.get(keysym)
            if usage is None:
                self.dropped_keys += 1
                return []
            if keysym == XK_CAPS_LOCK and down:
                self._caps_lk = not self._caps_lk
                if not self._caps_lk:
                    usage |= 0xFF00
            return [build_key_event(usage, down)]
        if kind == 5:
            return [build_pointer_event(int.from_bytes(message[2:4], "big"),
                                        int.from_bytes(message[4:6], "big"), message[1])]
        return []

    def recovery(self, width: int, height: int) -> bytes:
        self._after_frame = False
        return self.opening + framebuffer_update_request(False, 0, 0, width, height)


class Ast2100Wire:

    def __init__(self, version: str) -> None:
        if version not in (GREETING_003, GREETING_055):
            raise Ast2100StreamError("ast2100_stream_unsupported", greeting=version)
        self.server = Ast2100ServerStream()
        self.client = Ast2100ClientStream(version)
        self.server.on_frame = self.client.note_frame

    def recover(self, width: int, height: int) -> bytes:
        self.server.reset()
        return self.client.recovery(width, height)
