"""Measured RFB 55.8 / AST2100 wire structures for the inspected X10 BMC."""
from __future__ import annotations

import re
import struct
from dataclasses import dataclass
from typing import Any

RFB_VERSION = "RFB 055.008\n"
SUPPORTED_VERSIONS = frozenset({RFB_VERSION})
RFB_VERSION_BYTES = 12

SECURITY_TYPE_INSYDE = 16
SUPPORTED_SECURITY_TYPES = frozenset({SECURITY_TYPE_INSYDE})
AUTH_CHALLENGE_BYTES = 24
AUTH_RESPONSE_BYTES = 48
SECURITY_RESULT_OK = 0
SECURITY_RESULT_BYTES = 4

ENCODING_AST2100 = 87
ENCODING_AST2100_JPEG = 88
SUPPORTED_ENCODINGS = frozenset({
    0, 1, 2, 5, 7, ENCODING_AST2100, ENCODING_AST2100_JPEG,
    -223, -224, -239, -260, -26, -247, -309,
})
SUPPORTED_MODES = frozenset({0, 1, 2, 3, 4})

FBU_HEADER_BYTES = 4
RECT_HEADER_BYTES = 20
SERVER_INIT_FIXED_BYTES = 24
SERVER_INIT_EXTENSION_BYTES = 12
MAX_DESKTOP_DIMENSION = 4096
MAX_NAME_BYTES = 4096
MAX_RECT_DATA_BYTES = 1024 * 1024

SERVER_MSG_FRAMEBUFFER_UPDATE = 0
SERVER_MSG_BELL = 2
SERVER_MSG_CUT_TEXT = 3
SERVER_MSG_CURSOR_POS = 4
SERVER_MSG_SESSION_INFO = 22
SERVER_MSG_MOUSE_MODE = 55
SERVER_MSG_CONTROL = 57
CONTROL_MESSAGE_BYTES = 256
MAX_CURSOR_DIMENSION = 128
MAX_CURSOR_PATTERN_BYTES = MAX_CURSOR_DIMENSION * MAX_CURSOR_DIMENSION * 2

CLIENT_MSG_SET_ENCODINGS = 2
CLIENT_MSG_FBU_REQUEST = 3
CLIENT_MSG_KEY_EVENT = 4
CLIENT_MSG_POINTER_EVENT = 5


class ProtocolError(ValueError):
    pass


class IncompleteFrame(ProtocolError):
    pass


@dataclass(frozen=True)
class ServerInit:
    width: int
    height: int
    bits_per_pixel: int
    depth: int
    true_color: int
    name_length: int


@dataclass(frozen=True)
class RectHeader:
    x: int
    y: int
    width: int
    height: int
    encoding: int
    mode: int
    data_length: int

    @property
    def is_ast2100(self) -> bool:
        return self.encoding in (ENCODING_AST2100, ENCODING_AST2100_JPEG)


def parse_protocol_version(data: bytes) -> str:
    if len(data) != RFB_VERSION_BYTES:
        raise ProtocolError("version must be exactly 12 bytes")
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ProtocolError("version is not ASCII") from exc
    if not re.fullmatch(r"RFB \d{3}\.\d{3}\n", text):
        raise ProtocolError("malformed RFB version string")
    if text not in SUPPORTED_VERSIONS:
        raise ProtocolError(f"unsupported RFB version {text.strip()}")
    return text.strip()


def parse_security_types(data: bytes) -> tuple[int, ...]:
    if not data:
        raise ProtocolError("security type list is empty")
    count = data[0]
    if count == 0:
        raise ProtocolError("server signalled a security failure")
    if len(data) != 1 + count:
        raise ProtocolError("truncated security type list")
    types = tuple(data[1:])
    if not SUPPORTED_SECURITY_TYPES.intersection(types):
        raise ProtocolError("no supported security type offered")
    return types


def parse_server_init(data: bytes) -> ServerInit:
    if len(data) < SERVER_INIT_FIXED_BYTES:
        raise IncompleteFrame("incomplete ServerInit")
    width, height = struct.unpack_from(">HH", data, 0)
    bits_per_pixel, depth, _big_endian, true_color = struct.unpack_from(">BBBB", data, 4)
    (name_length,) = struct.unpack_from(">I", data, 20)
    if not 1 <= width <= MAX_DESKTOP_DIMENSION or not 1 <= height <= MAX_DESKTOP_DIMENSION:
        raise ProtocolError("implausible desktop dimensions")
    if bits_per_pixel not in (8, 16, 32) or not 1 <= depth <= 32 or true_color not in (0, 1):
        raise ProtocolError("unsupported pixel format")
    if name_length > MAX_NAME_BYTES:
        raise ProtocolError("desktop name too long")
    if len(data) < SERVER_INIT_FIXED_BYTES + name_length:
        raise IncompleteFrame("incomplete desktop name")
    return ServerInit(width, height, bits_per_pixel, depth, true_color, name_length)


def parse_server_init_extension(data: bytes) -> dict[str, Any]:
    if len(data) != SERVER_INIT_EXTENSION_BYTES:
        raise ProtocolError(f"server init extension must be {SERVER_INIT_EXTENSION_BYTES} bytes")
    (session_id,) = struct.unpack_from(">I", data, 4)
    flags = tuple(data[8:12])
    if any(flag not in (0, 1) for flag in flags):
        raise ProtocolError("server init task flags are not boolean")
    return {"session_id_present": session_id != 0, "video_enable": bool(flags[0]),
            "kbms_enable": bool(flags[1]), "kick_user_enable": bool(flags[2]),
            "vm_enable": bool(flags[3]), "session_id_recorded": False}


def parse_rect_header(data: bytes) -> RectHeader:
    if len(data) != RECT_HEADER_BYTES:
        raise ProtocolError(f"rect header must be {RECT_HEADER_BYTES} bytes")
    x, y, width, height, encoding, mode, data_length = struct.unpack(">HHHHiii", data)
    if not 1 <= width <= MAX_DESKTOP_DIMENSION or not 1 <= height <= MAX_DESKTOP_DIMENSION:
        raise ProtocolError("implausible rect dimensions")
    if x > MAX_DESKTOP_DIMENSION or y > MAX_DESKTOP_DIMENSION:
        raise ProtocolError("implausible rect origin")
    if encoding not in SUPPORTED_ENCODINGS:
        raise ProtocolError(f"unsupported encoding {encoding}")
    if mode not in SUPPORTED_MODES:
        raise ProtocolError(f"unsupported AST mode {mode}")
    if not 0 <= data_length <= MAX_RECT_DATA_BYTES:
        raise ProtocolError("rect payload length out of bounds")
    return RectHeader(x, y, width, height, encoding, mode, data_length)


class RfbHandshake:

    def __init__(self) -> None:
        self._buf = bytearray()
        self.stage = "version"
        self.events: list[dict[str, Any]] = []
        self.scheme: int | None = None
        self.server_init: ServerInit | None = None
        self.server_init_raw: bytes = b""
        self.consumed = 0
        self.rects: list[RectHeader] = []

    def feed(self, data: bytes, *, stop_after: str | None = None) -> list[dict[str, Any]]:
        self._buf.extend(data)
        produced: list[dict[str, Any]] = []
        while True:
            try:
                event = self._step()
            except IncompleteFrame:
                break
            if event is None:
                break
            produced.append(event)
            self.events.append(event)
            if stop_after is not None and event["stage"] == stop_after:
                break
        return produced

    def _need(self, size: int) -> bytes:
        if len(self._buf) < size:
            raise IncompleteFrame(f"need {size} bytes")
        return bytes(self._buf[:size])

    def _consume(self, size: int) -> bytes:
        chunk = self._need(size)
        del self._buf[:size]
        self.consumed += size
        return chunk

    def _step(self) -> dict[str, Any] | None:
        if self.stage == "version":
            version = parse_protocol_version(self._consume(RFB_VERSION_BYTES))
            self.stage = "security"
            return {"stage": "ProtocolVersion", "version": version}

        if self.stage == "security":
            count = self._need(1)[0]
            types = parse_security_types(self._consume(1 + count))
            self.scheme = SECURITY_TYPE_INSYDE
            self.stage = "auth"
            return {"stage": "Security", "types": types, "scheme": self.scheme}

        if self.stage == "auth":
            self._consume(AUTH_CHALLENGE_BYTES)
            self.stage = "security_result"
            return {"stage": "Authentication", "scheme": self.scheme,
                    "challenge_bytes": AUTH_CHALLENGE_BYTES, "value_recorded": False}

        if self.stage == "security_result":
            (code,) = struct.unpack(">I", self._consume(SECURITY_RESULT_BYTES))
            if code != SECURITY_RESULT_OK:
                raise ProtocolError(f"SecurityResult failed with code {code}")
            self.stage = "server_init"
            return {"stage": "SecurityResult", "ok": True}

        if self.stage == "server_init":
            if len(self._buf) < SERVER_INIT_FIXED_BYTES:
                raise IncompleteFrame("incomplete ServerInit header")
            (name_length,) = struct.unpack_from(">I", self._buf, 20)
            if name_length > MAX_NAME_BYTES:
                raise ProtocolError("desktop name too long")
            total = SERVER_INIT_FIXED_BYTES + name_length + SERVER_INIT_EXTENSION_BYTES
            if len(self._buf) < total:
                raise IncompleteFrame("incomplete ServerInit extension")
            raw = self._consume(total)
            init = parse_server_init(raw[:SERVER_INIT_FIXED_BYTES + name_length])
            extension = parse_server_init_extension(raw[-SERVER_INIT_EXTENSION_BYTES:])
            self.server_init = init
            self.server_init_raw = raw
            self.stage = "normal"
            return {"stage": "ServerInit", "width": init.width, "height": init.height,
                    "bits_per_pixel": init.bits_per_pixel, "depth": init.depth,
                    "true_color": init.true_color, "name_length": init.name_length,
                    "name_recorded": False, "extension_bytes": SERVER_INIT_EXTENSION_BYTES,
                    "consumed": self.consumed, **extension}

        if not self._buf:
            return None
        msg_type = self._buf[0]
        if msg_type == SERVER_MSG_FRAMEBUFFER_UPDATE:
            return self._framebuffer_update()
        if msg_type == SERVER_MSG_BELL:
            self._consume(1)
            return {"stage": "Bell", "bytes": 1}
        if msg_type == SERVER_MSG_CUT_TEXT:
            length = struct.unpack_from(">I", self._need(8), 4)[0]
            if length > MAX_NAME_BYTES:
                raise ProtocolError("cut text too long")
            self._consume(8 + length)
            return {"stage": "ServerCutText", "bytes": 8 + length, "text_recorded": False}
        if msg_type == SERVER_MSG_CURSOR_POS:
            return self._cursor_position()
        if msg_type == SERVER_MSG_SESSION_INFO:
            self._consume(2)
            return {"stage": "SessionInfo", "bytes": 2, "value_recorded": False}
        if msg_type == SERVER_MSG_MOUSE_MODE:
            self._consume(4)
            return {"stage": "MouseMode", "bytes": 4, "value_recorded": False}
        if msg_type == SERVER_MSG_CONTROL:
            self._consume(1 + 4 + 4 + CONTROL_MESSAGE_BYTES)
            return {"stage": "Control", "bytes": 1 + 8 + CONTROL_MESSAGE_BYTES,
                    "message_recorded": False}
        raise ProtocolError(f"unsupported server message type {msg_type}")

    def _cursor_position(self) -> dict[str, Any]:
        if len(self._buf) < 1 + 20:
            raise IncompleteFrame("incomplete cursor position")
        x, y, width, height, valid = struct.unpack_from(">IIIII", self._buf, 1)
        if not 0 <= width <= MAX_CURSOR_DIMENSION or not 0 <= height <= MAX_CURSOR_DIMENSION:
            raise ProtocolError("implausible cursor dimensions")
        if valid not in (0, 1):
            raise ProtocolError("implausible cursor validity flag")
        pattern = width * height * 2
        if pattern > MAX_CURSOR_PATTERN_BYTES:
            raise ProtocolError("cursor pattern too large")
        total = 1 + 20 + (4 + pattern if valid == 1 else 0)
        if len(self._buf) < total:
            raise IncompleteFrame("incomplete cursor pattern")
        self._consume(total)
        return {"stage": "CursorPos", "bytes": total, "pattern_bytes": pattern if valid else 0,
                "pattern_recorded": False}

    def _framebuffer_update(self) -> dict[str, Any]:
        header = self._need(FBU_HEADER_BYTES)
        (rect_count,) = struct.unpack_from(">H", header, 2)
        if rect_count == 0 or rect_count > 64:
            raise ProtocolError("implausible rect count")
        needed = FBU_HEADER_BYTES
        headers: list[RectHeader] = []
        for _ in range(rect_count):
            if len(self._buf) < needed + RECT_HEADER_BYTES:
                raise IncompleteFrame("incomplete rect header")
            rect = parse_rect_header(bytes(self._buf[needed:needed + RECT_HEADER_BYTES]))
            needed += RECT_HEADER_BYTES + rect.data_length
            headers.append(rect)
            if len(headers) > 64:
                raise ProtocolError("too many rects")
        self._consume(needed)
        self.rects.extend(headers[:8])
        return {"stage": "FramebufferUpdate", "rects": rect_count,
                "headers": tuple(headers), "payload_bytes": sum(r.data_length for r in headers),
                "payload_recorded": False}


def client_protocol_version() -> bytes:
    return RFB_VERSION.encode("ascii")


def client_security_scheme(scheme: int = SECURITY_TYPE_INSYDE) -> bytes:
    if scheme not in SUPPORTED_SECURITY_TYPES:
        raise ProtocolError("unsupported security scheme")
    return bytes([scheme])


def client_auth_response(opaque: bytes) -> bytes:
    if len(opaque) != AUTH_RESPONSE_BYTES:
        raise ProtocolError(f"scheme-16 response must be {AUTH_RESPONSE_BYTES} bytes")
    return bytes(opaque)


def client_init(shared: bool = True) -> bytes:
    return bytes([1 if shared else 0])


def pointer_event(x: int, y: int, mask: int = 0) -> bytes:
    if not 0 <= x <= 0xFFFF or not 0 <= y <= 0xFFFF or not 0 <= mask <= 0xFF:
        raise ProtocolError("pointer event fields out of range")
    return struct.pack(">BBHH", CLIENT_MSG_POINTER_EVENT, mask, x, y)


def key_event(keysym: int, down: bool) -> bytes:
    if not 0 <= keysym <= 0xFFFFFFFF or down not in (True, False):
        raise ProtocolError("key event fields out of range")
    return struct.pack(">BBHI", CLIENT_MSG_KEY_EVENT, int(down), 0, keysym)


def framebuffer_update_request(incremental: bool, x: int, y: int,
                               width: int, height: int) -> bytes:
    for value in (x, y, width, height):
        if not 0 <= value <= 0xFFFF:
            raise ProtocolError("framebuffer update fields out of range")
    return struct.pack(">BBHHHH", CLIENT_MSG_FBU_REQUEST, int(incremental), x, y, width, height)
