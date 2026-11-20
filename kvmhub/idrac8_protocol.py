"""iDRAC8 HTML5 console wire framing (APCP / BEEF)."""
from __future__ import annotations

import json
import struct
from dataclasses import dataclass

APCP_MAGIC = b"APCP"
BEEF_MAGIC = b"BEEF"

APCP_REQUEST = 0x01
APCP_RESPONSE = 0x81
APCP_INFO = 0x02
APCP_INFO_RESPONSE = 0x82

CMD_SESSION_SETUP = 0x04
CMD_HEARTBEAT = 0xFF
APCP_SESSION_CLOSE = 0x04

BEEF_AUTH = 0x01
BEEF_CONTROL = 0x02
BEEF_AUTH_RESPONSE = 0x83
BEEF_VIDEO_SOCKET_AUTH = 0x00
BEEF_REQUEST = 0x03
BEEF_VIDEO_ACK = 0x04

APCP_SECONDARY_VIDEO = 0x02
APCP_SESSION_ID = 0x03


class ProtocolError(ValueError):
    pass


@dataclass(frozen=True)
class ApcpHeader:
    magic: str
    length: int
    frame_type: int
    sub: int
    command: int

    @property
    def is_response(self) -> bool:
        return bool(self.frame_type & 0x80)


@dataclass(frozen=True)
class BeefHeader:
    magic: str
    frame_type: int
    sub: int
    flag: int
    payload: bytes


@dataclass(frozen=True)
class Capabilities:
    version: str | None
    avsp_version: str | None
    video_on_secondary_socket: bool
    compression_modes: tuple[str, ...]


def _check_apcp(frame: bytes) -> int:
    if len(frame) < 12 or frame[:4] != APCP_MAGIC:
        raise ProtocolError("bad_apcp_magic")
    declared = struct.unpack(">I", frame[4:8])[0]
    if declared != len(frame):
        raise ProtocolError(f"apcp_length_mismatch:{declared}!={len(frame)}")
    return declared


def parse_apcp_header(frame: bytes) -> ApcpHeader:
    declared = _check_apcp(frame)
    return ApcpHeader(
        magic="APCP",
        length=declared,
        frame_type=frame[8],
        sub=frame[9],
        command=frame[11],
    )


def build_session_setup(*, secondary: bool = False) -> bytes:
    body = bytes.fromhex(
        "0229000000060420" + "00" * 33
        + "14" + "00" * 2 + "b4" + "00" + "1e" + "00" * 8
    )
    payload = bytes([0x04 if secondary else 0x03]) + body
    assert len(payload) == 56
    return APCP_MAGIC + struct.pack(">I", 12 + len(payload)) + bytes(
        [APCP_REQUEST, 0x00, 0x01, CMD_SESSION_SETUP]
    ) + payload


def build_apcp_control(frame_type: int, sub: int, command: int,
                       payload: bytes = b"") -> bytes:
    return APCP_MAGIC + struct.pack(">I", 12 + len(payload)) + bytes(
        [frame_type, sub, 0x00, command]
    ) + payload


def build_session_close() -> bytes:
    return build_apcp_control(APCP_SESSION_CLOSE, 0x00, 0x00, bytes(8))


def build_beef(frame_type: int, sub: int, payload: bytes) -> bytes:
    total = 8 + len(payload)
    if total > 255:
        raise ProtocolError("beef_frame_too_long")
    return BEEF_MAGIC + bytes([frame_type, sub, 0x00, total]) + payload


def build_video_channel_auth(client_random: int = 1, appliance_random: int = 0) -> bytes:
    return build_beef(BEEF_CONTROL, 0x08,
                      client_random.to_bytes(4, "little")
                      + appliance_random.to_bytes(4, "little"))


def build_video_enable() -> bytes:
    return build_beef(BEEF_CONTROL, 0x04, bytes(8))


def build_video_socket_auth(client_random: int) -> bytes:
    if not 0 <= client_random <= 0xFFFFFFFF:
        raise ProtocolError("client_random_out_of_range")
    return build_beef(BEEF_VIDEO_SOCKET_AUTH, 0x01,
                      client_random.to_bytes(4, "big") + bytes(4))


VIDEO_ENABLE_PRIMARY_FRAMES: tuple[bytes, ...] = (
    bytes.fromhex("42454546030e00100101000000000000"),
    bytes.fromhex("42454546030400100000000000000000"),
    bytes.fromhex("42454546030100100000000000000000"),
    bytes.fromhex("42454546020200100000000000000000"),
)


def build_client_info(json_payload: bytes) -> bytes:
    header_tail = bytes([APCP_INFO, 0x01]) + bytes(9) + bytes([0xF8])
    assert len(header_tail) == 12
    total = 8 + len(header_tail) + len(json_payload)
    return APCP_MAGIC + struct.pack(">I", total) + header_tail + json_payload


def client_encryption_is_none(frame: bytes) -> bool:
    _check_apcp(frame)
    try:
        obj = json.loads(frame[20:].decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return False
    return obj.get("encryption_type") == "none"


def parse_beef_header(frame: bytes) -> BeefHeader:
    if len(frame) < 4 or frame[:4] != BEEF_MAGIC:
        raise ProtocolError("bad_beef_magic")
    if len(frame) < 8:
        raise ProtocolError("beef_header_truncated")
    return BeefHeader(
        magic="BEEF",
        frame_type=frame[4],
        sub=frame[5],
        flag=frame[6],
        payload=frame[8:],
    )


def build_beef_auth_frame(token: bytes) -> bytes:
    header = BEEF_MAGIC + bytes([BEEF_AUTH, 0x02, 0x00, 0xD9])
    return header + token


def parse_capabilities(raw: bytes) -> Capabilities:
    try:
        obj = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise ProtocolError("bad_capabilities_json") from exc
    protocols = obj.get("protocols") or {}
    avsp = protocols.get("AVSP")
    if not isinstance(avsp, dict):
        raise ProtocolError("capabilities_missing_avsp")
    video_socket = avsp.get("video_socket") or {}
    video = avsp.get("video") or {}
    dvc = video.get("dvc_compression") or {}
    modes = dvc.get("compression_modes") or []
    return Capabilities(
        version=obj.get("version"),
        avsp_version=avsp.get("version"),
        video_on_secondary_socket=bool(video_socket.get("video_on_secondary_socket")),
        compression_modes=tuple(modes),
    )
