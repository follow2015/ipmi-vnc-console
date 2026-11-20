"""Tests for the iDRAC8 HTML5 console wire protocol (APCP / BEEF frames)."""
from __future__ import annotations

import base64
import json
import struct

import pytest

from kvmhub import idrac8_protocol as ip



APCP_SETUP_REQ = bytes.fromhex(
    "41504350 00000044 01 00 01 04 03022900 0006 04 20"
    + "00" * 48
)
APCP_SETUP_RESP = bytes.fromhex(
    "41504350 00000044 81 00 01 04 02290000 0604 0000"
    + "00" * 48
)


def _apcp(frame_type: int, sub: int, cmd: int, payload: bytes) -> bytes:
    header = b"APCP" + struct.pack(">I", 12 + len(payload))
    return header + bytes([frame_type, sub, 0x00, 0x00, cmd]) + payload


CAPTURED_SETUP_HEX = (
    "415043500000004401000104030229000000060420"
    + "00" * 33 + "14" + "0000" + "b4" + "00" + "1e" + "00" * 8
)


def test_apcp_setup_request_is_68_bytes_with_command_4():
    frame = ip.build_session_setup()
    assert frame[:4] == b"APCP"
    assert struct.unpack(">I", frame[4:8])[0] == len(frame) == 68
    assert frame[8] == 0x01
    assert frame[11] == 0x04


def test_apcp_setup_is_byte_identical_to_capture():
    assert ip.build_session_setup() == bytes.fromhex(CAPTURED_SETUP_HEX)


def test_client_info_header_last_byte_is_f8():
    frame = ip.build_client_info(b'{"client_type":"HTML5"}')
    assert frame[19] == 0xF8


def test_apcp_decode_reports_type_sub_and_command():
    info = ip.parse_apcp_header(APCP_SETUP_RESP)
    assert info.magic == "APCP"
    assert info.length == 68
    assert info.frame_type == 0x81
    assert info.command == 0x04
    assert info.is_response is True


def test_apcp_decode_rejects_bad_magic():
    with pytest.raises(ip.ProtocolError):
        ip.parse_apcp_header(b"XXXX" + APCP_SETUP_RESP[4:])


def test_apcp_decode_rejects_truncated_frame():
    with pytest.raises(ip.ProtocolError):
        ip.parse_apcp_header(APCP_SETUP_RESP[:6])


def test_apcp_decode_rejects_length_mismatch():
    bad = bytearray(APCP_SETUP_RESP)
    bad[7] = 0xFF
    with pytest.raises(ip.ProtocolError):
        ip.parse_apcp_header(bytes(bad))


def test_client_info_frame_carries_json_payload():
    payload = json.dumps(
        {"client_type": "HTML5", "version": "1.10.8", "encryption_type": "none"},
        separators=(",", ":"),
    ).encode()
    frame = ip.build_client_info(payload)
    assert frame[:4] == b"APCP"
    assert frame[8] == 0x02
    assert json.loads(frame[20:])["encryption_type"] == "none"
    assert struct.unpack(">I", frame[4:8])[0] == len(frame)


def test_beef_frame_header_parse():
    frame = bytes.fromhex("42454546 01 02 00 d9") + b"token-placeholder"
    info = ip.parse_beef_header(frame)
    assert info.magic == "BEEF"
    assert info.frame_type == 0x01
    assert info.sub == 0x02
    assert info.payload == b"token-placeholder"


def test_beef_build_auth_frame_shape():
    frame = ip.build_beef_auth_frame(b"16@@000000000")
    assert frame[:4] == b"BEEF"
    assert frame[4] == 0x01
    assert b"16@@000000000" in frame


def test_capabilities_json_parse_extracts_video_modes():
    caps = {
        "version": "3.89.0",
        "protocols": {
            "AVSP": {
                "video_socket": {"video_on_secondary_socket": True, "protocol_number": 4},
                "video": {
                    "dvc_compression": {"compression_modes": ["DVC-7", "DVC-15", "DVC-23"]}
                },
            }
        },
    }
    info = ip.parse_capabilities(json.dumps(caps).encode())
    assert info.avsp_version is None or info.avsp_version == "2.41"
    assert info.video_on_secondary_socket is True
    assert list(info.compression_modes) == ["DVC-7", "DVC-15", "DVC-23"]


def test_capabilities_missing_avsp_is_explicit():
    caps = {"version": "3.89.0", "protocols": {"APCP": {"protocol_number": 1}}}
    with pytest.raises(ip.ProtocolError):
        ip.parse_capabilities(json.dumps(caps).encode())


def test_encryption_type_none_is_detected(monkeypatch):
    payload = json.dumps({"client_type": "HTML5", "encryption_type": "none"}).encode()
    frame = ip.build_client_info(payload)
    assert ip.client_encryption_is_none(frame) is True
    payload2 = json.dumps({"client_type": "HTML5", "encryption_type": "aes"}).encode()
    assert ip.client_encryption_is_none(ip.build_client_info(payload2)) is False


def test_secondary_session_setup_differs_only_in_connection_type():
    primary = ip.build_session_setup()
    secondary = ip.build_session_setup(secondary=True)
    assert len(primary) == len(secondary) == 68
    assert primary[12] == 0x03 and secondary[12] == 0x04
    assert primary[:12] == secondary[:12]
    assert primary[13:] == secondary[13:]


def test_video_handshake_builders_match_captured_frames():
    assert ip.build_video_channel_auth() == bytes.fromhex(
        "42454546020800100100000000000000")
    assert ip.build_video_enable() == bytes.fromhex(
        "42454546020400100000000000000000")
    assert ip.build_video_socket_auth(0x17C2) == bytes.fromhex(
        "4245454600010010000017c200000000")
    assert ip.build_apcp_control(0x01, 0x02, 0x00, bytes(4)) == bytes.fromhex(
        "41504350000000100102000000000000")
    assert ip.build_apcp_control(0x01, 0x03, 0x00, bytes(2) + bytes([1]) + bytes(33)) == bytes.fromhex(
        "415043500000003001030000000001000000000000000000000000000000000000000000000000000000000000000000")
    assert len(ip.VIDEO_ENABLE_PRIMARY_FRAMES) == 4


def test_session_close_matches_viewer_teardown_frame():
    assert ip.build_session_close() == bytes.fromhex(
        "4150435000000014040000000000000000000000")
