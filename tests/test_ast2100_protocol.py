"""Pure RFB 55.8 / AST2100 protocol layer measured on the real BMC."""
import ast
import inspect
import json
import struct
from pathlib import Path

import pytest

from kvmhub import ast2100_protocol as proto
from kvmhub.adapter_contract import ENABLED_ADAPTER_IDS, AdapterUnavailable
from kvmhub.adapters import SupermicroX10IKVMAdapter
from kvmhub.adapters import supermicro_x10 as adapter_module

EVIDENCE_FILE = (Path(__file__).resolve().parents[1]
                 / "docs/implementation/evidence/real-bmc-kvm-phase2-20261111.json")


def rect_bytes(x=0, y=0, width=1024, height=768, encoding=proto.ENCODING_AST2100,
               mode=0, data_length=15940):
    return struct.pack(">HHHHiii", x, y, width, height, encoding, mode, data_length)


def server_init_extension_bytes(session_id=0x5E5510, flags=(1, 1, 1, 1)):
    return b"\x00" * 4 + struct.pack(">I", session_id) + bytes(flags)


def server_init_bytes(width=480, height=640, bpp=32, depth=24, true_color=1, name=b"X" * 16,
                      extension=None):
    fixed = (struct.pack(">HHBBBB", width, height, bpp, depth, 0, true_color)
             + struct.pack(">HHHBBB", 255, 255, 255, 16, 8, 0)
             + b"\x00" * 3 + struct.pack(">I", len(name)))
    return fixed + name + (server_init_extension_bytes() if extension is None else extension)


def handshake_stream():
    return (proto.client_protocol_version()
            + bytes([1, proto.SECURITY_TYPE_INSYDE])
            + b"\x00" * proto.AUTH_CHALLENGE_BYTES
            + struct.pack(">I", proto.SECURITY_RESULT_OK)
            + server_init_bytes())


def fbu_stream(rect_count=1, data_length=15940):
    body = b"\x00" * data_length
    return (struct.pack(">BBH", 0, 0, rect_count)
            + rect_bytes(data_length=data_length) * rect_count + body * rect_count)


def stages(events):
    return [event["stage"] for event in events]



def test_constants_match_the_phase2_evidence_record():
    data = json.loads(EVIDENCE_FILE.read_text(encoding="utf-8"))
    assert data["rfb"]["protocol_version"].startswith(proto.RFB_VERSION.strip())
    assert data["rfb"]["security_types"] == [proto.SECURITY_TYPE_INSYDE]
    assert data["rfb"]["challenge_bytes"] == proto.AUTH_CHALLENGE_BYTES
    assert data["rfb"]["client_auth_response_bytes"] == proto.AUTH_RESPONSE_BYTES
    assert data["rfb"]["security_result"] == proto.SECURITY_RESULT_OK
    assert data["framebuffer"]["observed_rect"]["encoding"] == proto.ENCODING_AST2100
    assert data["framebuffer"]["rect_header_bytes"] == proto.RECT_HEADER_BYTES
    assert data["framebuffer"]["observed_rect"]["width"] == 1024
    assert data["framebuffer"]["observed_rect"]["height"] == 768
    assert data["websocket"]["path"] == "/"
    assert data["websocket"]["subprotocol_selected"] == ""
    assert data["websocket"]["handshake_status"] == 101
    assert data["adapter_decision"]["gate_status"] == "unverified"


def test_evidence_record_stays_desensitised():
    data = json.loads(EVIDENCE_FILE.read_text(encoding="utf-8"))
    assert data["credentials"]["value_recorded"] is False
    assert data["safety"]["raw_video_bytes_written"] is False
    assert data["safety"]["raw_websocket_payloads_written"] is False
    assert data["safety"]["ticket_value_recorded"] is False
    assert data["safety"]["cookie_values_recorded"] is False
    text = EVIDENCE_FILE.read_text(encoding="utf-8")
    for forbidden in ("ADM" + "IN", "Sec-WebSocket-Key\": \"", "pwd="):
        assert forbidden not in text


def test_protocol_layer_imports_nothing_that_can_open_a_socket():
    tree = ast.parse(inspect.getsource(proto))
    modules = {node.module.split(".")[0] for node in ast.walk(tree)
               if isinstance(node, ast.ImportFrom) and node.module}
    modules |= {alias.name.split(".")[0] for node in ast.walk(tree)
                if isinstance(node, ast.Import) for alias in node.names}
    assert modules <= {"__future__", "re", "struct", "dataclasses", "typing"}



def test_parse_protocol_version_accepts_measured_greeting():
    assert proto.parse_protocol_version(proto.client_protocol_version()) == "RFB 055.008"


@pytest.mark.parametrize("raw", [
    b"RFB 055.008",
    b"RFB 055.008\n\x00",
    b"RFB 003.008\n",
    b"XXXX 055.008\n",
    b"\xff" * 12,
])
def test_parse_protocol_version_rejects_anything_else(raw):
    with pytest.raises(proto.ProtocolError):
        proto.parse_protocol_version(raw)


def test_parse_security_types_requires_scheme_16():
    assert proto.parse_security_types(bytes([1, 16])) == (16,)
    assert proto.parse_security_types(bytes([2, 1, 16])) == (1, 16)
    with pytest.raises(proto.ProtocolError):
        proto.parse_security_types(b"")
    with pytest.raises(proto.ProtocolError, match="security failure"):
        proto.parse_security_types(b"\x00")
    with pytest.raises(proto.ProtocolError, match="truncated"):
        proto.parse_security_types(b"\x02\x10")
    with pytest.raises(proto.ProtocolError, match="no supported"):
        proto.parse_security_types(b"\x01\x02")


def test_parse_server_init_matches_the_wire_value():
    init = proto.parse_server_init(server_init_bytes())
    assert (init.width, init.height) == (480, 640)
    assert (init.bits_per_pixel, init.depth, init.true_color) == (32, 24, 1)
    assert init.name_length == 16


def test_parse_server_init_raises_incomplete_for_partial_data():
    full = server_init_bytes()
    for cut in (0, 8, 23, 24, 30):
        with pytest.raises(proto.IncompleteFrame):
            proto.parse_server_init(full[:cut])


@pytest.mark.parametrize("kwargs", [
    {"width": 0}, {"height": 5000}, {"bpp": 7}, {"depth": 0}, {"true_color": 2},
])
def test_parse_server_init_rejects_implausible_pixel_format(kwargs):
    with pytest.raises(proto.ProtocolError):
        proto.parse_server_init(server_init_bytes(**kwargs))


def test_server_init_extension_matches_the_measured_layout():
    extension = proto.parse_server_init_extension(server_init_extension_bytes())
    assert extension["session_id_present"] is True
    assert extension["session_id_recorded"] is False
    assert (extension["video_enable"], extension["kbms_enable"]) == (True, True)
    assert proto.parse_server_init_extension(server_init_extension_bytes(session_id=0))[
        "session_id_present"] is False
    with pytest.raises(proto.ProtocolError):
        proto.parse_server_init_extension(server_init_extension_bytes()[:-1])
    with pytest.raises(proto.ProtocolError):
        proto.parse_server_init_extension(server_init_extension_bytes(flags=(1, 2, 1, 1)))


def test_handshake_waits_for_the_full_extension():
    hs = proto.RfbHandshake()
    stream = handshake_stream()
    hs.feed(stream[:-1])
    assert hs.stage == "server_init"
    events = hs.feed(stream[-1:])
    assert stages(events) == ["ServerInit"]
    assert events[0]["extension_bytes"] == proto.SERVER_INIT_EXTENSION_BYTES
    assert hs.stage == "normal"


def test_parse_rect_header_matches_the_measured_ast2100_rect():
    rect = proto.parse_rect_header(rect_bytes())
    assert (rect.x, rect.y, rect.width, rect.height) == (0, 0, 1024, 768)
    assert rect.encoding == proto.ENCODING_AST2100
    assert rect.mode == 0
    assert rect.data_length == 15940
    assert rect.is_ast2100 is True


def test_parse_rect_header_accepts_jpeg_variant_and_rejects_bad_fields():
    jpeg = proto.parse_rect_header(rect_bytes(encoding=proto.ENCODING_AST2100_JPEG))
    assert jpeg.is_ast2100 is True
    raw = proto.parse_rect_header(rect_bytes(encoding=0))
    assert raw.is_ast2100 is False
    bad = [
        rect_bytes(encoding=999), rect_bytes(mode=9), rect_bytes(data_length=-1),
        rect_bytes(data_length=proto.MAX_RECT_DATA_BYTES + 1),
        rect_bytes(width=0), rect_bytes(height=9000), rect_bytes(x=9000),
    ]
    for value in bad:
        with pytest.raises(proto.ProtocolError):
            proto.parse_rect_header(value)
    with pytest.raises(proto.ProtocolError):
        proto.parse_rect_header(rect_bytes()[:-1])



def test_handshake_parses_the_complete_measured_exchange():
    hs = proto.RfbHandshake()
    events = hs.feed(handshake_stream())
    assert stages(events) == ["ProtocolVersion", "Security", "Authentication",
                              "SecurityResult", "ServerInit"]
    assert hs.stage == "normal"
    assert hs.scheme == 16
    assert hs.server_init.width == 480
    assert events[2]["challenge_bytes"] == 24 and events[2]["value_recorded"] is False
    assert events[4]["name_recorded"] is False


def test_handshake_survives_byte_by_byte_fragmentation():
    hs = proto.RfbHandshake()
    seen = []
    for byte in handshake_stream() + fbu_stream(data_length=24):
        seen.extend(hs.feed(bytes([byte])))
    assert "ProtocolVersion" in stages(seen) and "ServerInit" in stages(seen)
    assert "FramebufferUpdate" in stages(seen)
    assert hs.stage == "normal"
    assert len(hs.rects) == 1
    assert hs.rects[0].data_length == 24


def test_handshake_rejects_failed_security_result():
    hs = proto.RfbHandshake()
    stream = handshake_stream().replace(struct.pack(">I", 0), struct.pack(">I", 1))
    with pytest.raises(proto.ProtocolError, match="SecurityResult"):
        hs.feed(stream)


def test_handshake_fails_closed_on_unknown_server_message():
    hs = proto.RfbHandshake()
    hs.feed(handshake_stream())
    with pytest.raises(proto.ProtocolError, match="unsupported server message"):
        hs.feed(b"\x63\x00\x00")


def test_handshake_waits_for_a_complete_control_message():
    hs = proto.RfbHandshake()
    hs.feed(handshake_stream())
    control = struct.pack(">BII", 57, 1, 1) + b"x" * 256
    assert hs.feed(control[:-1]) == []
    assert stages(hs.feed(control[-1:])) == ["Control"]


def test_handshake_parses_framebuffer_update_without_retaining_payload():
    hs = proto.RfbHandshake()
    hs.feed(handshake_stream())
    events = hs.feed(fbu_stream(data_length=15940))
    assert len(events) == 1 and events[0]["stage"] == "FramebufferUpdate"
    assert events[0]["rects"] == 1 and events[0]["payload_bytes"] == 15940
    assert events[0]["payload_recorded"] is False
    assert len(events[0]["headers"]) == 1
    assert hs.rects[0].encoding == proto.ENCODING_AST2100


def test_handshake_handles_bell_and_cut_text():
    hs = proto.RfbHandshake()
    hs.feed(handshake_stream())
    cut = struct.pack(">B", 3) + b"\x00" * 3 + struct.pack(">I", 4) + b"text"
    events = hs.feed(b"\x02" + cut)
    assert stages(events) == ["Bell", "ServerCutText"]
    assert events[1]["text_recorded"] is False


def test_handshake_handles_the_measured_vendor_messages():
    hs = proto.RfbHandshake()
    hs.feed(handshake_stream())
    control = struct.pack(">BII", 57, 1, 1) + b"x" * 256
    assert len(control) == 265
    events = hs.feed(control)
    assert stages(events) == ["Control"]
    assert events[0]["bytes"] == 265 and events[0]["message_recorded"] is False
    assert stages(hs.feed(b"\x37\x01\x02\x03")) == ["MouseMode"]
    assert stages(hs.feed(b"\x16\x00")) == ["SessionInfo"]


def test_handshake_handles_cursor_position_with_optional_pattern():
    hs = proto.RfbHandshake()
    hs.feed(handshake_stream())
    empty = b"\x04" + struct.pack(">IIIII", 10, 20, 0, 0, 0)
    events = hs.feed(empty)
    assert stages(events) == ["CursorPos"] and events[0]["pattern_bytes"] == 0
    patterned = (b"\x04" + struct.pack(">IIIII", 1, 2, 4, 4, 1) + struct.pack(">I", 0)
                 + b"\x00" * (4 * 4 * 2))
    events = hs.feed(patterned)
    assert events[0]["bytes"] == len(patterned) and events[0]["pattern_bytes"] == 32


def test_handshake_rejects_malformed_cursor_position():
    hs = proto.RfbHandshake()
    hs.feed(handshake_stream())
    for payload in (b"\x04" + struct.pack(">IIIII", 0, 0, 500, 1, 0),
                    b"\x04" + struct.pack(">IIIII", 0, 0, 4, 4, 2)):
        with pytest.raises(proto.ProtocolError):
            hs.feed(payload)


@pytest.mark.parametrize("count", [0, 65])
def test_handshake_rejects_implausible_rect_counts(count):
    hs = proto.RfbHandshake()
    hs.feed(handshake_stream())
    with pytest.raises(proto.ProtocolError, match="rect count"):
        hs.feed(struct.pack(">BBH", 0, 0, count))



def test_client_messages_have_the_measured_wire_lengths():
    assert len(proto.client_protocol_version()) == 12
    assert proto.client_security_scheme() == b"\x10"
    assert proto.client_init() == b"\x01"
    pointer = proto.pointer_event(210, 160, 0)
    key = proto.key_event(0xFFE1, True)
    request = proto.framebuffer_update_request(True, 0, 0, 1024, 768)
    assert (len(pointer), len(key), len(request)) == (6, 8, 10)
    assert struct.unpack(">BBHH", pointer) == (5, 0, 210, 160)
    assert struct.unpack(">BBHI", key) == (4, 1, 0, 0xFFE1)
    assert struct.unpack(">BBHHHH", request) == (3, 1, 0, 0, 1024, 768)


def test_client_auth_response_is_opaque_and_length_checked():
    opaque = bytes(range(48))
    assert proto.client_auth_response(opaque) == opaque
    with pytest.raises(proto.ProtocolError):
        proto.client_auth_response(b"\x00" * 16)


@pytest.mark.parametrize("call", [
    lambda: proto.client_security_scheme(2),
    lambda: proto.pointer_event(-1, 0),
    lambda: proto.pointer_event(70000, 0),
    lambda: proto.key_event(-1, True),
    lambda: proto.key_event(0xFFE1, "yes"),
    lambda: proto.framebuffer_update_request(True, -1, 0, 1, 1),
])
def test_client_message_fields_are_bounded(call):
    with pytest.raises(proto.ProtocolError):
        call()



def test_adapter_evidence_tracks_protocol_constants():
    joined = "\n".join(adapter_module.EVIDENCE)
    assert proto.RFB_VERSION.strip() in joined
    assert f"{proto.RECT_HEADER_BYTES}-byte vendor rect header" in joined
    assert f"encoding {proto.ENCODING_AST2100}" in joined
    spec = SupermicroX10IKVMAdapter().console_spec()
    assert spec.max_frame_bytes == proto.MAX_RECT_DATA_BYTES
    assert "AST2100" in spec.codec
    assert "055.008" in spec.codec
    assert "logout.cgi" in spec.close_rule and "cleanup=ok" in spec.close_rule


def test_adapter_no_longer_claims_the_handshake_was_never_done():
    unconfirmed = "\n".join(adapter_module.UNCONFIRMED)
    assert "no WebSocket handshake" not in unconfirmed
    assert "AST2100 bitstream decoding is not implemented" in unconfirmed
    assert "not independently verified" in unconfirmed
    assert "only mock-v1" in unconfirmed


def test_data_plane_and_exchange_gate_remain_closed():
    assert ENABLED_ADAPTER_IDS == frozenset({"mock-v1"})
    instance = SupermicroX10IKVMAdapter()
    for method in (instance.authenticate, instance.open_console,
                   instance.keepalive, instance.logout):
        with pytest.raises(AdapterUnavailable, match="adapter_capability"):
            method()
