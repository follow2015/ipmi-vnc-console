"""The AST2100 vendor wire, as the fixed client sees it through the gateway."""
import asyncio
import struct

import aiohttp
import pytest

from kvmhub import huawei_kvm_input
from kvmhub.ast2100_keymap import AST2100_KEYMAP
from kvmhub.ast2100_wire import (
    CURSOR_TAG,
    ENCODING_AST2100,
    GREETING_003,
    GREETING_055,
    MOUSE_SYNC,
    PSEUDO_DESKTOP_SIZE,
    Ast2100ClientStream,
    Ast2100ServerStream,
    Ast2100StreamError,
    Ast2100Wire,
    VENDOR_ONLY_MESSAGES,
    standard_server_init,
)
from kvmhub.adapters.passthrough import FIXED_CLIENT_VERSION, PassthroughAdapter
from kvmhub.common import PASSTHROUGH_ADAPTER_ID, Problem
from kvmhub.insyde_messages import (
    InsydeKeyEvent, InsydePointerEvent, build_key_event, build_pointer_event,
    parse_key_event, parse_pointer_event)
from kvmhub.passthrough import ALLOWED_CLIENT_MESSAGES, BrowserHandshake, RfbPassthroughSession
from kvmhub.rfb_server import RFB_PIXEL_FORMAT_32BPP
from kvmhub.recovery import RecoveryPolicy

MODE_420 = 420
CURSOR = 4
FRAMEBUFFER_UPDATE = 0


def vendor_frame(width, height, data, mode=MODE_420, x=0, y=0, rects=1, pad=0):
    return (struct.pack(">BBH", FRAMEBUFFER_UPDATE, pad, rects)
            + struct.pack(">HHHHiII", x, y, width, height, ENCODING_AST2100, mode, len(data))
            + data)


def vendor_cursor(x, y, width, height, pattern, valid=1):
    head = struct.pack(">B5I", CURSOR, x, y, width, height, valid)
    return head + struct.pack(">I", 7) + pattern if valid == 1 else head


def standard_fbu(*rects):
    return struct.pack(">BBH", 0, 0, len(rects)) + b"".join(rects)


def desktop_size(width, height):
    return struct.pack(">HHHHi", 0, 0, width, height, PSEUDO_DESKTOP_SIZE)


def ast_rect(width, height, mode, data, x=0, y=0):
    return struct.pack(">HHHHi", x, y, width, height, ENCODING_AST2100) + struct.pack(">II", mode, len(data)) + data


def key_event(keysym, down):
    return struct.pack(">BBHI", 4, int(down), 0, keysym)


def pointer_event(mask, x, y):
    return struct.pack(">BBHH", 5, mask, x, y)


def fbu_request(incremental=1, x=0, y=0, w=1024, h=768):
    return struct.pack(">BBHHHH", 3, incremental, x, y, w, h)



def test_frame_is_reframed_with_a_desktop_size_rect_and_its_payload_verbatim():
    stream = Ast2100ServerStream()
    payload = bytes(range(256)) * 3
    out = stream.feed(vendor_frame(1024, 768, payload))
    assert out == standard_fbu(desktop_size(1024, 768), ast_rect(1024, 768, MODE_420, payload))
    out = stream.feed(vendor_frame(1024, 768, b"\x11" * 5))
    assert out == standard_fbu(ast_rect(1024, 768, MODE_420, b"\x11" * 5))
    assert stream.frames == 2 and stream.encodings == {87: 2}


def test_frame_split_at_every_byte_boundary_is_reassembled():
    raw = (vendor_frame(640, 480, b"A" * 40) + vendor_frame(640, 480, b"B" * 7)
           + bytes([2]) + vendor_frame(800, 600, b"C" * 9))
    for cut in range(len(raw) + 1):
        stream = Ast2100ServerStream()
        out = stream.feed(raw[:cut]) + stream.feed(raw[cut:])
        assert out == (standard_fbu(desktop_size(640, 480), ast_rect(640, 480, MODE_420, b"A" * 40))
                       + standard_fbu(ast_rect(640, 480, MODE_420, b"B" * 7))
                       + b"\x02"
                       + standard_fbu(desktop_size(800, 600), ast_rect(800, 600, MODE_420, b"C" * 9)))


def test_frame_arriving_in_three_byte_pieces_yields_the_same_bytes():
    raw = vendor_frame(64, 64, bytes(range(100))) + b"\x16\x00" + b"\x37\x01\x02\x03"
    whole = Ast2100ServerStream().feed(raw)
    stream = Ast2100ServerStream()
    pieces = b"".join(stream.feed(raw[i:i + 3]) for i in range(0, len(raw), 3))
    assert pieces == whole


def test_oversized_geometry_falls_back_like_the_vendor_client():
    stream = Ast2100ServerStream()
    out = stream.feed(vendor_frame(64896, 65056, b""))
    assert out == standard_fbu(desktop_size(640, 480), ast_rect(640, 480, MODE_420, b""))
    stream.feed(vendor_frame(1024, 768, b"\x00" * 4))
    out = stream.feed(vendor_frame(65535, 65535, b""))
    assert out == standard_fbu(ast_rect(1024, 768, MODE_420, b""))


def test_zero_length_frame_is_forwarded_so_the_client_can_clear_the_screen():
    stream = Ast2100ServerStream()
    stream.feed(vendor_frame(1024, 768, b"\x01"))
    assert stream.feed(vendor_frame(1024, 768, b"")) == standard_fbu(ast_rect(1024, 768, MODE_420, b""))


@pytest.mark.parametrize("kind,length", sorted(VENDOR_ONLY_MESSAGES.items()))
def test_private_notification_messages_are_dropped_by_their_measured_length(kind, length):
    body = bytes([kind]) + bytes((index * 7) & 0xFF for index in range(length - 1))
    stream = Ast2100ServerStream()
    assert stream.feed(body) == b""
    out = stream.feed(vendor_frame(64, 64, b"Z"))
    assert out == standard_fbu(desktop_size(64, 64), ast_rect(64, 64, MODE_420, b"Z"))
    assert stream.message_types == {kind: 1, 0: 1}


def test_cursor_becomes_a_tagged_rect_with_position_and_rgba():
    pattern = bytes([0x0F, 0x00, 0x00, 0x0A])
    stream = Ast2100ServerStream()
    out = stream.feed(vendor_cursor(300, 40, 2, 1, pattern))
    assert out == standard_fbu(
        struct.pack(">HHHHi", 0, 0, 2, 1, CURSOR_TAG) + struct.pack(">HH", 300, 40)
        + bytes([0x00, 0x00, 0xF0, 0xFF,
                 0xA0, 0x00, 0x00, 0xFF]))
    assert CURSOR_TAG == -0x41535443 == -1095980099 and -2 ** 31 <= CURSOR_TAG < 0


def test_cursor_split_across_feeds_and_an_invalid_one_is_ignored():
    raw = vendor_cursor(5, 6, 2, 2, bytes(8)) + vendor_cursor(1, 1, 2, 2, b"", valid=0) + b"\x02"
    stream = Ast2100ServerStream()
    out = b""
    for byte in raw:
        out += stream.feed(bytes([byte]))
    assert len(out) == 4 + 12 + 4 + 2 * 2 * 4 + 1 and out.endswith(b"\x02")
    assert stream.message_types == {4: 2, 2: 1}


def test_cursor_outside_any_sane_shape_is_refused_not_guessed():
    for width, height in ((0, 4), (4, 0), (129, 4)):
        with pytest.raises(Ast2100StreamError) as exc:
            Ast2100ServerStream().feed(vendor_cursor(0, 0, width, height, b""))
        assert exc.value.code == "ast2100_stream_unsupported"
        assert exc.value.shape == {"kind": CURSOR, "width": width, "height": height}


def test_a_cursor_with_an_unmeasured_validity_flag_is_refused():
    with pytest.raises(Ast2100StreamError) as exc:
        Ast2100ServerStream().feed(vendor_cursor(1, 1, 2, 2, bytes(8), valid=2))
    assert exc.value.code == "ast2100_stream_desync"
    assert exc.value.shape == {"kind": CURSOR, "valid": 2}


def test_bell_and_server_cut_text_pass_through_as_standard():
    text = struct.pack(">B3xI", 3, 5) + b"hello"
    out = Ast2100ServerStream().feed(b"\x02" + text)
    assert out == b"\x02" + text


@pytest.mark.parametrize("raw,code,shape", [
    (b"\x63", "ast2100_stream_unsupported", {"kind": 99}),
    (b"\x00\x01\x00\x01", "ast2100_stream_desync", {"kind": 0, "rects": 1}),
    (b"\x00\x00\x00\x00", "ast2100_stream_desync", {"kind": 0, "rects": 0}),
    (b"\x00\x00\x00\x01" + struct.pack(">HHHHiII", 0, 0, 4, 4, 88, 0, 4) + b"\x00" * 4,
     "ast2100_stream_unsupported", {"kind": 0, "encoding": 88}),
    (b"\x00\x00\x00\x01" + struct.pack(">HHHHiII", 0, 0, 4, 4, 87, 0, 1 << 30),
     "ast2100_stream_desync", {"kind": 0, "length": 1 << 30}),
])
def test_anything_outside_the_measured_profile_is_a_named_error(raw, code, shape):
    with pytest.raises(Ast2100StreamError) as exc:
        Ast2100ServerStream().feed(raw)
    assert (exc.value.code, exc.value.shape) == (code, shape)


def test_on_frame_fires_once_per_complete_frame():
    seen = []
    stream = Ast2100ServerStream()
    stream.on_frame = lambda: seen.append(1)
    stream.feed(vendor_frame(8, 8, b"\x00"))
    stream.feed(bytes([22, 0]))
    stream.feed(vendor_frame(8, 8, b"")[:10])
    assert len(seen) == 1



def test_pixel_format_and_encodings_are_dropped_not_replaced():
    client = Ast2100ClientStream(GREETING_003)
    assert client.translate(bytes(20)) == []
    assert client.translate(struct.pack(">BBH", 2, 0, 1) + struct.pack(">i", 0)) == []


def test_003_firmware_gets_a_cursor_request_only_after_a_frame():
    client = Ast2100ClientStream(GREETING_003)
    assert client.opening == b""
    assert client.translate(fbu_request(0)) == [fbu_request(0)]
    client.note_frame()
    assert client.translate(fbu_request()) == [fbu_request(), b"\x19"]
    assert client.translate(fbu_request()) == [fbu_request()]


def test_055_firmware_gets_one_mouse_sync_up_front_and_no_cursor_request():
    client = Ast2100ClientStream(GREETING_055)
    assert client.opening == MOUSE_SYNC == bytes([7, 0x07, 0xC0])
    client.note_frame()
    assert client.translate(fbu_request()) == [fbu_request()]


def test_key_events_carry_the_measured_hid_usage_in_the_18_byte_layout():
    client = Ast2100ClientStream(GREETING_003)
    (down,) = client.translate(key_event(0x61, True))
    (up,) = client.translate(key_event(0xFFE3, False))
    assert parse_key_event(down) == InsydeKeyEvent(down=True, key=0x04)
    assert parse_key_event(up) == InsydeKeyEvent(down=False, key=0xE0)
    assert len(down) == len(up) == 18


def test_caps_lock_toggles_like_the_vendor_client():
    client = Ast2100ClientStream(GREETING_003)
    presses = [client.translate(key_event(0xFFE5, True))[0] for _ in range(4)]
    assert [parse_key_event(press).key for press in presses] == [0x39, 0xFF39, 0x39, 0xFF39]
    assert parse_key_event(client.translate(key_event(0xFFE5, False))[0]).key == 0x39


def test_a_keysym_outside_the_table_sends_nothing_and_is_counted():
    client = Ast2100ClientStream(GREETING_003)
    assert client.translate(key_event(0x0100_0000, True)) == []
    assert client.dropped_keys == 1


def test_pointer_event_keeps_mask_and_position():
    (event,) = Ast2100ClientStream(GREETING_055).translate(pointer_event(5, 300, 200))
    assert parse_pointer_event(event) == InsydePointerEvent(mask=5, x=300, y=200)


def test_recovery_is_the_opening_plus_one_full_request():
    client = Ast2100ClientStream(GREETING_055)
    client.note_frame()
    assert client.recovery(640, 480) == MOUSE_SYNC + fbu_request(0, 0, 0, 640, 480)
    assert client.translate(fbu_request()) == [fbu_request()]


def test_only_the_two_measured_greetings_have_a_profile():
    with pytest.raises(Ast2100StreamError) as exc:
        Ast2100Wire("RFB 004.001")
    assert exc.value.code == "ast2100_stream_unsupported" and exc.value.shape == {"greeting": "RFB 004.001"}


def test_wire_ties_the_frame_cue_to_the_client_stream():
    wire = Ast2100Wire(GREETING_003)
    wire.server.feed(vendor_frame(8, 8, b"\x00"))
    assert wire.client.translate(fbu_request()) == [fbu_request(), b"\x19"]
    wire.recover(8, 8)
    assert wire.client.translate(fbu_request()) == [fbu_request()]


def test_platform_hid_map_never_disagrees_with_this_one():
    checked = 0
    for keysym in range(0x20, 0x7F):
        found = huawei_kvm_input.keysym_to_usage(keysym)
        if found:
            assert AST2100_KEYMAP[keysym] == found[0]
            checked += 1
    assert checked and AST2100_KEYMAP[0xFFE5] == 0x39 and AST2100_KEYMAP[0xFF0D] == 0x28


def test_every_ascii_letter_and_digit_has_a_hid_usage():
    for keysym in list(range(0x61, 0x7B)) + list(range(0x30, 0x3A)):
        assert keysym in AST2100_KEYMAP, chr(keysym)
    assert AST2100_KEYMAP[0x79] == 0x1C



class FakeUpstream:
    def __init__(self, frames=(), server_init=b"", version=GREETING_003):
        self.sent = []
        self._frames = list(frames)
        self._release = asyncio.Event()
        self.server_init_raw = server_init
        self.protocol_version = version

    async def relay(self, on_bytes):
        for frame in self._frames:
            await on_bytes(frame)
        await self._release.wait()

    async def send_raw(self, data):
        self.sent.append(bytes(data))

    async def close(self):
        return "ok"

    def stop(self):
        self._release.set()


def server_init_bytes(width=1024, height=768):
    name = b"ast2100-test"
    fixed = (struct.pack(">HHBBBB", width, height, 32, 24, 0, 1)
             + struct.pack(">HHHBBB", 255, 255, 255, 16, 8, 0)
             + b"\x00" * 3 + struct.pack(">I", len(name)))
    return fixed + name


async def browser_handshake(session):
    await session.start()
    assert (await session.__anext__()).data == FIXED_CLIENT_VERSION == b"RFB 003.008\n"
    out = b""
    await session.send_bytes(b"RFB 003.008\n")
    out += (await session.__anext__()).data
    await session.send_bytes(b"\x01")
    out += (await session.__anext__()).data
    await session.send_bytes(b"\x01")
    out += (await session.__anext__()).data
    assert out == bytes([1, 1]) + b"\x00\x00\x00\x00" + server_init_bytes()
    return out



VENDOR_PIXEL_FORMAT = struct.pack(">BBBBHHHBBBxxx", 16, 15, 1, 1, 31, 63, 31, 10, 5, 0)
INSYDE_EXTENSION = b"\x00\x00\x00\x00" + b"\x12\x34\x56\x78" + b"\x01\x01\x00\x00"


def vendor_server_init_bytes(width=480, height=640, name=b"AST2100", extension=INSYDE_EXTENSION,
                             pixel_format=VENDOR_PIXEL_FORMAT):
    return (struct.pack(">HH", width, height) + pixel_format
            + struct.pack(">I", len(name)) + name + extension)


def test_server_init_loses_the_insyde_extension_and_declares_the_decoders_pixel_format():
    raw = vendor_server_init_bytes()
    out = standard_server_init(raw)
    assert len(out) == 24 + len(b"AST2100")
    assert out[4:20] == RFB_PIXEL_FORMAT_32BPP
    assert struct.unpack_from(">HH", out) == (480, 640)
    assert struct.unpack_from(">I", out, 20)[0] == len(b"AST2100")
    assert out[24:] == b"AST2100"
    assert raw[24 + len(b"AST2100"):] == INSYDE_EXTENSION != b""
    other = standard_server_init(vendor_server_init_bytes(1024, 768, b"X10"))
    assert struct.unpack_from(">HH", other) == (1024, 768) and other.endswith(b"X10")


def test_a_server_init_without_the_extension_is_passed_with_the_standard_format():
    out = standard_server_init(vendor_server_init_bytes(extension=b""))
    assert out == (struct.pack(">HH", 480, 640) + RFB_PIXEL_FORMAT_32BPP
                   + struct.pack(">I", len(b"AST2100")) + b"AST2100")


@pytest.mark.parametrize("raw, shape", [
    (vendor_server_init_bytes(extension=b"\x00" * 4), {"extension": 4}),
    (vendor_server_init_bytes(extension=INSYDE_EXTENSION + b"\x00"), {"extension": 13}),
    (vendor_server_init_bytes()[:20] + struct.pack(">I", 5000) + b"AST2100" + INSYDE_EXTENSION,
     {"name_length": 5000}),
    (vendor_server_init_bytes()[:10], {}),
])
def test_a_server_init_outside_the_measured_shape_is_refused_by_name(raw, shape):
    with pytest.raises(Ast2100StreamError) as exc:
        standard_server_init(raw)
    assert exc.value.code == "ast2100_stream_desync"
    assert exc.value.shape["kind"] == "server_init"
    for key, value in shape.items():
        assert exc.value.shape[key] == value


def test_session_shows_the_fixed_client_standard_rfb_and_speaks_vendor_to_the_bmc():
    async def scenario():
        payload = bytes(range(64))
        upstream = FakeUpstream(frames=[vendor_frame(1024, 768, payload) + b"\x16\x00"],
                                server_init=server_init_bytes())
        session = RfbPassthroughSession(
            upstream,
            BrowserHandshake(server_init_bytes(), version=FIXED_CLIENT_VERSION,
                             security_type=BrowserHandshake.SECURITY_TYPE_NONE),
            wire=Ast2100Wire(GREETING_003))
        await browser_handshake(session)
        await session.send_bytes(bytes(20) + struct.pack(">BBH", 2, 0, 1) + struct.pack(">i", 0)
                                 + fbu_request(0))
        assert upstream.sent == [fbu_request(0)]
        frame = (await session.__anext__()).data
        assert frame == standard_fbu(desktop_size(1024, 768), ast_rect(1024, 768, MODE_420, payload))
        await asyncio.sleep(0)
        await session.send_bytes(fbu_request() + key_event(0x61, True) + pointer_event(1, 10, 20))
        assert upstream.sent[1:] == [fbu_request(), b"\x19",
                                     build_key_event(0x04, True), build_pointer_event(10, 20, 1)]
        assert session.as_dict()["server_message_types"] == {"0": 1, "22": 1}
        assert session.as_dict()["frames"] == 1
        upstream.stop()
        await session.close()

    asyncio.run(scenario())


def test_055_session_sends_the_mouse_sync_before_the_first_browser_message():
    async def scenario():
        upstream = FakeUpstream(server_init=server_init_bytes(), version=GREETING_055)
        session = RfbPassthroughSession(
            upstream,
            BrowserHandshake(server_init_bytes(), version=FIXED_CLIENT_VERSION,
                             security_type=BrowserHandshake.SECURITY_TYPE_NONE),
            wire=Ast2100Wire(GREETING_055))
        await session.start()
        await session.send_bytes(b"RFB 003.008\n")
        await session.__anext__()
        await session.send_bytes(b"\x01")
        await session.__anext__()
        await session.send_bytes(b"\x01" + fbu_request(0))
        assert upstream.sent == [MOUSE_SYNC, fbu_request(0)]
        upstream.stop()
        await session.close()

    asyncio.run(scenario())


def test_unreadable_upstream_message_ends_the_session_with_a_named_reason():
    async def scenario():
        upstream = FakeUpstream(frames=[vendor_frame(64, 64, b"\x00" * 8), b"\x63"],
                                server_init=server_init_bytes())
        session = RfbPassthroughSession(
            upstream,
            BrowserHandshake(server_init_bytes(), version=FIXED_CLIENT_VERSION,
                             security_type=BrowserHandshake.SECURITY_TYPE_NONE),
            wire=Ast2100Wire(GREETING_003))
        await browser_handshake(session)
        await session.send_bytes(fbu_request(0))
        assert (await session.__anext__()).data == standard_fbu(
            desktop_size(64, 64), ast_rect(64, 64, MODE_420, b"\x00" * 8))
        with pytest.raises(StopAsyncIteration):
            await session.__anext__()
        assert session.error == "ast2100_stream_unsupported"
        assert session.stream_error == {"kind": 99}
        from kvmhub.recovery import retryable
        assert retryable("ast2100_stream_unsupported") is False
        await session.close()

    asyncio.run(scenario())


def test_relay_without_a_wire_is_byte_for_byte_as_before():
    async def scenario():
        raw = b"\x00\x00\x00\x01\x00\x00\x00\x00\x39" + b"\x00" * 264
        upstream = FakeUpstream(frames=[raw], server_init=server_init_bytes())
        session = RfbPassthroughSession(upstream, BrowserHandshake(server_init_bytes(), challenge=b"C" * 24))
        await session.start()
        await session.__anext__()
        for byte in b"RFB 055.008\n" + bytes([16]) + b"A" * 48 + b"\x01":
            await session.send_bytes(bytes([byte]))
        for _ in range(4):
            await session.__anext__()
        await asyncio.sleep(0)
        assert (await session.__anext__()).data == raw
        assert "server_message_types" not in session.as_dict()
        upstream.stop()
        await session.close()

    asyncio.run(scenario())



def fixed_client_adapter(version=GREETING_003):
    adapter = object.__new__(PassthroughAdapter)
    adapter.adapter_id = PASSTHROUGH_ADAPTER_ID
    adapter.client_v2 = True
    adapter.session = None
    adapter.recovery = None
    adapter.recovery_before_connect = None
    adapter.recovery_requires_permit = False
    adapter.input_shaping = None
    adapter.upstream = FakeUpstream(server_init=vendor_server_init_bytes(), version=version)
    return adapter


def test_adapter_hands_the_fixed_client_a_standard_none_handshake_and_a_standard_framer():
    async def scenario():
        adapter = fixed_client_adapter()
        session = await adapter.connect(["binary"])
        assert session.handshake._security_type == BrowserHandshake.SECURITY_TYPE_NONE
        assert session.handshake._version == FIXED_CLIENT_VERSION
        assert session.wire.client.version == GREETING_003
        assert session._framer._allowed == ALLOWED_CLIENT_MESSAGES
        await session.start()
        for byte in b"RFB 003.008\n\x01\x01":
            await session.send_bytes(bytes([byte]))
        for _ in range(4):
            await session.__anext__()
        await session.send_bytes(key_event(0xFFE9, True))
        assert len(adapter.upstream.sent[-1]) == 18
        adapter.upstream.stop()
        await adapter.close()

    asyncio.run(scenario())


def test_the_browser_never_receives_the_insyde_extension():
    async def scenario():
        adapter = fixed_client_adapter()
        session = await adapter.connect(["binary"])
        await session.start()
        await session.__anext__()
        for byte in b"RFB 003.008\n\x01\x01":
            await session.send_bytes(bytes([byte]))
        out = b""
        for _ in range(3):
            out += (await session.__anext__()).data
        assert out == (bytes([1, 1]) + b"\x00\x00\x00\x00"
                       + standard_server_init(vendor_server_init_bytes()))
        assert out.endswith(b"AST2100")
        assert len(out) == 2 + 4 + 24 + 7
        assert session.vendor_server_init == vendor_server_init_bytes()
        assert session.handshake._server_init != session.vendor_server_init
        adapter.upstream.stop()
        await adapter.close()

    asyncio.run(scenario())


def test_a_server_init_of_an_unmeasured_shape_is_a_bmc_fault_not_a_policy_refusal():
    async def scenario():
        adapter = fixed_client_adapter()
        adapter.upstream.server_init_raw = vendor_server_init_bytes(extension=b"\x00" * 5)
        with pytest.raises(Problem) as exc:
            await adapter.connect(["binary"])
        assert exc.value.code == "ast2100_stream_desync"
        assert exc.value.status == 502
        assert adapter.session is None

    asyncio.run(scenario())


def test_adapter_refuses_a_greeting_that_was_never_measured():
    async def scenario():
        with pytest.raises(Problem) as exc:
            await fixed_client_adapter(version="RFB 004.001").connect(["binary"])
        assert exc.value.code == "adapter_not_verified"

    asyncio.run(scenario())



class ReopenableUpstream(FakeUpstream):

    def __init__(self, after):
        super().__init__(server_init=vendor_server_init_bytes())
        self.after = after

    async def drop_websocket(self):
        return None

    async def reopen(self, request_frames=False):
        self.server_init_raw = self.after

    async def wait_first_frame(self, timeout=None):
        return True


def recovered_session(after, wire_version=GREETING_003):
    upstream = ReopenableUpstream(after)
    session = RfbPassthroughSession(
        upstream,
        BrowserHandshake(standard_server_init(vendor_server_init_bytes()),
                         version=FIXED_CLIENT_VERSION,
                         security_type=BrowserHandshake.SECURITY_TYPE_NONE),
        recovery=RecoveryPolicy(attempts=1, first_delay=0.01, deadline=10),
        wire=Ast2100Wire(wire_version),
        vendor_server_init=vendor_server_init_bytes())
    return upstream, session


def test_a_rebuilt_console_with_the_same_vendor_greeting_is_not_a_geometry_change():
    async def scenario():
        upstream, session = recovered_session(vendor_server_init_bytes())
        assert await session._recover("upstream_closed") is True
        assert session.reload_requested is False
        assert session.reload_reason is None
        assert upstream.sent == [Ast2100Wire(GREETING_003).recover(480, 640)]
        assert session.recovery.state == "relaying"
        await session.close()

    asyncio.run(scenario())


def test_a_rebuilt_console_at_another_size_still_requests_the_reload():
    async def scenario():
        upstream, session = recovered_session(vendor_server_init_bytes(800, 600))
        assert await session._recover("upstream_closed") is False
        assert session.reload_requested is True
        assert session.reload_reason == "geometry_changed"
        assert (session.geometry_before["width"], session.geometry_before["height"]) == (480, 640)
        assert session.geometry_after["width"] == 800 and session.geometry_after["height"] == 600
        assert upstream.sent == []
        await session.close()

    asyncio.run(scenario())
