"""Unit tests for the browser-facing passthrough handshake and relay session."""
import asyncio
import json
import struct
from pathlib import Path

import aiohttp
import pytest

from kvmhub.passthrough import (
    CHALLENGE_BYTES,
    INSYDE_CLIENT_MESSAGES,
    INSYDE_MESSAGE_SIZES,
    SECURITY_RESULT_OK,
    SECURITY_TYPES_FRAME,
    BrowserHandshake,
    BrowserHandshakeError,
    ClientMessageError,
    ClientMessageFramer,
    RfbPassthroughSession,
)

VERSION = b"RFB 055.008\n"


def server_init_bytes(width=480, height=640, session_id=0x11223344):
    name = b"test-bmc"
    fixed = (struct.pack(">HHBBBB", width, height, 32, 24, 0, 1)
             + struct.pack(">HHHBBB", 255, 255, 255, 16, 8, 0)
             + b"\x00" * 3 + struct.pack(">I", len(name)))
    assert len(fixed) == 24
    extension = b"\x00" * 4 + struct.pack(">I", session_id) + bytes([1, 1, 1, 1])
    return fixed + name + extension


def client_bytes(shared=1, scheme=16, version=VERSION):
    return version + bytes([scheme]) + b"A" * 48 + bytes([shared])


def run(coro):
    return asyncio.run(coro)


class FakeUpstream:

    def __init__(self, frames=(), pending=b""):
        self.sent = []
        self.pending = pending
        self._frames = list(frames)
        self._release = asyncio.Event()

    async def relay(self, on_bytes):
        if self.pending:
            buffered, self.pending = self.pending, b""
            await on_bytes(buffered)
        for frame in self._frames:
            await on_bytes(frame)
        await self._release.wait()

    async def send_raw(self, data):
        self.sent.append(bytes(data))

    def stop(self):
        self._release.set()


class SlowUpstream(FakeUpstream):

    def __init__(self, delay=0.0, **kwargs):
        super().__init__(**kwargs)
        self.delay = delay
        self.concurrent = 0
        self.max_concurrent = 0

    async def send_raw(self, data):
        self.concurrent += 1
        self.max_concurrent = max(self.max_concurrent, self.concurrent)
        try:
            if self.delay:
                await asyncio.sleep(self.delay)
            self.sent.append(bytes(data))
        finally:
            self.concurrent -= 1



def test_handshake_produces_the_measured_server_sequence():
    init = server_init_bytes()
    hs = BrowserHandshake(init, challenge=b"C" * CHALLENGE_BYTES)
    assert hs.start() == VERSION
    out, upstream = hs.feed(client_bytes())
    assert hs.completed is True
    assert hs.shared is True
    assert upstream == b""
    assert out == SECURITY_TYPES_FRAME + b"C" * CHALLENGE_BYTES + SECURITY_RESULT_OK + init


def test_handshake_is_byte_stream_safe():
    init = server_init_bytes()
    hs = BrowserHandshake(init, challenge=b"C" * CHALLENGE_BYTES)
    hs.start()
    produced = bytearray()
    for byte in client_bytes():
        out, upstream = hs.feed(bytes([byte]))
        produced += out
        assert upstream == b""
    assert bytes(produced) == SECURITY_TYPES_FRAME + b"C" * CHALLENGE_BYTES + SECURITY_RESULT_OK + init
    assert hs.completed is True


def test_handshake_forwards_coalesced_post_init_messages():
    init = server_init_bytes()
    hs = BrowserHandshake(init, challenge=b"C" * CHALLENGE_BYTES)
    hs.start()
    pointer = b"\x05\x00\x01\x00\x02\x00"
    out, upstream = hs.feed(client_bytes() + pointer)
    assert hs.completed is True
    assert out.endswith(init)
    assert upstream == pointer


def test_handshake_rejects_a_non_measured_version():
    hs = BrowserHandshake(server_init_bytes(), challenge=b"C" * CHALLENGE_BYTES)
    hs.start()
    with pytest.raises(BrowserHandshakeError, match="unexpected_client_version"):
        hs.feed(b"RFB 003.008\n" + b"\x10" + b"A" * 48 + b"\x01")


def test_handshake_rejects_a_foreign_security_type():
    hs = BrowserHandshake(server_init_bytes(), challenge=b"C" * CHALLENGE_BYTES)
    hs.start()
    with pytest.raises(BrowserHandshakeError, match="unsupported_security_type"):
        hs.feed(VERSION + b"\x02")


def test_handshake_rejects_an_invalid_client_init():
    hs = BrowserHandshake(server_init_bytes(), challenge=b"C" * CHALLENGE_BYTES)
    hs.start()
    with pytest.raises(BrowserHandshakeError, match="invalid_client_init"):
        hs.feed(VERSION + b"\x10" + b"A" * 48 + b"\x07")


def test_handshake_requires_a_server_init():
    with pytest.raises(ValueError):
        BrowserHandshake(b"")


def test_handshake_requires_a_24_byte_challenge():
    with pytest.raises(ValueError):
        BrowserHandshake(server_init_bytes(), challenge=b"short")


def test_handshake_generates_a_fresh_challenge_by_default():
    first = BrowserHandshake(server_init_bytes())
    second = BrowserHandshake(server_init_bytes())
    assert len(first._challenge) == CHALLENGE_BYTES
    assert first._challenge != second._challenge


def test_handshake_never_retains_the_client_auth_reply():
    hs = BrowserHandshake(server_init_bytes(), challenge=b"C" * CHALLENGE_BYTES)
    hs.start()
    hs.feed(client_bytes())
    assert not hasattr(hs, "response")
    assert b"A" * 48 not in bytes(hs._buf)



def test_session_orders_server_init_before_relayed_frames():
    async def scenario():
        init = server_init_bytes()
        pending = b"\x00\x00\x00\x01\x00\x00\x00\x00" + b"\x39" + b"\x00" * 264
        upstream = FakeUpstream(frames=[b"frame-1", b"frame-2"], pending=pending)
        session = RfbPassthroughSession(upstream, BrowserHandshake(init, challenge=b"C" * 24))
        await session.start()
        assert await session.__anext__() == aiohttp.WSMessage(aiohttp.WSMsgType.BINARY, VERSION, "")
        for byte in client_bytes():
            await session.send_bytes(bytes([byte]))
        messages = [await session.__anext__() for _ in range(5)]
        payloads = [m.data for m in messages]
        assert payloads[0] == SECURITY_TYPES_FRAME
        assert payloads[1] == b"C" * 24
        assert payloads[2] == SECURITY_RESULT_OK
        assert payloads[3] == init
        assert payloads[4] == pending
        await asyncio.sleep(0)
        assert [await session.__anext__() for _ in range(2)] == [
            aiohttp.WSMessage(aiohttp.WSMsgType.BINARY, b"frame-1", ""),
            aiohttp.WSMessage(aiohttp.WSMsgType.BINARY, b"frame-2", ""),
        ]
        upstream.stop()
        with pytest.raises(StopAsyncIteration):
            await session.__anext__()
        await session.close()

    run(scenario())


def test_session_forwards_client_messages_after_the_handshake():
    async def scenario():
        upstream = FakeUpstream()
        session = RfbPassthroughSession(upstream, BrowserHandshake(server_init_bytes(), challenge=b"C" * 24))
        await session.start()
        await session.send_bytes(client_bytes(shared=0))
        pointer = b"\x05\x04\x00\x64\x00\xc8"
        await session.send_bytes(pointer)
        assert upstream.sent == [pointer]
        assert session.handshake.shared is False
        assert session.client_bytes > 0
        await session.close()

    run(scenario())


def test_session_forwards_the_coalesced_trailing_bytes():
    async def scenario():
        upstream = FakeUpstream()
        session = RfbPassthroughSession(upstream, BrowserHandshake(server_init_bytes(), challenge=b"C" * 24))
        await session.start()
        keys = b"\x04\x01\x00\x00\x00\x00\xff\xe1"
        await session.send_bytes(client_bytes() + keys)
        assert upstream.sent == [keys]
        await session.close()

    run(scenario())


def test_a_key_burst_is_queued_in_order_and_never_dropped():
    async def scenario():
        upstream = SlowUpstream(delay=0.001)
        session = RfbPassthroughSession(upstream, BrowserHandshake(server_init_bytes(), challenge=b"C" * 24))
        await session.start()
        await session.send_bytes(client_bytes())
        burst = [b"\x04" + bytes([i % 2]) + b"\x00\x00" + i.to_bytes(4, "big") for i in range(200)]
        for key in burst:
            await session.send_bytes(key)
        assert upstream.sent == burst
        assert upstream.max_concurrent == 1
        assert session.error is None
        await session.close()

    run(scenario())


def test_a_slow_browser_backpressures_the_bmc_instead_of_losing_frames():
    async def scenario():
        frames = [b"frame-%03d" % i for i in range(200)]
        upstream = FakeUpstream(frames=frames)
        session = RfbPassthroughSession(upstream, BrowserHandshake(server_init_bytes(), challenge=b"C" * 24),
                                        queue_size=2)
        await session.start()
        seen = []

        async def slow_reader():
            while len(seen) < 2 + len(frames):
                seen.append((await session.__anext__()).data)
                await asyncio.sleep(0.001)

        reader = asyncio.create_task(slow_reader())
        await session.send_bytes(client_bytes())
        await asyncio.wait_for(reader, 10)
        assert seen[2:] == frames
        await session.close()

    run(scenario())


def test_the_outbound_queue_is_bounded_by_bytes_not_only_by_count():
    async def scenario():
        frame = b"x" * 4096
        frames = [frame] * 40
        upstream = FakeUpstream(frames=frames)
        session = RfbPassthroughSession(upstream, BrowserHandshake(server_init_bytes(), challenge=b"C" * 24),
                                        queue_size=64, queue_bytes=16 * 1024)
        await session.start()
        seen = []

        async def slow_reader():
            while len(seen) < 2 + len(frames):
                seen.append((await session.__anext__()).data)
                await asyncio.sleep(0.001)

        reader = asyncio.create_task(slow_reader())
        await session.send_bytes(client_bytes())
        await asyncio.wait_for(reader, 10)
        assert seen[2:] == frames
        assert session.peak_buffered_bytes <= 16 * 1024
        await session.close()

    run(scenario())


def test_a_frame_bigger_than_the_byte_budget_is_still_admitted():
    async def scenario():
        big = b"y" * 8192
        upstream = FakeUpstream(frames=[big])
        session = RfbPassthroughSession(upstream, BrowserHandshake(server_init_bytes(), challenge=b"C" * 24),
                                        queue_size=4, queue_bytes=1024)
        await session.start()
        await session.send_bytes(client_bytes())
        await session.__anext__()
        await session.__anext__()
        assert (await session.__anext__()).data == big
        await session.close()

    run(scenario())


def pixel_format():
    return b"\x00" + b"\x00" * 3 + b"\x20\x18\x00\x01" + b"\x00\xff\x00\xff\x00\xff\x10\x08\x00" + b"\x00" * 3


def set_encodings(*values):
    return struct.pack(">BBH", 2, 0, len(values)) + b"".join(struct.pack(">i", v) for v in values)


def fb_request():
    return struct.pack(">BBHHHH", 3, 1, 0, 0, 480, 640)


KEY = b"\x04\x01\x00\x00\x00\x00\xff\xe1"
POINTER = b"\x05\x04\x00\x64\x00\xc8"


def test_framer_forwards_only_whole_messages_across_split_frames():
    framer = ClientMessageFramer()
    stream = pixel_format() + set_encodings(87, 0, 1) + fb_request() + KEY + POINTER
    forwarded = bytearray()
    for byte in stream:
        forwarded += framer.feed(bytes([byte]))
    assert bytes(forwarded) == stream
    assert framer.feed(KEY[:5]) == b""
    assert framer.feed(KEY[5:]) == KEY


def test_framer_forwards_a_coalesced_burst_unchanged():
    burst = pixel_format() + set_encodings(87, 0) + fb_request() + KEY + POINTER
    assert ClientMessageFramer().feed(burst) == burst


@pytest.mark.parametrize("message", [
    b"\x06\x00\x00\x00\x00\x00\x00\x04abcd",
    b"\x16\x00\x00\x00",
    b"\x37\x00\x00\x00",
    b"\x39" + b"\x00" * 8,
    b"\xfa\xfa\xfa\xfa",
])
def test_framer_denies_everything_outside_the_allowlist(message):
    with pytest.raises(ClientMessageError, match="client_message_denied"):
        ClientMessageFramer().feed(message)


@pytest.mark.parametrize("count", [0, 33, 0xFFFF])
def test_framer_rejects_an_implausible_encoding_count(count):
    with pytest.raises(ClientMessageError, match="client_message_malformed"):
        ClientMessageFramer().feed(struct.pack(">BBH", 2, 0, count))


def test_framer_yields_nothing_from_a_chunk_that_contains_a_denied_message():
    framer = ClientMessageFramer()
    with pytest.raises(ClientMessageError):
        framer.feed(POINTER + b"\x06\x00\x00\x00\x00\x00\x00\x00")


def test_framer_allowlist_is_configurable_and_never_guesses_sizes():
    assert ClientMessageFramer({4}).feed(KEY) == KEY
    with pytest.raises(ClientMessageError, match="client_message_denied"):
        ClientMessageFramer({4}).feed(POINTER)
    with pytest.raises(ClientMessageError, match="client_message_denied"):
        ClientMessageFramer({6}).feed(b"\x06" + b"\x00" * 16)


INSYDE_KEY = b"\x04\x00\x01\x00\x00\x00\x00\x00\xe1" + b"\x00" * 9
INSYDE_POINTER = b"\x05\x00\x04\x00\x64\x00\xc8" + b"\x00" * 11
INSYDE_CURSOR_POS = b"\x19"


def test_vendor_profile_frames_the_measured_insyde_input():
    framer = ClientMessageFramer(INSYDE_CLIENT_MESSAGES, sizes=INSYDE_MESSAGE_SIZES)
    stream = INSYDE_KEY + INSYDE_POINTER + INSYDE_CURSOR_POS
    assert framer.feed(stream) == stream
    assert framer.feed(b"") == b""


def test_vendor_profile_waits_for_the_whole_eighteen_byte_key_event():
    framer = ClientMessageFramer(INSYDE_CLIENT_MESSAGES, sizes=INSYDE_MESSAGE_SIZES)
    assert framer.feed(INSYDE_KEY[:8]) == b""
    assert framer.feed(INSYDE_KEY[8:]) == INSYDE_KEY
    assert framer.feed(INSYDE_POINTER) == INSYDE_POINTER


def test_vendor_profile_keeps_denying_unlisted_messages():
    framer = ClientMessageFramer(INSYDE_CLIENT_MESSAGES, sizes=INSYDE_MESSAGE_SIZES)
    with pytest.raises(ClientMessageError, match="client_message_denied"):
        framer.feed(b"\x06\x00\x00\x00\x00\x00\x00\x04abcd")
    with pytest.raises(ClientMessageError, match="client_message_denied"):
        ClientMessageFramer(INSYDE_CLIENT_MESSAGES, sizes={0: 20}).feed(INSYDE_CURSOR_POS)


def test_default_profile_still_rejects_the_vendor_cursor_request():
    with pytest.raises(ClientMessageError, match="client_message_denied"):
        ClientMessageFramer().feed(INSYDE_CURSOR_POS)


def test_session_relays_the_vendor_profile_verbatim():
    async def scenario():
        upstream = FakeUpstream()
        session = RfbPassthroughSession(
            upstream, BrowserHandshake(server_init_bytes(), challenge=b"C" * 24),
            allowed_client_messages=INSYDE_CLIENT_MESSAGES, message_sizes=INSYDE_MESSAGE_SIZES)
        await session.start()
        await session.send_bytes(client_bytes())
        for message in (fb_request(), INSYDE_POINTER, INSYDE_KEY, INSYDE_CURSOR_POS):
            await session.send_bytes(message)
        await asyncio.sleep(0)
        assert session.error is None
        assert upstream.sent == [fb_request(), INSYDE_POINTER, INSYDE_KEY, INSYDE_CURSOR_POS]
        await session.close()

    run(scenario())


def test_session_relays_the_allowed_message_set_in_arrival_order():
    async def scenario():
        upstream = FakeUpstream()
        session = RfbPassthroughSession(upstream, BrowserHandshake(server_init_bytes(), challenge=b"C" * 24))
        await session.start()
        await session.send_bytes(client_bytes())
        for message in (pixel_format(), set_encodings(87, 0), fb_request(), KEY, POINTER):
            await session.send_bytes(message)
        assert b"".join(upstream.sent) == pixel_format() + set_encodings(87, 0) + fb_request() + KEY + POINTER
        assert session.error is None
        await session.close()

    run(scenario())


def test_session_ends_and_forwards_nothing_on_a_denied_client_message():
    async def scenario():
        upstream = FakeUpstream()
        session = RfbPassthroughSession(upstream, BrowserHandshake(server_init_bytes(), challenge=b"C" * 24))
        await session.start()
        await session.send_bytes(client_bytes())
        await session.send_bytes(KEY + b"\x06\x00\x00\x00\x00\x00\x00\x01x")
        assert session.error == "client_message_denied"
        assert session.closed
        assert upstream.sent == []
        await session.send_bytes(POINTER)
        assert upstream.sent == []

    run(scenario())


def test_session_refuses_a_denied_message_coalesced_with_the_client_init():
    async def scenario():
        upstream = FakeUpstream()
        session = RfbPassthroughSession(upstream, BrowserHandshake(server_init_bytes(), challenge=b"C" * 24))
        await session.start()
        await session.send_bytes(client_bytes() + b"\x39" + b"\x00" * 8)
        assert session.error == "client_message_denied"
        assert session.closed and upstream.sent == []
        assert session._relay_task is None

    run(scenario())


def test_session_closes_on_a_bad_handshake():
    async def scenario():
        session = RfbPassthroughSession(FakeUpstream(), BrowserHandshake(server_init_bytes(), challenge=b"C" * 24))
        await session.start()
        await session.send_bytes(b"RFB 003.008\n")
        assert session.error == "unexpected_client_version"
        assert session.handshake.completed is False
        assert (await session.__anext__()).data == VERSION
        with pytest.raises(StopAsyncIteration):
            await session.__anext__()

    run(scenario())


def test_session_rejects_text_frames():
    async def scenario():
        session = RfbPassthroughSession(FakeUpstream(), BrowserHandshake(server_init_bytes(), challenge=b"C" * 24))
        await session.start()
        await session.send_str("hello")
        assert session.error == "unexpected_text_frame"

    run(scenario())


def test_session_close_is_idempotent_and_keeps_the_upstream_alive():
    async def scenario():
        upstream = FakeUpstream()
        session = RfbPassthroughSession(upstream, BrowserHandshake(server_init_bytes(), challenge=b"C" * 24))
        await session.start()
        await session.send_bytes(client_bytes())
        await session.close()
        await session.close()
        assert not hasattr(upstream, "closed")

    run(scenario())


def test_session_reports_no_credentials_in_its_surface():
    session = RfbPassthroughSession(FakeUpstream(), BrowserHandshake(server_init_bytes()))
    surface = repr(session.as_dict())
    for forbidden in ("SID", "ticket", "pwd", "passw"):
        assert forbidden not in surface



def test_browser_handshake_sends_the_negotiated_version():
    hs = BrowserHandshake(server_init_bytes(), challenge=b"C" * 24,
                          version=b"RFB 003.008\n")
    assert hs.start() == b"RFB 003.008\n"


def test_browser_handshake_accepts_the_matching_client_version():
    hs = BrowserHandshake(server_init_bytes(), challenge=b"C" * 24,
                          version=b"RFB 003.008\n")
    hs.start()
    out, trailing = hs.feed(b"RFB 003.008\n\x10" + b"X" * 48 + b"\x01")
    assert hs.completed and trailing == b""
    assert out.endswith(server_init_bytes())


def test_browser_handshake_rejects_a_mismatched_client_version():
    hs = BrowserHandshake(server_init_bytes(), challenge=b"C" * 24,
                          version=b"RFB 003.008\n")
    hs.start()
    with pytest.raises(BrowserHandshakeError, match="unexpected_client_version"):
        hs.feed(b"RFB 055.008\n")



def capture_messages(group):
    path = Path(__file__).parent / "fixtures" / "insyde-client-capture.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    return [bytes.fromhex(item["bytes_hex"]) for item in data[group]]


def test_measured_capture_completes_the_browser_handshake():
    hs = BrowserHandshake(server_init_bytes(), challenge=b"C" * 24,
                          version=b"RFB 003.008\n")
    assert hs.start() == b"RFB 003.008\n"
    for message in capture_messages("handshake_messages"):
        hs.feed(message)
    assert hs.completed
    assert hs.shared is True


def test_measured_capture_is_relayed_whole_by_the_vendor_profile():
    upstream = FakeUpstream()
    session = RfbPassthroughSession(
        upstream, BrowserHandshake(server_init_bytes(), challenge=b"C" * 24,
                                   version=b"RFB 003.008\n"),
        allowed_client_messages=INSYDE_CLIENT_MESSAGES, message_sizes=INSYDE_MESSAGE_SIZES)

    async def scenario():
        await session.start()
        for message in capture_messages("handshake_messages"):
            await session.send_bytes(message)
        assert session.handshake.completed
        relay = capture_messages("relay_messages")
        for message in relay:
            await session.send_bytes(message)
        await asyncio.sleep(0)
        assert session.error is None
        assert upstream.sent == relay
        await session.close()

    run(scenario())


def test_measured_capture_still_contains_the_one_byte_cursor_request():
    relay = capture_messages("relay_messages")
    assert b"\x19" in relay
    assert [len(m) for m in relay if m[0] in (4, 5)] == [18, 18]
