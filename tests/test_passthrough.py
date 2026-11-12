"""Unit tests for the browser-facing passthrough handshake and relay session."""
import asyncio
import struct

import aiohttp
import pytest

from kvmhub.passthrough import (
    CHALLENGE_BYTES,
    SECURITY_RESULT_OK,
    SECURITY_TYPES_FRAME,
    BrowserHandshake,
    BrowserHandshakeError,
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
        keys = b"\x04\x01\x00\x00\x00\xff\xe1"
        await session.send_bytes(client_bytes() + keys)
        assert upstream.sent == [keys]
        await session.close()

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
