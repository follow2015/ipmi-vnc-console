"""Browser-facing RFB server for the measured X10 iKVM/HTML5 console."""
from __future__ import annotations

import asyncio
import contextlib
import secrets
import time
from typing import Any

import aiohttp
from aiohttp import WSMsgType, WSMessage

from .ast2100_protocol import (
    AUTH_RESPONSE_BYTES,
    CLIENT_MSG_FBU_REQUEST,
    CLIENT_MSG_KEY_EVENT,
    CLIENT_MSG_POINTER_EVENT,
    CLIENT_MSG_SET_ENCODINGS,
    RFB_VERSION,
    RFB_VERSION_BYTES,
    SECURITY_TYPE_INSYDE,
)
from .common import Problem
from .recovery import RecoveryPolicy, RecoveryState, retryable

SECURITY_TYPES_FRAME = bytes([1, SECURITY_TYPE_INSYDE])
SECURITY_RESULT_OK = b"\x00\x00\x00\x00"
CHALLENGE_BYTES = 24
MAX_TRAILING_BYTES = 64 * 1024
MAX_BUFFERED_BYTES = 8 * 1024 * 1024

CLIENT_MSG_SET_PIXEL_FORMAT = 0
CLIENT_MSG_INSYDE_MT_CURSOR_POS_REQ = 25
ALLOWED_CLIENT_MESSAGES = frozenset({
    CLIENT_MSG_SET_PIXEL_FORMAT, CLIENT_MSG_SET_ENCODINGS, CLIENT_MSG_FBU_REQUEST,
    CLIENT_MSG_KEY_EVENT, CLIENT_MSG_POINTER_EVENT,
})
_FIXED_CLIENT_MESSAGE_BYTES = {
    CLIENT_MSG_SET_PIXEL_FORMAT: 20,
    CLIENT_MSG_FBU_REQUEST: 10,
    CLIENT_MSG_KEY_EVENT: 8,
    CLIENT_MSG_POINTER_EVENT: 6,
}

INSYDE_MESSAGE_SIZES = {
    CLIENT_MSG_SET_PIXEL_FORMAT: 20,
    CLIENT_MSG_FBU_REQUEST: 10,
    CLIENT_MSG_KEY_EVENT: 18,
    CLIENT_MSG_POINTER_EVENT: 18,
    CLIENT_MSG_INSYDE_MT_CURSOR_POS_REQ: 1,
}
INSYDE_CLIENT_MESSAGES = ALLOWED_CLIENT_MESSAGES | {CLIENT_MSG_INSYDE_MT_CURSOR_POS_REQ}
MAX_SET_ENCODINGS = 32


class BrowserHandshakeError(ValueError):
    pass


class ClientMessageError(ValueError):

    def __init__(self, code: str, *, kind: int | None = None, length: int = 0) -> None:
        super().__init__(code)
        self.code = code
        self.kind = kind
        self.length = length


class ClientMessageFramer:

    def __init__(self, allowed=ALLOWED_CLIENT_MESSAGES, *,
                 sizes: dict[int, int] | None = None) -> None:
        self._allowed = frozenset(allowed)
        self._sizes = dict(_FIXED_CLIENT_MESSAGE_BYTES if sizes is None else sizes)
        self._buf = bytearray()
        self.key_events = 0
        self.client_types: dict[int, int] = {}

    def _next_size(self) -> int | None:
        kind = self._buf[0]
        buffered = len(self._buf)
        if kind not in self._allowed:
            raise ClientMessageError("client_message_denied", kind=kind, length=buffered)
        if kind == CLIENT_MSG_SET_ENCODINGS:
            if len(self._buf) < 4:
                return None
            count = int.from_bytes(self._buf[2:4], "big")
            if not 1 <= count <= MAX_SET_ENCODINGS:
                raise ClientMessageError("client_message_malformed", kind=kind, length=buffered)
            return 4 + 4 * count
        size = self._sizes.get(kind)
        if size is None:
            raise ClientMessageError("client_message_denied", kind=kind, length=buffered)
        return size

    def feed(self, data: bytes) -> bytes:
        self._buf.extend(data)
        ready = bytearray()
        while self._buf:
            size = self._next_size()
            if size is None or len(self._buf) < size:
                break
            ready += self._buf[:size]
            kind = self._buf[0]
            if kind == CLIENT_MSG_KEY_EVENT:
                self.key_events += 1
            self.client_types[kind] = self.client_types.get(kind, 0) + 1
            del self._buf[:size]
        return bytes(ready)

    def type_summary(self) -> str:
        return ",".join(f"{kind}:{count}" for kind, count in sorted(self.client_types.items()))


class BrowserHandshake:

    def __init__(self, server_init: bytes, *, challenge: bytes | None = None,
                 version: bytes = RFB_VERSION.encode("ascii")) -> None:
        if not isinstance(server_init, (bytes, bytearray)) or not server_init:
            raise ValueError("server_init is required")
        if (not isinstance(version, (bytes, bytearray)) or len(version) != RFB_VERSION_BYTES
                or version[:4] != b"RFB " or version[-1:] != b"\n"
                or not all(byte in b"0123456789." for byte in version[4:-1])):
            raise ValueError("invalid_browser_version")
        self._version = bytes(version)
        self._server_init = bytes(server_init)
        self._challenge = bytes(challenge) if challenge is not None else secrets.token_bytes(CHALLENGE_BYTES)
        if len(self._challenge) != CHALLENGE_BYTES:
            raise ValueError("challenge must be 24 bytes")
        self._buf = bytearray()
        self.stage = "version"
        self.shared: bool | None = None
        self.completed = False

    def start(self) -> bytes:
        if self.stage != "version":
            raise BrowserHandshakeError("handshake already started")
        return self._version

    def feed(self, data: bytes) -> tuple[bytes, bytes]:
        if self.completed:
            if len(data) > MAX_TRAILING_BYTES:
                raise BrowserHandshakeError("trailing_bytes_too_large")
            return b"", bytes(data)
        self._buf.extend(data)
        out = bytearray()
        while True:
            if self.stage == "version":
                if len(self._buf) < RFB_VERSION_BYTES:
                    break
                raw = bytes(self._buf[:RFB_VERSION_BYTES])
                del self._buf[:RFB_VERSION_BYTES]
                if raw != self._version:
                    raise BrowserHandshakeError("unexpected_client_version")
                out += SECURITY_TYPES_FRAME
                self.stage = "security"
            elif self.stage == "security":
                if not self._buf:
                    break
                scheme = self._buf[0]
                del self._buf[:1]
                if scheme != SECURITY_TYPE_INSYDE:
                    raise BrowserHandshakeError("unsupported_security_type")
                out += self._challenge
                self.stage = "response"
            elif self.stage == "response":
                if len(self._buf) < AUTH_RESPONSE_BYTES:
                    break
                del self._buf[:AUTH_RESPONSE_BYTES]
                out += SECURITY_RESULT_OK
                self.stage = "client_init"
            elif self.stage == "client_init":
                if not self._buf:
                    break
                shared = self._buf[0]
                del self._buf[:1]
                if shared not in (0, 1):
                    raise BrowserHandshakeError("invalid_client_init")
                self.shared = bool(shared)
                out += self._server_init
                self.completed = True
                self.stage = "relay"
                break
            else:  # pragma: no cover - defensive
                break
        trailing = bytes(self._buf) if self.completed else b""
        if self.completed:
            self._buf.clear()
        return bytes(out), trailing


class RfbPassthroughSession:

    protocol = "binary"

    def __init__(self, upstream, handshake: BrowserHandshake, *, queue_size: int = 64,
                 queue_bytes: int = MAX_BUFFERED_BYTES,
                 allowed_client_messages=ALLOWED_CLIENT_MESSAGES,
                 message_sizes: dict[int, int] | None = None,
                 recovery: RecoveryPolicy | None = None) -> None:
        self.upstream = upstream
        self.handshake = handshake
        self.recovery: RecoveryState | None = RecoveryState(recovery) if recovery else None
        self._framer = ClientMessageFramer(allowed_client_messages, sizes=message_sizes)
        self._out: asyncio.Queue[bytes | None] = asyncio.Queue(maxsize=queue_size)
        self._relay_task: asyncio.Task | None = None
        self._closed = False
        self._buffer_limit = queue_bytes
        self._buffered = 0
        self.peak_buffered_bytes = 0
        self._room = asyncio.Event()
        self._room.set()
        self.started = False
        self.error: str | None = None
        self.denied: dict[str, int] | None = None
        self.client_bytes = 0
        self.server_bytes = 0

    @property
    def client_key_events(self) -> int:
        return self._framer.key_events

    @property
    def client_message_types(self) -> dict[int, int]:
        return dict(self._framer.client_types)

    @property
    def client_message_summary(self) -> str:
        return self._framer.type_summary()

    async def start(self) -> None:
        if self.started:
            return
        self.started = True
        await self._emit(self.handshake.start())

    async def send_bytes(self, data: bytes) -> None:
        if self._closed or not data:
            return
        self.client_bytes += len(data)
        if self.handshake.completed:
            await self._forward(data)
            return
        try:
            out, trailing = self.handshake.feed(data)
        except BrowserHandshakeError as exc:
            self.error = exc.args[0] if exc.args else "handshake_failed"
            await self.close(code=1002)
            return
        if out:
            await self._emit(out)
        if trailing and not await self._forward(trailing):
            return
        if self.handshake.completed:
            self._start_relay()

    async def _forward(self, data: bytes) -> bool:
        try:
            ready = self._framer.feed(data)
        except ClientMessageError as exc:
            self.error = exc.code
            self.denied = {"kind": exc.kind, "length": exc.length}
            await self.close(code=1008)
            return False
        if ready:
            try:
                await self.upstream.send_raw(ready)
            except Problem:
                if self.recovery is None or self.recovery.state != "recovering":
                    raise
                self.recovery.dropped_input += 1
        return True

    async def send_str(self, data: str) -> None:
        self.error = "unexpected_text_frame"
        await self.close(code=1003)

    def _start_relay(self) -> None:
        if self._relay_task is None and not self._closed:
            self._relay_task = asyncio.create_task(self._relay())

    async def _relay(self) -> None:
        try:
            while not self._closed:
                error = await self._relay_once()
                if self._closed:
                    break
                if self.recovery is None or not self.recovery.may_try(
                        error, getattr(self.upstream, "upstream_close_code", None)):
                    self.error = error or self.error
                    break
                if not await self._recover(error):
                    self.error = self.recovery.last_error or error or self.error
                    break
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - classified into a stable code
            self.error = getattr(exc, "code", None) or type(exc).__name__
        finally:
            with contextlib.suppress(asyncio.QueueFull):
                self._out.put_nowait(None)

    async def _relay_once(self) -> str | None:
        try:
            await self.upstream.relay(self._emit)
        except asyncio.CancelledError:
            raise
        except Problem as exc:
            return exc.code
        except Exception as exc:  # noqa: BLE001
            return getattr(exc, "code", None) or type(exc).__name__
        return "upstream_closed"

    async def _recover(self, error: str) -> bool:
        state = self.recovery
        assert state is not None
        state.begin()
        expected = self.handshake._server_init[:20]
        started = time.monotonic()
        await self.upstream.drop_websocket()
        for attempt in range(1, state.policy.attempts + 1):
            await asyncio.sleep(state.policy.delay(attempt))
            if self._closed:
                state.give_up(None)
                return False
            if time.monotonic() - started > state.policy.deadline:
                state.give_up(state.last_error or error)
                return False
            state.attempt()
            attempt_started = time.monotonic()
            try:
                await self.upstream.reopen()
            except Problem as exc:
                state.fail(exc.code)
                if not retryable(exc.code):
                    state.give_up(exc.code)
                    return False
                continue
            except (aiohttp.ClientError, TimeoutError):
                state.fail("upstream_unavailable")
                continue
            if self.upstream.server_init_raw[:20] != expected:
                state.fail("upstream_changed")
                await self.upstream.drop_websocket()
                state.give_up("upstream_changed")
                return False
            try:
                await self.upstream.wait_first_frame(timeout=state.policy.frame_timeout)
            except Problem as exc:
                state.fail(exc.code)
                continue
            except (aiohttp.ClientError, TimeoutError):
                state.fail("upstream_unavailable")
                continue
            state.succeed(int((time.monotonic() - attempt_started) * 1000))
            return True
        state.give_up(state.last_error or error)
        return False

    async def _emit(self, data: bytes) -> None:
        if self._closed:
            return
        size = len(data)
        while not self._closed and self._buffered and self._buffered + size > self._buffer_limit:
            self._room.clear()
            await self._room.wait()
        if self._closed:
            return
        self._buffered += size
        self.peak_buffered_bytes = max(self.peak_buffered_bytes, self._buffered)
        self.server_bytes += size
        await self._out.put(bytes(data))

    async def close(self, code: int = 1000) -> None:
        if self._closed:
            return
        self._closed = True
        self._room.set()
        if self._relay_task is not None and not self._relay_task.done():
            self._relay_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._relay_task
        with contextlib.suppress(asyncio.QueueFull):
            self._out.put_nowait(None)

    def __aiter__(self) -> "RfbPassthroughSession":
        return self

    @property
    def closed(self) -> bool:
        return self._closed

    async def __anext__(self) -> WSMessage:
        item = await self._out.get()
        if item is None:
            raise StopAsyncIteration
        self._buffered -= len(item)
        self._room.set()
        return WSMessage(WSMsgType.BINARY, item, "")

    def as_dict(self) -> dict[str, Any]:
        data = {"protocol": self.protocol, "handshake_completed": self.handshake.completed,
                "shared": self.handshake.shared, "client_bytes": self.client_bytes,
                "server_bytes": self.server_bytes, "buffered_bytes": self._buffered,
                "peak_buffered_bytes": self.peak_buffered_bytes, "error": self.error,
                "client_message_types": {str(kind): count
                                         for kind, count in self._framer.client_types.items()}}
        if self.recovery is not None:
            data.update(self.recovery.counters())
        return data
