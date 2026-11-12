"""Browser-facing RFB server for the measured X10 iKVM/HTML5 console."""
from __future__ import annotations

import asyncio
import contextlib
import secrets
from typing import Any

from aiohttp import WSMsgType, WSMessage

from .ast2100_protocol import (
    AUTH_RESPONSE_BYTES,
    RFB_VERSION,
    RFB_VERSION_BYTES,
    SECURITY_TYPE_INSYDE,
)

SECURITY_TYPES_FRAME = bytes([1, SECURITY_TYPE_INSYDE])
SECURITY_RESULT_OK = b"\x00\x00\x00\x00"
CHALLENGE_BYTES = 24
MAX_TRAILING_BYTES = 64 * 1024


class BrowserHandshakeError(ValueError):
    pass


class BrowserHandshake:

    def __init__(self, server_init: bytes, *, challenge: bytes | None = None) -> None:
        if not isinstance(server_init, (bytes, bytearray)) or not server_init:
            raise ValueError("server_init is required")
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
        return RFB_VERSION.encode("ascii")

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
                if raw != RFB_VERSION.encode("ascii"):
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

    def __init__(self, upstream, handshake: BrowserHandshake, *, queue_size: int = 64) -> None:
        self.upstream = upstream
        self.handshake = handshake
        self._out: asyncio.Queue[bytes | None] = asyncio.Queue(maxsize=queue_size)
        self._relay_task: asyncio.Task | None = None
        self._closed = False
        self.started = False
        self.error: str | None = None
        self.client_bytes = 0
        self.server_bytes = 0

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
            await self.upstream.send_raw(data)
            return
        try:
            out, trailing = self.handshake.feed(data)
        except BrowserHandshakeError as exc:
            self.error = exc.args[0] if exc.args else "handshake_failed"
            await self.close(code=1002)
            return
        if out:
            await self._emit(out)
        if trailing:
            await self.upstream.send_raw(trailing)
        if self.handshake.completed:
            self._start_relay()

    async def send_str(self, data: str) -> None:
        self.error = "unexpected_text_frame"
        await self.close(code=1003)

    def _start_relay(self) -> None:
        if self._relay_task is None and not self._closed:
            self._relay_task = asyncio.create_task(self._relay())

    async def _relay(self) -> None:
        try:
            await self.upstream.relay(self._emit)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - classified into a stable code
            self.error = getattr(exc, "code", None) or type(exc).__name__
        finally:
            with contextlib.suppress(asyncio.QueueFull):
                self._out.put_nowait(None)

    async def _emit(self, data: bytes) -> None:
        if self._closed:
            return
        self.server_bytes += len(data)
        await self._out.put(bytes(data))

    async def close(self, code: int = 1000) -> None:
        if self._closed:
            return
        self._closed = True
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
        return WSMessage(WSMsgType.BINARY, item, "")

    def as_dict(self) -> dict[str, Any]:
        return {"protocol": self.protocol, "handshake_completed": self.handshake.completed,
                "shared": self.handshake.shared, "client_bytes": self.client_bytes,
                "server_bytes": self.server_bytes, "error": self.error}
