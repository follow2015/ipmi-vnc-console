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
    framebuffer_update_request,
)
from .common import Problem
from .input_shaping import InputOverflow, InputShaper, InputShapingConfig
from .insyde_messages import is_key_release
from .recovery import RecoveryPolicy, RecoveryState, retryable
from .rfb_upstream import set_encodings

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

CLIENT_MSG_SMC_MOUSE_SYNC = 7
SMC_CLIENT_MESSAGES = ALLOWED_CLIENT_MESSAGES | {
    CLIENT_MSG_SMC_MOUSE_SYNC, CLIENT_MSG_INSYDE_MT_CURSOR_POS_REQ}
SMC_MESSAGE_SIZES = {**INSYDE_MESSAGE_SIZES, CLIENT_MSG_SMC_MOUSE_SYNC: 3}
MAX_SET_ENCODINGS = 32


def server_init_geometry(raw: bytes) -> dict[str, int]:
    if len(raw) < 20:
        return {}
    return {"width": int.from_bytes(raw[0:2], "big"),
            "height": int.from_bytes(raw[2:4], "big"),
            "pixel_format": raw[4:20].hex()}


def client_message_profile(version: str | None) -> tuple[frozenset[int], dict[int, int]]:
    if version == "RFB 003.008":
        return INSYDE_CLIENT_MESSAGES, dict(INSYDE_MESSAGE_SIZES)
    if version == "RFB 055.008":
        return SMC_CLIENT_MESSAGES, dict(SMC_MESSAGE_SIZES)
    return ALLOWED_CLIENT_MESSAGES, dict(_FIXED_CLIENT_MESSAGE_BYTES)


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

    def feed_messages(self, data: bytes) -> list[bytes]:
        self._buf.extend(data)
        messages: list[bytes] = []
        while self._buf:
            size = self._next_size()
            if size is None or len(self._buf) < size:
                break
            message = bytes(self._buf[:size])
            kind = message[0]
            if kind == CLIENT_MSG_KEY_EVENT:
                self.key_events += 1
            self.client_types[kind] = self.client_types.get(kind, 0) + 1
            del self._buf[:size]
            messages.append(message)
        return messages

    def feed(self, data: bytes) -> bytes:
        return b"".join(self.feed_messages(data))

    def type_summary(self) -> str:
        return ",".join(f"{kind}:{count}" for kind, count in sorted(self.client_types.items()))


class BrowserHandshake:

    SECURITY_TYPE_NONE = 1

    def __init__(self, server_init: bytes, *, challenge: bytes | None = None,
                 version: bytes = RFB_VERSION.encode("ascii"),
                 security_type: int | None = None) -> None:
        if not isinstance(server_init, (bytes, bytearray)) or not server_init:
            raise ValueError("server_init is required")
        if (not isinstance(version, (bytes, bytearray)) or len(version) != RFB_VERSION_BYTES
                or version[:4] != b"RFB " or version[-1:] != b"\n"
                or not all(byte in b"0123456789." for byte in version[4:-1])):
            raise ValueError("invalid_browser_version")
        security_type = SECURITY_TYPE_INSYDE if security_type is None else security_type
        if security_type not in (SECURITY_TYPE_INSYDE, self.SECURITY_TYPE_NONE):
            raise ValueError("unsupported_security_type_config")
        self._security_type = security_type
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
                if self._security_type == self.SECURITY_TYPE_NONE:
                    out += bytes([1, self.SECURITY_TYPE_NONE])
                    self.stage = "security_none"
                else:
                    out += SECURITY_TYPES_FRAME
                    self.stage = "security"
            elif self.stage == "security_none":
                if not self._buf:
                    break
                scheme = self._buf[0]
                del self._buf[:1]
                if scheme != self.SECURITY_TYPE_NONE:
                    raise BrowserHandshakeError("unsupported_security_type")
                out += SECURITY_RESULT_OK
                self.stage = "client_init"
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
                 recovery: RecoveryPolicy | None = None,
                 before_connect=None,
                 require_before_connect: bool = False,
                 input_shaping: InputShapingConfig | None = None) -> None:
        self.upstream = upstream
        self.handshake = handshake
        self.recovery: RecoveryState | None = (
            RecoveryState(recovery, before_connect=before_connect,
                          require_before_connect=require_before_connect)
            if recovery else None)
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
        self._exception_type: str | None = None
        self._shaper = (InputShaper(input_shaping)
                        if input_shaping is not None and input_shaping.enabled else None)
        self._flush_task: asyncio.Task | None = None
        self._recovery_input: list[bytes] = []
        self._client_settings: dict[int, bytes] = {}
        self._client_send_lock = asyncio.Lock()
        self.recovery_input_replayed = 0
        self.recovery_input_dropped = 0
        self.client_bytes = 0
        self.server_bytes = 0
        self.reload_requested = False
        self.reload_reason: str | None = None
        self.geometry_before: dict[str, int] | None = None
        self.geometry_after: dict[str, int] | None = None

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
            messages = self._framer.feed_messages(data)
        except ClientMessageError as exc:
            self.error = exc.code
            self.denied = {"kind": exc.kind, "length": exc.length}
            await self.close(code=1008)
            return False
        for message in messages:
            try:
                outgoing = ([message] if self._shaper is None
                            else self._shaper.feed(message))
            except InputOverflow as exc:
                self.error = exc.code
                await self.close(code=1008)
                return False
            for payload in outgoing:
                try:
                    await self._send_client(payload)
                except Problem:
                    if self.recovery is None or self.recovery.state != "recovering":
                        raise
                    self._hold_during_recovery(payload)
        if self._shaper is not None:
            self._schedule_shaper_flush()
        return True

    async def _send_client(self, payload: bytes) -> None:
        async with self._client_send_lock:
            if self.recovery is not None and self.recovery.state == "recovering":
                self._hold_during_recovery(payload)
                return
            await self.upstream.send_raw(payload)
            if self.recovery is not None and payload[0] in (
                    CLIENT_MSG_SET_PIXEL_FORMAT, CLIENT_MSG_SET_ENCODINGS):
                self._client_settings.pop(payload[0], None)
                self._client_settings[payload[0]] = bytes(payload)

    RECOVERY_INPUT_LIMIT = 64

    def _hold_during_recovery(self, payload: bytes) -> None:
        if is_key_release(payload) and len(self._recovery_input) < self.RECOVERY_INPUT_LIMIT:
            self._recovery_input.append(payload)
            return
        self.recovery_input_dropped += 1
        if self.recovery is not None:
            self.recovery.dropped_input += 1

    async def _replay_recovery_input(self) -> None:
        held, self._recovery_input = self._recovery_input, []
        for payload in held:
            try:
                await self.upstream.send_raw(payload)
                self.recovery_input_replayed += 1
            except Problem:
                self.recovery_input_dropped += 1
                if self.recovery is not None:
                    self.recovery.dropped_input += 1

    def _schedule_shaper_flush(self) -> None:
        if self._shaper is None or self._closed or self._flush_task is not None:
            return
        due = self._shaper.next_due()
        if due is None:
            return
        self._flush_task = asyncio.create_task(self._flush_shaper(due))

    async def _flush_shaper(self, due: float) -> None:
        try:
            await asyncio.sleep(max(0.0, due - time.monotonic()))
            if not self._closed:
                for payload in self._shaper.drain():
                    try:
                        await self._send_client(payload)
                    except Problem:
                        if self.recovery is not None and self.recovery.state == "recovering":
                            self._hold_during_recovery(payload)
        except asyncio.CancelledError:
            raise
        finally:
            self._flush_task = None
            self._schedule_shaper_flush()

    async def _release_held_keys(self) -> None:
        if self._shaper is None:
            return
        for payload in self._shaper.release_all():
            with contextlib.suppress(Exception):
                await self.upstream.send_raw(payload)

    async def send_str(self, data: str) -> None:
        if (getattr(self.handshake, "accepts_text", False)
                and not self.handshake.completed):
            try:
                raw = data.encode("latin-1")
            except UnicodeEncodeError:
                self.error = "unexpected_text_frame"
                await self.close(code=1003)
                return
            await self.send_bytes(raw)
            return
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
                if self.recovery is None:
                    self.error = error or self.error
                    break
                if not self.recovery.may_try(
                        error, getattr(self.upstream, "upstream_close_code", None)):
                    if self.recovery.budget_spent():
                        self.recovery.give_up(error)
                        self.error = "upstream_reconnect_failed"
                    else:
                        self.error = error or self.error
                    break
                if not await self._recover(error):
                    if not self.reload_requested:
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
        self._exception_type = None
        try:
            await self.upstream.relay(self._emit)
        except asyncio.CancelledError:
            raise
        except Problem as exc:
            self._exception_type = type(exc).__name__
            return exc.code
        except Exception as exc:  # noqa: BLE001
            self._exception_type = type(exc).__name__
            return getattr(exc, "code", None) or type(exc).__name__
        return "upstream_closed"

    async def _recover(self, error: str) -> bool:
        state = self.recovery
        assert state is not None
        async with self._client_send_lock:
            state.begin()
        expected = self.handshake._server_init[:20]
        started = time.monotonic()
        await self.upstream.drop_websocket()
        if state.require_before_connect and state.before_connect is None:
            state.fail("operation_permit_invalid")
            state.give_up("operation_permit_invalid")
            return False
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
                decision = await state.before_connect(attempt) if state.before_connect else None
                if decision and float(decision.get("start_deadline") or 0) <= time.time():
                    raise Problem("operation_permit_invalid", 401)
                await self.upstream.reopen(request_frames=False)
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
                state.succeed(int((time.monotonic() - attempt_started) * 1000))
                self.reload_requested = True
                self.reload_reason = "geometry_changed"
                self.geometry_before = server_init_geometry(expected)
                self.geometry_after = server_init_geometry(self.upstream.server_init_raw)
                await self._replay_recovery_input()
                return False
            try:
                async with self._client_send_lock:
                    settings = b"".join(self._client_settings.values())
                    if CLIENT_MSG_SET_ENCODINGS not in self._client_settings:
                        settings += set_encodings()
                    width = int.from_bytes(expected[:2], "big")
                    height = int.from_bytes(expected[2:4], "big")
                    await self.upstream.send_raw(
                        settings + framebuffer_update_request(False, 0, 0, width, height))
                await self.upstream.wait_first_frame(timeout=state.policy.frame_timeout)
            except Problem as exc:
                state.fail(exc.code)
                continue
            except (aiohttp.ClientError, TimeoutError):
                state.fail("upstream_unavailable")
                continue
            async with self._client_send_lock:
                await self._replay_recovery_input()
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
        await self._release_held_keys()
        self._closed = True
        self._client_settings.clear()
        self._room.set()
        if self._flush_task is not None and not self._flush_task.done():
            self._flush_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._flush_task
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
                "exception_type": self._exception_type,
                "recovery_input_replayed": self.recovery_input_replayed,
                "recovery_input_dropped": self.recovery_input_dropped,
                "reload_requested": self.reload_requested,
                "reload_reason": self.reload_reason,
                "geometry_before": self.geometry_before,
                "geometry_after": self.geometry_after,
                "client_message_types": {str(kind): count
                                         for kind, count in self._framer.client_types.items()}}
        if self.recovery is not None:
            data.update(self.recovery.counters())
        if (isinstance(self.denied, dict)
                and isinstance(self.denied.get("kind"), int)
                and isinstance(self.denied.get("length"), int)):
            data["denied"] = {"kind": self.denied["kind"],
                              "length": self.denied["length"]}
        return data
