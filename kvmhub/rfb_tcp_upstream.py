"""Bare-TCP RFB upstream for iDRAC's built-in VNC server."""
from __future__ import annotations

import asyncio
import contextlib
import hashlib
import ipaddress
import re
import socket
import ssl
import struct
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable

from .common import Problem
from .vnc_des import des_ecb_encrypt

RFB_VERSIONS: tuple[str, ...] = ("RFB 003.008", "RFB 003.007", "RFB 003.003")
BROWSER_RFB_VERSION = "RFB 003.008"
RFB_VERSION_BYTES = 12
SECURITY_NONE = 1
SECURITY_VNC_AUTH = 2
SERVERINIT_FIXED_BYTES = 20
MAX_DESKTOP_NAME_BYTES = 4096
MAX_SECURITY_TYPES = 32
MAX_CHUNK_BYTES = 64 * 1024

_HOST = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")


def validate_host(host: str) -> str:
    if not isinstance(host, str) or not host or len(host) > 253:
        raise ValueError("invalid_bmc_host")
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    if not _HOST.fullmatch(host) or any(
            not part or len(part) > 63 or part.startswith("-") or part.endswith("-")
            for part in host.split(".")):
        raise ValueError("invalid_bmc_host")
    return host


def _reverse_bits(byte: int) -> int:
    return int(f"{byte:08b}"[::-1], 2)


def vnc_des_key(password: str) -> bytes:
    if not isinstance(password, str) or not password:
        raise ValueError("empty_vnc_password")
    try:
        raw = password.encode("latin-1")
    except UnicodeEncodeError:  # pragma: no cover - latin-1 encodes every str
        raise ValueError("invalid_vnc_password") from None
    return bytes(_reverse_bits(byte) for byte in raw[:8].ljust(8, b"\x00"))


def vnc_auth_response(challenge: bytes, password: str) -> bytes:
    if not isinstance(challenge, (bytes, bytearray)) or len(challenge) != 16:
        raise ValueError("invalid_challenge")
    key = vnc_des_key(password)
    result = des_ecb_encrypt(bytes(challenge), key)
    assert len(result) == 16
    return result


@dataclass(frozen=True)
class RfbTcpConfig:
    host: str
    password: str
    port: int = 5901
    versions: tuple[str, ...] = RFB_VERSIONS
    tls_enabled: bool = False
    tls_cert_sha256: str = ""
    connect_timeout: float = 5.0
    handshake_timeout: float = 25.0
    max_frame_bytes: int = 8 * 1024 * 1024
    max_total_bytes: int = 512 * 1024 * 1024

    def __post_init__(self) -> None:
        validate_host(self.host)
        if isinstance(self.port, bool) or not isinstance(self.port, int) or not 1 <= self.port <= 65535:
            raise ValueError("invalid_bmc_port")
        if (not isinstance(self.versions, tuple) or not self.versions
                or any(not isinstance(v, str) or not re.fullmatch(r"RFB \d{3}\.\d{3}", v)
                       for v in self.versions)):
            raise ValueError("invalid_protocol_versions")
        if not isinstance(self.tls_enabled, bool):
            raise ValueError("invalid_tls_enabled")
        if (not isinstance(self.tls_cert_sha256, str)
                or (self.tls_cert_sha256 != ""
                    and not re.fullmatch(r"[0-9a-fA-F]{64}", self.tls_cert_sha256))):
            raise ValueError("invalid_tls_cert_sha256")
        if self.tls_enabled and not self.tls_cert_sha256:
            raise ValueError("bmc_cert_pin_required")
        if not isinstance(self.password, str) or not self.password or len(self.password) > 128:
            raise ValueError("invalid_vnc_password")
        for value in (self.connect_timeout, self.handshake_timeout):
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 < value <= 60:
                raise ValueError("invalid_timeout")
        if not 4096 <= self.max_frame_bytes <= 16 * 1024 * 1024:
            raise ValueError("invalid_frame_limit")
        if self.max_frame_bytes > self.max_total_bytes:
            raise ValueError("invalid_budget")

    def __repr__(self) -> str:
        return (f"RfbTcpConfig(host={self.host!r}, port={self.port}, "
                f"tls={self.tls_enabled}, versions={self.versions!r}, "
                f"password=<redacted>)")


HANDSHAKE_STAGES: tuple[str, ...] = (
    "tcp_connect", "greeting", "security_types", "challenge",
    "security_result", "server_init",
)

FAILURE_REASONS = frozenset({
    "tcp_connect_timeout", "tcp_connect_error", "greeting_timeout",
    "greeting_incomplete", "greeting_invalid", "security_types_timeout",
    "security_types_invalid", "security_type_unsupported", "challenge_timeout",
    "challenge_incomplete", "auth_failed", "auth_timeout",
    "server_init_timeout", "server_init_incomplete", "server_init_invalid",
    "budget_exceeded", "tls_cert_pin_mismatch", "closed",
})


@dataclass
class HandshakeTrace:
    stage: str = "tcp_connect"
    elapsed_ms: dict[str, int] = field(default_factory=dict)
    offered_security_types: tuple[int, ...] = ()
    failure_reason: str = ""

    def begin(self, stage: str) -> None:
        self.stage = stage

    def mark(self, stage: str, started: float) -> None:
        if stage in HANDSHAKE_STAGES:
            self.elapsed_ms[stage] = max(0, int((time.monotonic() - started) * 1000))
        self.stage = stage

    def fail(self, reason: str) -> None:
        self.failure_reason = reason if reason in FAILURE_REASONS else "closed"

    def as_dict(self) -> dict[str, Any]:
        return {
            "stage": self.stage,
            "elapsed_ms": dict(self.elapsed_ms),
            "offered_security_types": list(self.offered_security_types),
            "failure_reason": self.failure_reason,
        }


@dataclass
class TcpRelayStats:
    frames: int = 0
    chunks: int = 0
    bytes: int = 0
    protocol_version: str = ""
    security_type: int | None = None
    width: int = 0
    height: int = 0
    trace: HandshakeTrace = field(default_factory=HandshakeTrace)

    def as_dict(self) -> dict[str, Any]:
        return {"frames": self.frames, "chunks": self.chunks, "bytes": self.bytes,
                "protocol_version": self.protocol_version,
                "security_type": self.security_type,
                "width": self.width, "height": self.height,
                "trace": self.trace.as_dict()}


class RfbTcpUpstream:

    def __init__(self, cfg: RfbTcpConfig) -> None:
        self.cfg = cfg
        self.stats = TcpRelayStats()
        self.server_init_raw: bytes = b""
        self.protocol_version: str | None = None
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._send_lock = asyncio.Lock()
        self._closed = False

    def _peer_cert_matches_pin(self) -> bool:
        expected = self.cfg.tls_cert_sha256.lower().replace(":", "")
        if not expected or self._writer is None:
            return False
        ssl_obj = self._writer.get_extra_info("ssl_object")
        if ssl_obj is None:
            return False
        try:
            der = ssl_obj.getpeercert(binary_form=True)
        except (ValueError, OSError):
            return False
        if not der:
            return False
        return hashlib.sha256(der).hexdigest() == expected

    async def connect(self) -> None:
        if self._closed:
            self.stats.trace.fail("closed")
            raise Problem("upstream_unavailable", 502)
        trace = self.stats.trace
        started = time.monotonic()
        try:
            ssl_ctx = None
            server_hostname = None
            if self.cfg.tls_enabled:
                ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ssl_ctx.check_hostname = False
                ssl_ctx.verify_mode = ssl.CERT_NONE
                server_hostname = self.cfg.host
            async with asyncio.timeout(self.cfg.connect_timeout):
                self._reader, self._writer = await asyncio.open_connection(
                    self.cfg.host, self.cfg.port, limit=self.cfg.max_frame_bytes,
                    ssl=ssl_ctx, server_hostname=server_hostname)
            trace.mark("tcp_connect", started)
            if self.cfg.tls_enabled:
                if not self._peer_cert_matches_pin():
                    trace.fail("tls_cert_pin_mismatch")
                    await self.close()
                    raise Problem("bmc_cert_pin_mismatch", 502)
            sock = self._writer.get_extra_info("socket")
            if sock is not None and not self.cfg.tls_enabled:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            async with asyncio.timeout(self.cfg.handshake_timeout):
                await self._handshake()
        except Problem as exc:
            if not trace.failure_reason:
                trace.fail("auth_failed" if exc.code == "bmc_auth_failed" else "closed")
            await self.close()
            raise
        except (asyncio.IncompleteReadError, asyncio.TimeoutError, TimeoutError) as exc:
            phase = trace.stage
            reason = {
                "tcp_connect": "tcp_connect_timeout",
                "greeting": "greeting_incomplete" if isinstance(exc, asyncio.IncompleteReadError) else "greeting_timeout",
                "security_types": "security_types_timeout",
                "challenge": "challenge_incomplete" if isinstance(exc, asyncio.IncompleteReadError) else "challenge_timeout",
                "security_result": "auth_timeout",
                "server_init": "server_init_incomplete" if isinstance(exc, asyncio.IncompleteReadError) else "server_init_timeout",
            }.get(phase, "tcp_connect_timeout")
            trace.fail(reason)
            await self.close()
            raise Problem("upstream_unavailable", 502) from None
        except OSError:
            reason = "tcp_connect_error" if trace.stage == "tcp_connect" else "closed"
            trace.fail(reason)
            await self.close()
            raise Problem("upstream_unavailable", 502) from None

    async def _read_exactly(self, count: int) -> bytes:
        assert self._reader is not None
        if not 0 < count <= self.cfg.max_frame_bytes:
            raise Problem("upstream_handshake_failed", 502)
        return await self._reader.readexactly(count)

    def _handshake_fail(self, stage: str, reason: str) -> Problem:
        self.stats.trace.fail(reason)
        return Problem("bmc_auth_failed" if reason == "auth_failed"
                       else "upstream_handshake_failed", 502)

    async def _handshake(self) -> None:
        assert self._writer is not None
        trace = self.stats.trace

        started = time.monotonic()
        trace.begin("greeting")
        greeting = await self._read_exactly(RFB_VERSION_BYTES)
        version = ""
        if greeting.endswith(b"\n"):
            try:
                version = greeting[:-1].decode("ascii", "strict")
            except UnicodeDecodeError:
                version = ""
        if not version or version not in self.cfg.versions:
            trace.mark("greeting", started)
            raise self._handshake_fail("greeting", "greeting_invalid")
        trace.mark("greeting", started)
        self.protocol_version = version
        self.stats.protocol_version = version
        self._write((version + "\n").encode("ascii"))

        started = time.monotonic()
        trace.begin("security_types")
        legacy_33 = version == "RFB 003.003"
        if legacy_33:
            (offered,) = struct.unpack(">I", await self._read_exactly(4))
            trace.offered_security_types = (offered,)
            trace.mark("security_types", started)
            if offered != SECURITY_VNC_AUTH:
                raise self._handshake_fail("security_types", "security_type_unsupported")
            selected = SECURITY_VNC_AUTH
        else:
            count = (await self._read_exactly(1))[0]
            if not 1 <= count <= MAX_SECURITY_TYPES:
                trace.mark("security_types", started)
                raise self._handshake_fail("security_types", "security_types_invalid")
            types = await self._read_exactly(count)
            trace.offered_security_types = tuple(int(t) for t in types)
            trace.mark("security_types", started)
            if SECURITY_VNC_AUTH in types:
                selected = SECURITY_VNC_AUTH
            elif SECURITY_NONE in types and not self.cfg.password:  # pragma: no cover - password required
                selected = SECURITY_NONE
            else:
                raise self._handshake_fail("security_types", "security_type_unsupported")
            self._write(bytes([selected]))
        self.stats.security_type = selected

        if selected == SECURITY_VNC_AUTH:
            started = time.monotonic()
            trace.begin("challenge")
            challenge = await self._read_exactly(16)
            self._write(vnc_auth_response(challenge, self.cfg.password))
            del challenge
            trace.mark("challenge", started)

            started = time.monotonic()
            trace.begin("security_result")
            result = struct.unpack(">I", await self._read_exactly(4))[0]
            if result != 0:
                if version == "RFB 003.008":
                    length = struct.unpack(">I", await self._read_exactly(4))[0]
                    if length <= MAX_DESKTOP_NAME_BYTES:
                        await self._read_exactly(length)
                trace.mark("security_result", started)
                raise self._handshake_fail("security_result", "auth_failed")
            trace.mark("security_result", started)

        started = time.monotonic()
        trace.begin("server_init")
        self._write(b"\x01")
        fixed = await self._read_exactly(SERVERINIT_FIXED_BYTES)
        name_len = struct.unpack(">I", await self._read_exactly(4))[0]
        if not 0 <= name_len <= MAX_DESKTOP_NAME_BYTES:
            trace.mark("server_init", started)
            raise self._handshake_fail("server_init", "server_init_invalid")
        name = await self._read_exactly(name_len) if name_len else b""
        self.server_init_raw = fixed + struct.pack(">I", name_len) + name
        self.stats.width = struct.unpack(">H", fixed[0:2])[0]
        self.stats.height = struct.unpack(">H", fixed[2:4])[0]
        del name
        trace.mark("server_init", started)

    def _write(self, data: bytes) -> None:
        assert self._writer is not None
        self._writer.write(data)

    async def relay(self, on_bytes: Callable[[bytes], Awaitable[None]]) -> None:
        if self._reader is None or not self.server_init_raw:
            raise Problem("upstream_handshake_failed", 502)
        reader = self._reader
        while True:
            data = await reader.read(MAX_CHUNK_BYTES)
            if not data:
                return
            self.stats.chunks += 1
            self.stats.frames = self.stats.chunks
            self.stats.bytes += len(data)
            if self.stats.bytes > self.cfg.max_total_bytes:
                self.stats.trace.fail("budget_exceeded")
                raise Problem("upstream_budget_exceeded", 502)
            await on_bytes(data)

    async def send_raw(self, data: bytes) -> None:
        if not isinstance(data, (bytes, bytearray, memoryview)) or not data:
            return
        if len(data) > self.cfg.max_frame_bytes:
            raise Problem("upstream_frame_too_large", 502)
        if self._writer is None or self._writer.is_closing():
            raise Problem("upstream_unavailable", 502)
        async with self._send_lock:
            try:
                self._writer.write(bytes(data))
                await asyncio.wait_for(self._writer.drain(), 3.0)
            except (OSError, TimeoutError, asyncio.TimeoutError):
                raise Problem("upstream_unavailable", 502) from None

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        writer, self._writer = self._writer, None
        self._reader = None
        object.__setattr__(self.cfg, "password", "")
        if writer is None:
            return
        writer.close()
        with contextlib.suppress(Exception):
            await asyncio.wait_for(writer.wait_closed(), 3.0)


class StandardRfbBrowserHandshake:

    accepts_text = True

    def __init__(self, server_init: bytes, *, version: bytes = b"RFB 003.008\n") -> None:
        if not isinstance(server_init, (bytes, bytearray)) or len(server_init) < SERVERINIT_FIXED_BYTES + 4:
            raise ValueError("server_init is required")
        if (not isinstance(version, (bytes, bytearray)) or len(version) != RFB_VERSION_BYTES
                or not version.startswith(b"RFB ") or not version.endswith(b"\n")
                or not all(byte in b"0123456789." for byte in version[4:-1])):
            raise ValueError("invalid_browser_version")
        self._version = bytes(version)
        self._server_init = bytes(server_init)
        self._buf = bytearray()
        self.stage = "version"
        self.completed = False

    def start(self) -> bytes:
        if self.stage != "version":
            raise ValueError("handshake already started")
        return self._version

    def feed(self, data: bytes) -> tuple[bytes, bytes]:
        if not isinstance(data, (bytes, bytearray)):
            raise ValueError("data must be bytes")
        if self.completed:
            if len(data) > MAX_DESKTOP_NAME_BYTES * 16:
                raise ValueError("trailing_bytes_too_large")
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
                    raise ValueError("unexpected_client_version")
                out += b"\x01\x01"
                self.stage = "security"
            elif self.stage == "security":
                if not self._buf:
                    break
                if self._buf[0] != SECURITY_NONE:
                    raise ValueError("unsupported_security_type")
                del self._buf[:1]
                out += b"\x00\x00\x00\x00"
                self.stage = "client_init"
            elif self.stage == "client_init":
                if not self._buf:
                    break
                shared = self._buf[0]
                if shared not in (0, 1):
                    raise ValueError("invalid_client_init")
                del self._buf[:1]
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
