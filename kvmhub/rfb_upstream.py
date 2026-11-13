"""Protocol-gateway upstream transport for the measured X10 iKVM/HTML5 console."""
from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import re
import struct
import time
from dataclasses import dataclass, field
from http.cookies import CookieError, SimpleCookie
from typing import Any, Awaitable, Callable, Iterable
from urllib.parse import urlsplit

import aiohttp

from .ast2100_protocol import (
    AUTH_RESPONSE_BYTES,
    CLIENT_MSG_SET_ENCODINGS,
    ENCODING_AST2100,
    RFB_VERSION,
    IncompleteFrame,
    ProtocolError,
    RfbHandshake,
    client_init,
    client_protocol_version,
    client_security_scheme,
    framebuffer_update_request,
    key_event,
    pointer_event,
)
from .common import Problem

MAX_HTML_BYTES = 256 * 1024
MAX_ASSET_BYTES = 4 * 1024 * 1024
MAX_TICKET_CHARS = 24
MIN_TICKET_CHARS = 8
MAX_NAME_CHARS = 128
DEFAULT_ENCODINGS = (ENCODING_AST2100, 1, 2, 5, 7, 0, -223, -239, -224)

_TICKET_ID_FIRST = re.compile(rb"id=[\"']entry_value[\"'][^>]{0,400}?value=[\"']([^\"']{1,80})[\"']")
_TICKET_VALUE_FIRST = re.compile(rb"value=[\"']([^\"']{1,80})[\"'][^>]{0,400}?id=[\"']entry_value[\"']")
_HOSTNAME = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")


def _validate_host(host: str) -> str:
    if not isinstance(host, str) or not host or len(host) > 253:
        raise ValueError("invalid_bmc_host")
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    if not _HOSTNAME.fullmatch(host) or any(
            not label or len(label) > 63 or label.startswith("-") or label.endswith("-")
            for label in host.split(".")):
        raise ValueError("invalid_bmc_host")
    return host


def _validate_path(path: str, *, allow_query: bool) -> str:
    if not isinstance(path, str) or not path or len(path) > 512:
        raise ValueError("invalid_upstream_path")
    if any(ord(c) < 33 or ord(c) > 126 for c in path):
        raise ValueError("invalid_upstream_path")
    if path.startswith("//") or not path.startswith("/"):
        raise ValueError("invalid_upstream_path")
    parsed = urlsplit(path)
    if parsed.scheme or parsed.netloc or parsed.fragment:
        raise ValueError("invalid_upstream_path")
    if any(part in (".", "..") for part in parsed.path.split("/")):
        raise ValueError("invalid_upstream_path")
    if parsed.query and not allow_query:
        raise ValueError("invalid_upstream_path")
    return path


@dataclass(frozen=True)
class UpstreamConfig:

    host: str
    port: int = 443
    scheme: str = "https"
    cert_sha256: str | None = None
    login_path: str = "/cgi/login.cgi"
    logout_path: str = "/cgi/logout.cgi"
    bootstrap_path: str = "/cgi/url_redirect.cgi?url_name=man_ikvm_html5_bootstrap"
    ws_path: str = "/"
    request_timeout: float = 5.0
    handshake_timeout: float = 10.0
    max_frame_bytes: int = 1024 * 1024
    max_total_bytes: int = 64 * 1024 * 1024
    max_frames: int = 4000
    max_redirects: int = 0
    enforce_relay_budget: bool = True
    protocol_versions: tuple[str, ...] = (RFB_VERSION.strip(),)
    keepalive_seconds: float | None = 20.0

    def __post_init__(self) -> None:
        _validate_host(self.host)
        versions = self.protocol_versions
        if (not isinstance(versions, tuple) or not versions
                or any(not isinstance(v, str) or not re.fullmatch(r"RFB \d{3}\.\d{3}", v)
                       for v in versions)
                or len(set(versions)) != len(versions)):
            raise ValueError("invalid_protocol_versions")
        if not isinstance(self.port, int) or isinstance(self.port, bool) or not 1 <= self.port <= 65535:
            raise ValueError("invalid_bmc_port")
        if self.scheme not in ("https", "http"):
            raise ValueError("invalid_scheme")
        if self.scheme == "http" and not ipaddress.ip_address(self.host).is_loopback:
            raise ValueError("plaintext_requires_loopback")
        if self.cert_sha256 is not None:
            digest = self.cert_sha256.replace(":", "").lower()
            if not re.fullmatch(r"[0-9a-f]{64}", digest):
                raise ValueError("invalid_certificate_fingerprint")
            object.__setattr__(self, "cert_sha256", digest)
            if self.scheme != "https":
                raise ValueError("fingerprint_requires_tls")
        for value in (self.request_timeout, self.handshake_timeout):
            if not isinstance(value, (int, float)) or not 0 < value <= 60:
                raise ValueError("invalid_timeout")
        if not 4096 <= self.max_frame_bytes <= 8 * 1024 * 1024:
            raise ValueError("invalid_frame_limit")
        if not 1 <= self.max_frames <= 100000 or not self.max_frame_bytes <= self.max_total_bytes <= 512 * 1024 * 1024:
            raise ValueError("invalid_budget")
        if self.max_redirects != 0:
            raise ValueError("redirects_are_never_followed")
        _validate_path(self.login_path, allow_query=False)
        _validate_path(self.logout_path, allow_query=False)
        _validate_path(self.bootstrap_path, allow_query=True)
        _validate_path(self.ws_path, allow_query=False)
        keepalive = self.keepalive_seconds
        if keepalive is not None and (isinstance(keepalive, bool)
                                      or not isinstance(keepalive, (int, float))
                                      or not 0.1 <= keepalive <= 300):
            raise ValueError("invalid_keepalive")

    @property
    def base_url(self) -> str:
        return f"{self.scheme}://{self.host}:{self.port}"

    def url(self, path: str) -> str:
        return self.base_url + path


def encode_auth_response(ticket: str) -> bytes:
    if not isinstance(ticket, str) or not MIN_TICKET_CHARS <= len(ticket) <= MAX_TICKET_CHARS:
        raise Problem("bmc_auth_failed", 502)
    try:
        raw = ticket.encode("ascii")
    except UnicodeEncodeError:
        raise Problem("bmc_auth_failed", 502) from None
    if any(not 33 <= byte <= 126 for byte in raw):
        raise Problem("bmc_auth_failed", 502)
    return raw[:MAX_TICKET_CHARS].ljust(AUTH_RESPONSE_BYTES, b"\x00")


def extract_ticket(html: bytes) -> str:
    if not isinstance(html, (bytes, bytearray)):
        raise Problem("upstream_invalid_response", 502)
    if len(html) > MAX_HTML_BYTES:
        raise Problem("upstream_invalid_response", 502)
    for pattern in (_TICKET_ID_FIRST, _TICKET_VALUE_FIRST):
        match = pattern.search(bytes(html))
        if match:
            try:
                ticket = match.group(1).decode("ascii")
            except UnicodeDecodeError:
                raise Problem("upstream_invalid_response", 502) from None
            if MIN_TICKET_CHARS <= len(ticket) <= MAX_TICKET_CHARS:
                return ticket
    raise Problem("bmc_auth_failed", 502)


def absorb_set_cookie(values: Iterable[str]) -> dict[str, str]:
    jar: dict[str, str] = {}
    for raw in values:
        if not isinstance(raw, str) or len(raw) > 4096:
            continue
        parsed = SimpleCookie()
        try:
            parsed.load(raw)
        except CookieError:
            continue
        for name, morsel in parsed.items():
            if name and morsel.value:
                jar[name] = morsel.value
    return jar


def set_encodings(encodings=DEFAULT_ENCODINGS) -> bytes:
    values = list(encodings)
    if not 1 <= len(values) <= 32:
        raise ProtocolError("implausible encoding list")
    body = b"".join(struct.pack(">i", value) for value in values)
    return struct.pack(">BBH", CLIENT_MSG_SET_ENCODINGS, 0, len(values)) + body


@dataclass
class RelayStats:
    frames: int = 0
    bytes: int = 0
    framebuffer_updates: int = 0
    rects: int = 0
    payload_bytes: int = 0
    max_frame_bytes: int = 0
    encodings: set[int] = field(default_factory=set)
    modes: set[int] = field(default_factory=set)
    width: int = 0
    height: int = 0
    last_event_at: float = 0.0
    stages: dict[str, int] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {"frames": self.frames, "bytes": self.bytes,
                "framebuffer_updates": self.framebuffer_updates, "rects": self.rects,
                "payload_bytes": self.payload_bytes, "max_frame_bytes": self.max_frame_bytes,
                "encodings": sorted(self.encodings), "modes": sorted(self.modes),
                "width": self.width, "height": self.height,
                "server_message_stages": dict(sorted(self.stages.items()))}


class RfbUpstream:

    def __init__(self, cfg: UpstreamConfig, *, session: aiohttp.ClientSession | None = None,
                 clock=time.monotonic):
        self.cfg = cfg
        self.clock = clock
        self.stats = RelayStats()
        self.server_init = None
        self.protocol_version: str | None = None
        self.server_init_raw: bytes = b""
        self.pending: bytes = b""
        self.upstream_close_code: int | None = None
        self.init_event: dict[str, Any] | None = None
        self._rx = bytearray()
        self._capturing = True
        self._ticket: str | None = None
        self._cookies: dict[str, str] = {}
        self._ws: aiohttp.ClientWebSocketResponse | None = None
        self._parser: RfbHandshake | None = None
        self._closed = False
        self._logged_in = False
        self.last_logout_status: int | None = None
        self._owns_session = session is None
        if session is not None:
            self.http = session
        else:
            self.http = aiohttp.ClientSession(
                connector=self._connector(), cookie_jar=aiohttp.DummyCookieJar(),
                trust_env=False, auto_decompress=False,
                timeout=aiohttp.ClientTimeout(total=None, connect=cfg.request_timeout))

    def _connector(self) -> aiohttp.TCPConnector:
        ssl: Any = None
        if self.cfg.scheme == "https":
            ssl = (aiohttp.Fingerprint(bytes.fromhex(self.cfg.cert_sha256))
                   if self.cfg.cert_sha256 else True)
        return aiohttp.TCPConnector(ssl=ssl, limit=4)

    async def login(self, username: str, password: str) -> None:
        if (not isinstance(username, str) or not username or len(username) > MAX_NAME_CHARS
                or not isinstance(password, str) or not password or len(password) > MAX_NAME_CHARS):
            raise Problem("bmc_auth_failed", 502)
        try:
            async with asyncio.timeout(self.cfg.request_timeout):
                async with self.http.post(
                        self.cfg.url(self.cfg.login_path),
                        data={"name": username, "pwd": password},
                        headers={"Content-Type": "application/x-www-form-urlencoded",
                                 "Referer": self.cfg.base_url + "/",
                                 "Origin": self.cfg.base_url},
                        allow_redirects=False) as response:
                    status = response.status
                    await self._read_body(response, MAX_HTML_BYTES)
                    absorbed = absorb_set_cookie(response.headers.getall("Set-Cookie", []))
        except (aiohttp.ClientError, TimeoutError, asyncio.TimeoutError):
            raise Problem("upstream_unavailable", 502) from None
        if 300 <= status < 400:
            raise Problem("upstream_redirect_denied", 502)
        if status != 200:
            raise Problem("bmc_auth_failed", 502)
        self._cookies = absorbed
        self._logged_in = True

    def _cookie_header(self) -> dict[str, str]:
        if not self._cookies:
            return {}
        return {"Cookie": "; ".join(f"{name}={value}" for name, value in sorted(self._cookies.items()))}

    @staticmethod
    async def _read_body(response: aiohttp.ClientResponse, limit: int) -> bytes:
        declared = response.headers.get("Content-Length")
        if declared is not None:
            if not declared.isdigit() or int(declared) > limit:
                raise Problem("upstream_invalid_response", 502)
        body = await response.read()
        if len(body) > limit:
            raise Problem("upstream_invalid_response", 502)
        return body

    async def read_ticket(self) -> str:
        if not self._logged_in:
            raise Problem("bmc_auth_failed", 502)
        try:
            async with asyncio.timeout(self.cfg.request_timeout):
                async with self.http.get(self.cfg.url(self.cfg.bootstrap_path),
                                         headers=self._cookie_header(),
                                         allow_redirects=False) as response:
                    status = response.status
                    if 300 <= status < 400:
                        raise Problem("bmc_auth_failed", 502)
                    if status != 200:
                        raise Problem("upstream_invalid_response", 502)
                    if response.headers.get("Content-Encoding", "identity").lower() != "identity":
                        raise Problem("upstream_invalid_response", 502)
                    body = await self._read_body(response, MAX_HTML_BYTES)
        except Problem:
            raise
        except (aiohttp.ClientError, TimeoutError, asyncio.TimeoutError):
            raise Problem("upstream_unavailable", 502) from None
        if len(body) > MAX_HTML_BYTES:
            raise Problem("upstream_invalid_response", 502)
        self._ticket = extract_ticket(body)
        return self._ticket

    async def open(self, *, request_frames: bool = True) -> None:
        if self._ticket is None:
            await self.read_ticket()
        try:
            async with asyncio.timeout(self.cfg.handshake_timeout):
                self._ws = await self.http.ws_connect(
                    self.cfg.url(self.cfg.ws_path), protocols=(), compress=0,
                    headers={**self._cookie_header(), "Origin": self.cfg.base_url},
                    max_msg_size=min(self.cfg.max_frame_bytes * 2, 16 * 1024 * 1024),
                    autoping=True, heartbeat=self.cfg.keepalive_seconds,
                    timeout=aiohttp.ClientWSTimeout(ws_close=2))
                await self._handshake(request_frames=request_frames)
        except Problem:
            raise
        except (aiohttp.ClientError, TimeoutError, asyncio.TimeoutError):
            raise Problem("upstream_unavailable", 502) from None

    async def _handshake(self, *, request_frames: bool = True) -> None:
        parser = RfbHandshake(allowed_versions=tuple(
            version + "\n" for version in self.cfg.protocol_versions))
        self._parser = parser
        for expected in ("ProtocolVersion", "Security", "Authentication", "SecurityResult", "ServerInit"):
            event = await self._event(parser, expected)
            if expected == "ProtocolVersion":
                self.protocol_version = event["version"]
                await self._send(client_protocol_version(event["version"]))
            elif expected == "Security":
                await self._send(client_security_scheme())
            elif expected == "Authentication":
                await self._send(encode_auth_response(self._ticket or ""))
                self._ticket = None
            elif expected == "SecurityResult":
                await self._send(client_init(shared=True))
            else:
                self.server_init = parser.server_init
                self.server_init_raw = parser.server_init_raw
                self.pending = bytes(self._rx[event["consumed"]:])
                self._rx.clear()
                self._capturing = False
                self.init_event = {key: event[key] for key in
                                   ("extension_bytes", "video_enable", "kbms_enable",
                                    "kick_user_enable", "vm_enable", "session_id_present")
                                   if key in event}
                self.stats.width = event["width"]
                self.stats.height = event["height"]
                if request_frames:
                    await self._send(set_encodings() + framebuffer_update_request(
                        False, 0, 0, event["width"], event["height"]))

    async def _event(self, parser: RfbHandshake, expected: str) -> dict:
        deadline = self.clock() + self.cfg.handshake_timeout
        while True:
            remaining = deadline - self.clock()
            if remaining <= 0:
                raise Problem("upstream_handshake_failed", 502)
            for event in await self._read(remaining, stop_after=expected):
                if event["stage"] == expected:
                    return event
                if event["stage"] in ("ProtocolVersion", "Security", "Authentication",
                                      "SecurityResult", "ServerInit"):
                    raise Problem("upstream_handshake_failed", 502)

    async def _read(self, timeout: float, *, stop_after: str | None = None) -> list[dict]:
        assert self._ws is not None and self._parser is not None
        try:
            async with asyncio.timeout(timeout):
                message = await self._ws.receive()
        except (TimeoutError, asyncio.TimeoutError):
            raise Problem("upstream_unavailable", 502) from None
        if message.type is aiohttp.WSMsgType.BINARY:
            data = message.data
            if len(data) > self.cfg.max_frame_bytes:
                raise Problem("upstream_frame_too_large", 502)
            self.stats.frames += 1
            self.stats.bytes += len(data)
            self.stats.max_frame_bytes = max(self.stats.max_frame_bytes, len(data))
            if self.stats.frames > self.cfg.max_frames or self.stats.bytes > self.cfg.max_total_bytes:
                raise Problem("upstream_budget_exceeded", 502)
            self.stats.last_event_at = self.clock()
            if self._capturing:
                self._rx.extend(data)
            try:
                events = self._parser.feed(data, stop_after=stop_after)
            except IncompleteFrame:
                return []
            except ProtocolError:
                raise Problem("upstream_handshake_failed", 502) from None
            for event in events:
                self._record(event)
            return events
        if message.type in (aiohttp.WSMsgType.CLOSE, aiohttp.WSMsgType.CLOSING,
                            aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.ERROR):
            raise Problem("upstream_unavailable", 502)
        if message.type is aiohttp.WSMsgType.TEXT:
            raise Problem("upstream_invalid_response", 502)
        return []

    def _record(self, event: dict) -> None:
        stage = event["stage"]
        self.stats.stages[stage] = self.stats.stages.get(stage, 0) + 1
        if stage != "FramebufferUpdate":
            return
        self.stats.framebuffer_updates += 1
        self.stats.rects += event["rects"]
        self.stats.payload_bytes += event["payload_bytes"]
        for header in event["headers"]:
            self.stats.encodings.add(header.encoding)
            self.stats.modes.add(header.mode)

    async def _send(self, data: bytes) -> None:
        if self._ws is None:
            raise Problem("upstream_unavailable", 502)
        try:
            async with asyncio.timeout(self.cfg.request_timeout):
                await self._ws.send_bytes(data)
        except (aiohttp.ClientError, TimeoutError, asyncio.TimeoutError):
            raise Problem("upstream_unavailable", 502) from None

    async def relay(self, on_bytes: Callable[[bytes], Awaitable[None]]) -> None:
        if self._ws is None or self.server_init is None:
            raise Problem("upstream_handshake_failed", 502)
        ws = self._ws
        if self.pending:
            buffered, self.pending = self.pending, b""
            await on_bytes(buffered)
        while True:
            message = await ws.receive()
            if message.type is aiohttp.WSMsgType.BINARY:
                data = message.data
                if len(data) > self.cfg.max_frame_bytes:
                    raise Problem("upstream_frame_too_large", 502)
                self.stats.frames += 1
                self.stats.bytes += len(data)
                self.stats.max_frame_bytes = max(self.stats.max_frame_bytes, len(data))
                self.stats.last_event_at = self.clock()
                if self.cfg.enforce_relay_budget and (
                        self.stats.frames > self.cfg.max_frames
                        or self.stats.bytes > self.cfg.max_total_bytes):
                    raise Problem("upstream_budget_exceeded", 502)
                await on_bytes(data)
            elif message.type is aiohttp.WSMsgType.TEXT:
                raise Problem("upstream_invalid_response", 502)
            elif message.type is aiohttp.WSMsgType.ERROR:
                raise Problem("upstream_unresponsive", 502)
            else:
                if message.type is aiohttp.WSMsgType.CLOSE:
                    self.upstream_close_code = message.data
                elif message.type is aiohttp.WSMsgType.CLOSED:
                    self.upstream_close_code = getattr(self._ws, "close_code", None)
                return

    async def send_raw(self, data: bytes) -> None:
        if not isinstance(data, (bytes, bytearray, memoryview)) or not data:
            return
        if len(data) > self.cfg.max_frame_bytes:
            raise Problem("upstream_frame_too_large", 502)
        await self._send(bytes(data))

    async def fetch_asset(self, path: str, *, max_bytes: int = MAX_ASSET_BYTES) -> tuple[str, bytes]:
        _validate_path(path, allow_query=False)
        if not self._logged_in:
            raise Problem("bmc_auth_failed", 502)
        try:
            async with asyncio.timeout(self.cfg.request_timeout):
                async with self.http.get(
                        self.cfg.url(path),
                        headers={**self._cookie_header(), "Accept-Encoding": "identity"},
                        allow_redirects=False) as response:
                    if response.status != 200:
                        raise Problem("route_denied", 404)
                    if response.headers.get("Content-Encoding", "identity").lower() != "identity":
                        raise Problem("upstream_invalid_response", 502)
                    content_type = (response.headers.get("Content-Type")
                                    or "application/octet-stream").split(";")[0].strip()
                    body = await self._read_body(response, max_bytes)
        except Problem:
            raise
        except (aiohttp.ClientError, TimeoutError, asyncio.TimeoutError):
            raise Problem("upstream_unavailable", 502) from None
        return content_type, body

    def _reset_console_state(self) -> None:
        self._rx.clear()
        self._capturing = True
        self._parser = None
        self.server_init = None
        self.server_init_raw = b""
        self.pending = b""
        self.upstream_close_code = None

    async def drop_websocket(self, code: int = 1000) -> None:
        ws, self._ws = self._ws, None
        self._reset_console_state()
        if ws is None:
            return
        with contextlib.suppress(Exception):
            async with asyncio.timeout(2):
                await ws.close(code=code)

    async def reopen(self, *, request_frames: bool = True) -> None:
        if not self._logged_in:
            raise Problem("bmc_auth_failed", 502)
        await self.drop_websocket()
        self._ticket = None
        await self.open(request_frames=request_frames)

    async def wait_frames(self, count: int = 2, timeout: float = 10.0) -> int:
        if self._ws is None or self.server_init is None:
            raise Problem("upstream_handshake_failed", 502)
        deadline = self.clock() + timeout
        seen = 0
        while seen < count:
            remaining = deadline - self.clock()
            if remaining <= 0:
                raise Problem("upstream_unavailable", 502)
            for event in await self._read(remaining):
                if event["stage"] == "FramebufferUpdate":
                    seen += 1
                    await self._send(framebuffer_update_request(
                        True, 0, 0, self.stats.width, self.stats.height))
        return seen

    async def wait_first_frame(self, timeout: float = 3.0) -> bytes:
        if self.pending:
            return self.pending
        if self._ws is None:
            raise Problem("upstream_handshake_failed", 502)
        try:
            async with asyncio.timeout(timeout):
                while True:
                    message = await self._ws.receive()
                    if message.type is aiohttp.WSMsgType.BINARY:
                        data = message.data
                        if len(data) > self.cfg.max_frame_bytes:
                            raise Problem("upstream_frame_too_large", 502)
                        self.stats.frames += 1
                        self.stats.bytes += len(data)
                        self.stats.max_frame_bytes = max(self.stats.max_frame_bytes, len(data))
                        self.stats.last_event_at = self.clock()
                        self.pending = bytes(data) + self.pending
                        return bytes(data)
                    if message.type is aiohttp.WSMsgType.CLOSE:
                        self.upstream_close_code = message.data
                        raise Problem("upstream_unavailable", 502)
                    if message.type in (aiohttp.WSMsgType.CLOSING, aiohttp.WSMsgType.CLOSED,
                                        aiohttp.WSMsgType.ERROR):
                        self.upstream_close_code = getattr(self._ws, "close_code", None)
                        raise Problem("upstream_unavailable", 502)
                    if message.type is aiohttp.WSMsgType.TEXT:
                        raise Problem("upstream_invalid_response", 502)
        except (TimeoutError, asyncio.TimeoutError):
            raise Problem("upstream_silent", 502) from None

    async def send_pointer(self, x: int, y: int, mask: int = 0) -> None:
        await self._send(pointer_event(x, y, mask))

    async def send_key(self, keysym: int, down: bool) -> None:
        await self._send(key_event(keysym, down))

    async def close(self) -> str:
        if self._closed:
            return "ok"
        self._closed = True
        self._ticket = None
        if self._ws is not None:
            try:
                async with asyncio.timeout(3):
                    await self._ws.close(code=1000)
            except (aiohttp.ClientError, TimeoutError, asyncio.TimeoutError):
                pass
            self._ws = None
        cleaned = "not_needed"
        try:
            if self._logged_in:
                try:
                    async with asyncio.timeout(self.cfg.request_timeout):
                        async with self.http.post(self.cfg.url(self.cfg.logout_path),
                                                  data=b"", headers=self._cookie_header(),
                                                  allow_redirects=False) as response:
                            await response.read()
                            self.last_logout_status = response.status
                            cleaned = "ok" if response.status in (200, 204) else "failed"
                except (aiohttp.ClientError, TimeoutError, asyncio.TimeoutError):
                    cleaned = "failed"
        finally:
            self._logged_in = False
            self._cookies.clear()
            if self._owns_session:
                await self.http.close()
        return cleaned
