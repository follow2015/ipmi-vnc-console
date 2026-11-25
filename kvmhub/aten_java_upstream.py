"""ATEN Java-launcher tickets over pinned HTTPS, private RFB over TCP."""
from __future__ import annotations

import asyncio
import contextlib
import re
import struct
from urllib.parse import urlsplit
from xml.etree import ElementTree as ET

import aiohttp

from .ast2100_protocol import parse_server_init, parse_server_init_extension
from .common import (Problem, aten_http_codebase_hosts_from_env,
                     require_controlled_host)
from .rfb_protocol import SupermicroProtocol

JAVA_LAUNCH_PATH = "/cgi/url_redirect.cgi?url_name=ikvm&url_type=jwsk"
MAX_HTTP_BYTES = 512 * 1024
RFB_VERSION = b"RFB 003.008\n"


def parse_java_launch(body: bytes, host: str, *, allow_http_codebase: bool = False) -> tuple[str, str]:
    if (len(body) > MAX_HTTP_BYTES or b"\0" in body
            or re.search(rb"<!\s*(?:DOCTYPE|ENTITY)", body, re.I)):
        raise ValueError("invalid_java_launch")
    try:
        root = ET.fromstring(body)
        codebase = urlsplit(root.get("codebase", ""))
        app = root.find("application-desc")
        args = [node.text or "" for node in app.findall("argument")] if app is not None else []
        secure_codebase = (codebase.scheme == "https" and codebase.port in (None, 443))
        allowed_http_codebase = (
            allow_http_codebase and codebase.scheme == "http" and codebase.port == 80)
        valid = (
            root.tag == "jnlp" and (secure_codebase or allowed_http_codebase)
            and codebase.hostname == host
            and codebase.username is None and codebase.password is None
            and codebase.path in ("", "/") and not codebase.query and not codebase.fragment
            and app is not None and app.get("main-class") == "tw.com.aten.ikvm.KVMMain"
            and len(args) in (10, 11) and args[0] == host
            and args[4] == "5900"
            and args[8] in (("0", "1") if allow_http_codebase else ("0",))
            and all(re.fullmatch(r"[A-Za-z0-9_-]{16}", value) for value in args[1:3])
        )
    except (ET.ParseError, ValueError, TypeError):
        valid = False
    if not valid:
        raise ValueError("invalid_java_launch")
    return args[1], args[2]


class AtenJavaUpstream:

    def __init__(self, host: str, fingerprint: str, *, networks,
                 allow_http_codebase: bool | None = None) -> None:
        require_controlled_host(host, networks)
        if not isinstance(fingerprint, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", fingerprint):
            raise Problem("invalid_target_policy", 502)
        self.host = host
        self.allow_http_codebase = (
            host in aten_http_codebase_hosts_from_env()
            if allow_http_codebase is None else bool(allow_http_codebase))
        self._fingerprint = bytes.fromhex(fingerprint)
        self._http: aiohttp.ClientSession | None = None
        self._cookies: dict[str, str] = {}
        self._login_attempted = False
        self._login_response_received = False
        self._identity_rejected = False
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._send_lock = asyncio.Lock()
        self.server_init_raw = b""
        self.protocol_version = "RFB 003.008"
        self.cleanup_outcome: str | None = None

    async def _request(self, path: str, *, method="GET", data=None) -> tuple[int, bytes]:
        assert self._http is not None
        headers = {"Origin": f"https://{self.host}", "Referer": f"https://{self.host}/"}
        if self._cookies:
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in self._cookies.items())
        async with self._http.request(method, f"https://{self.host}{path}",
                                      data=data, headers=headers, allow_redirects=False) as response:
            self._cookies.update(SupermicroProtocol().absorb_cookies(
                response.headers.getall("Set-Cookie", [])))
            if path == "/cgi/login.cgi":
                self._login_response_received = True
            body = bytearray()
            async for chunk in response.content.iter_chunked(16384):
                body.extend(chunk)
                if len(body) > MAX_HTTP_BYTES:
                    raise Problem("upstream_invalid_response", 502)
            return response.status, bytes(body)

    async def login(self, username: str, password: str) -> None:
        if self._http is not None:
            raise Problem("connection_limit", 409)
        if not username or not password:
            raise Problem("credential_unavailable", 503)
        self._http = aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(ssl=aiohttp.Fingerprint(self._fingerprint), limit=2),
            cookie_jar=aiohttp.DummyCookieJar(), timeout=aiohttp.ClientTimeout(total=8))
        self._login_attempted = True
        try:
            async with asyncio.timeout(24):
                status, _ = await self._request("/cgi/login.cgi", method="POST",
                                                data={"name": username, "pwd": password})
                if status != 200 or not self._cookies:
                    raise Problem("bmc_auth_failed", 502)
                status, body = await self._request(JAVA_LAUNCH_PATH)
                if status != 200:
                    raise Problem("upstream_invalid_response", 502)
                try:
                    ticket_user, ticket_password = parse_java_launch(
                        body, self.host, allow_http_codebase=self.allow_http_codebase)
                except ValueError:
                    raise Problem("upstream_invalid_response", 502) from None
                body = b""
                self._reader, self._writer = await asyncio.open_connection(self.host, 5900)
                if await self._read(12) != RFB_VERSION:
                    raise Problem("upstream_handshake_failed", 502)
                await self.send_raw(RFB_VERSION)
                count = (await self._read(1))[0]
                if not 1 <= count <= 32 or 16 not in await self._read(count):
                    raise Problem("upstream_handshake_failed", 502)
                await self.send_raw(b"\x10")
                await self._read(24)
                await self.send_raw(ticket_user.encode("ascii").ljust(24, b"\0")
                                    + ticket_password.encode("ascii").ljust(24, b"\0"))
                ticket_user = ticket_password = ""
                if await self._read(4) != bytes(4):
                    raise Problem("bmc_auth_failed", 502)
                await self.send_raw(b"\0")
                fixed = await self._read(24)
                name_length = struct.unpack_from(">I", fixed, 20)[0]
                if name_length > 4096:
                    raise Problem("upstream_handshake_failed", 502)
                raw = fixed + await self._read(name_length + 12)
                try:
                    parse_server_init(raw[:-12])
                    flags = parse_server_init_extension(raw[-12:])
                except ValueError:
                    raise Problem("upstream_handshake_failed", 502) from None
                if not flags["video_enable"] or not flags["kbms_enable"]:
                    raise Problem("upstream_handshake_failed", 502)
                self.server_init_raw = raw
        except Problem:
            raise
        except aiohttp.ServerFingerprintMismatch:
            self._identity_rejected = True
            raise Problem("upstream_unavailable", 502) from None
        except (OSError, aiohttp.ClientError, TimeoutError, asyncio.IncompleteReadError):
            raise Problem("upstream_unavailable", 502) from None

    async def _read(self, size: int) -> bytes:
        assert self._reader is not None
        return await self._reader.readexactly(size)

    async def send_raw(self, data: bytes) -> None:
        if self._writer is None or self._writer.is_closing():
            raise Problem("upstream_unavailable", 502)
        try:
            async with self._send_lock, asyncio.timeout(8):
                self._writer.write(data)
                await self._writer.drain()
        except (OSError, TimeoutError):
            raise Problem("upstream_unavailable", 502) from None

    async def relay(self, emit) -> None:
        if self._reader is None:
            raise Problem("upstream_unavailable", 502)
        try:
            while data := await self._reader.read(65536):
                await emit(data)
        except OSError:
            raise Problem("upstream_unavailable", 502) from None

    async def close(self) -> bool:
        if self._writer is not None:
            self._writer.close()
            with contextlib.suppress(OSError, TimeoutError):
                await asyncio.wait_for(self._writer.wait_closed(), 2)
            self._writer = None
        self._reader = None
        if self._http is None:
            return not self._login_attempted or self.cleanup_outcome == "confirmed"
        confirmed = False
        try:
            if self._login_attempted and self._cookies:
                status, _ = await self._request("/cgi/logout.cgi", method="POST")
                check, body = await self._request("/cgi/url_redirect.cgi?url_name=mainmenu")
                confirmed = status == 200 and check == 200 and bool(re.search(
                    rb"SessionTimeout\s*\(|session.?timeout|(?:action|href)=[\"'](?:/cgi/)?login\.cgi",
                    body, re.I))
            elif not self._cookies:
                confirmed = self._identity_rejected or self._login_response_received
        except (OSError, aiohttp.ClientError, TimeoutError, Problem):
            confirmed = False
        finally:
            await self._http.close()
            self._http = None
            self._cookies.clear()
            self.server_init_raw = b""
        self.cleanup_outcome = "confirmed" if confirmed else "unconfirmed"
        return confirmed
