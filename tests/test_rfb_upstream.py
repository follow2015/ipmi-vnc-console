"""Tests for the real-device upstream transport against a synthetic BMC."""
from __future__ import annotations

import asyncio
import struct

import pytest
from aiohttp import web

from kvmhub.adapters import SupermicroX10IKVMAdapter
from kvmhub.ast2100_protocol import ENCODING_AST2100
from kvmhub.common import Problem
from kvmhub.rfb_upstream import (
    DEFAULT_ENCODINGS,
    MAX_TICKET_CHARS,
    RfbUpstream,
    UpstreamConfig,
    absorb_set_cookie,
    encode_auth_response,
    extract_ticket,
    set_encodings,
)

TICKET = "TICKET0123456789"
PASSWORD = "synthetic-password"
SERVER_INIT = struct.pack(">HHBBBBHHHBBB3xI", 1024, 768, 32, 24, 0, 1,
                          255, 255, 255, 8, 8, 8, 4) + b"fake"
SERVER_INIT += b"\x00" * 4 + struct.pack(">I", 0x5E5510) + bytes([1, 1, 1, 1])


def parse_client_messages(data: bytes) -> list[tuple]:
    out: list[tuple] = []
    index = 0
    while index < len(data):
        kind = data[index]
        if kind == 2:
            count = struct.unpack_from(">H", data, index + 2)[0]
            values = struct.unpack_from(f">{count}i", data, index + 4)
            out.append(("SetEncodings", values))
            index += 4 + 4 * count
        elif kind == 3:
            incremental, x, y, width, height = struct.unpack_from(">BHHHH", data, index + 1)
            out.append(("FBURequest", incremental, x, y, width, height))
            index += 9
        elif kind == 4:
            down, keysym = struct.unpack_from(">B2xI", data, index + 1)
            out.append(("KeyEvent", down, keysym))
            index += 7
        elif kind == 5:
            mask, x, y = struct.unpack_from(">BHH", data, index + 1)
            out.append(("PointerEvent", mask, x, y))
            index += 5
        elif kind == 0:
            index += 20
        else:
            out.append(("Unknown", kind))
            break
    return out


class FakeBmc:
    def __init__(self, *, ticket: str = TICKET, expect_ticket: str | None = None,
                 password: str = PASSWORD,
                 bootstrap_redirect: bool = False, bootstrap_ticket: bool = True,
                 fail_login_status: int = 200, auth_result: int = 0,
                 oversized_frame: bool = False, text_frame: bool = False,
                 send_updates: int = 2, payload_bytes: int = 32):
        self.ticket, self.password = ticket, password
        self.expect_ticket = ticket if expect_ticket is None else expect_ticket
        self.bootstrap_redirect = bootstrap_redirect
        self.bootstrap_ticket = bootstrap_ticket
        self.fail_login_status = fail_login_status
        self.auth_result = auth_result
        self.oversized_frame = oversized_frame
        self.text_frame = text_frame
        self.send_updates = send_updates
        self.payload_bytes = payload_bytes
        self.ws_headers: dict[str, str] = {}
        self.client_messages: list[tuple] = []
        self.logged_out = False
        self.response_seen: bytes | None = None
        self.ws_started = False
        self.runner: web.AppRunner | None = None
        self.port = 0

    async def start(self) -> "FakeBmc":
        app = web.Application()
        app.router.add_post("/cgi/login.cgi", self.login)
        app.router.add_get("/cgi/url_redirect.cgi", self.bootstrap)
        app.router.add_post("/cgi/logout.cgi", self.logout)
        app.router.add_get("/", self.console)
        self.runner = web.AppRunner(app, access_log=None)
        await self.runner.setup()
        site = web.TCPSite(self.runner, "127.0.0.1", 0)
        await site.start()
        self.port = site._server.sockets[0].getsockname()[1]
        return self

    async def stop(self) -> None:
        assert self.runner is not None
        await self.runner.cleanup()

    async def login(self, request: web.Request) -> web.Response:
        form = await request.post()
        if form.get("name") != "operator" or form.get("pwd") != self.password:
            return web.Response(status=403, text="denied")
        if self.fail_login_status != 200:
            return web.Response(status=self.fail_login_status, text="odd")
        response = web.Response(status=200, text="<html>mainmenu</html>",
                                content_type="text/html")
        response.set_cookie("SID", "session-cookie")
        return response

    async def bootstrap(self, request: web.Request) -> web.Response:
        if request.cookies.get("SID") != "session-cookie":
            return web.Response(status=302, headers={"Location": "/"})
        if self.bootstrap_redirect:
            return web.Response(status=302, headers={"Location": "/cgi/url_redirect.cgi?url_name=mainmenu"})
        if not self.bootstrap_ticket:
            return web.Response(status=200, text="<html>no ticket here</html>",
                                content_type="text/html")
        body = ('<html><input type="hidden" id="entry_value" value="%s">'
                '<canvas id="noVNC_canvas"></canvas></html>' % self.ticket)
        return web.Response(status=200, text=body, content_type="text/html")

    async def logout(self, request: web.Request) -> web.Response:
        self.logged_out = True
        return web.Response(status=204)

    async def console(self, request: web.Request) -> web.StreamResponse:
        self.ws_headers = {key.lower(): value for key, value in request.headers.items()}
        if request.cookies.get("SID") != "session-cookie":
            return web.Response(status=403)
        ws = web.WebSocketResponse(max_msg_size=4 * 1024 * 1024)
        await ws.prepare(request)
        self.ws_started = True
        await ws.send_bytes(b"RFB 055.008\n")
        assert (await self._recv(ws)) == b"RFB 055.008\n"
        await ws.send_bytes(bytes([1, 16]))
        assert (await self._recv(ws)) == bytes([16])
        await ws.send_bytes(b"Z" * 24)
        self.response_seen = await self._recv(ws)
        if self.auth_result or self.response_seen != encode_auth_response(self.expect_ticket):
            await ws.send_bytes(struct.pack(">I", self.auth_result or 1))
            await ws.close()
            return ws
        await ws.send_bytes(struct.pack(">I", 0))
        assert (await self._recv(ws)) == b"\x01"
        await ws.send_bytes(SERVER_INIT)
        self.client_messages.extend(parse_client_messages(await self._recv(ws)))
        for index in range(self.send_updates):
            if self.oversized_frame:
                await ws.send_bytes(b"\x00\x00\x00\x01" + b"\x00" * 1_500_000)
            elif self.text_frame:
                await ws.send_str("rfb text frame")
            else:
                await ws.send_bytes(self._framebuffer_update(index))
        while True:
            try:
                data = await self._recv(ws)
            except (asyncio.TimeoutError, AssertionError, ConnectionError):
                break
            if not data:
                break
            self.client_messages.extend(parse_client_messages(data))
        return ws

    def _framebuffer_update(self, index: int) -> bytes:
        header = struct.pack(">BBH", 0, 0, 1)
        rect = struct.pack(">HHHHiii", 0, 0, 1024, 768, 87, 0, self.payload_bytes)
        return header + rect + bytes([index + 1]) * self.payload_bytes

    @staticmethod
    async def _recv(ws: web.WebSocketResponse) -> bytes:
        message = await ws.receive(timeout=5)
        if message.type is web.WSMsgType.BINARY:
            return message.data
        if message.type is web.WSMsgType.TEXT:
            raise AssertionError("unexpected text frame from client")
        raise ConnectionError("closed")


@pytest.fixture
async def fake_bmc():
    server = await FakeBmc().start()
    try:
        yield server
    finally:
        await server.stop()


def config_for(server: FakeBmc, **overrides) -> UpstreamConfig:
    values = dict(host="127.0.0.1", port=server.port, scheme="http",
                  handshake_timeout=5, request_timeout=5)
    values.update(overrides)
    return UpstreamConfig(**values)


async def opened(server: FakeBmc, **overrides) -> RfbUpstream:
    upstream = RfbUpstream(config_for(server, **overrides))
    await upstream.login("operator", password=server.password)
    await upstream.open()
    return upstream


async def test_handshake_and_first_frames(fake_bmc):
    upstream = await opened(fake_bmc)
    try:
        assert upstream.server_init is not None
        assert (upstream.stats.width, upstream.stats.height) == (1024, 768)
        assert upstream.stats.frames >= 5
        assert await upstream.wait_frames(2, timeout=5) == 2
        assert upstream.stats.framebuffer_updates == 2
        assert upstream.stats.encodings == {87}
        assert upstream.stats.modes == {0}
        assert 87 in next(m for m in fake_bmc.client_messages if m[0] == "SetEncodings")[1]
        request = next(m for m in fake_bmc.client_messages if m[0] == "FBURequest")
        assert request[2:] == (0, 0, 1024, 768)
    finally:
        assert await upstream.close() == "ok"


async def test_ticket_is_single_use_and_never_exposed(fake_bmc):
    upstream = await opened(fake_bmc)
    try:
        assert upstream._ticket is None
        assert fake_bmc.response_seen == encode_auth_response(TICKET)
        assert TICKET not in repr(upstream.stats.as_dict())
        assert "ticket" not in repr(upstream.stats.as_dict()).lower()
        assert TICKET not in repr(vars(upstream.cfg))
    finally:
        await upstream.close()


async def test_no_subprotocol_and_cookie_authenticated_websocket(fake_bmc):
    upstream = await opened(fake_bmc)
    try:
        assert "sec-websocket-protocol" not in fake_bmc.ws_headers
        assert "cookie" in fake_bmc.ws_headers
        assert "sec-websocket-key" in fake_bmc.ws_headers
        assert fake_bmc.ws_headers["origin"] == f"http://127.0.0.1:{fake_bmc.port}"
    finally:
        await upstream.close()


async def test_pointer_and_key_are_relayed(fake_bmc):
    upstream = await opened(fake_bmc)
    try:
        await upstream.send_pointer(640, 400, 1)
        await upstream.send_key(0xFFE1, True)
        await upstream.send_key(0xFFE1, False)
        await upstream.wait_frames(1, timeout=5)
        for _ in range(100):
            if any(m[0] == "KeyEvent" for m in fake_bmc.client_messages):
                break
            await asyncio.sleep(0.02)
        pointer = [m for m in fake_bmc.client_messages if m[0] == "PointerEvent"]
        keys = [m for m in fake_bmc.client_messages if m[0] == "KeyEvent"]
        assert pointer == [("PointerEvent", 1, 640, 400)]
        assert ("KeyEvent", 1, 0xFFE1) in keys and ("KeyEvent", 0, 0xFFE1) in keys
    finally:
        await upstream.close()


async def test_close_logs_out_and_is_idempotent(fake_bmc):
    upstream = await opened(fake_bmc)
    assert await upstream.close() == "ok"
    assert fake_bmc.logged_out is True
    assert await upstream.close() == "ok"


async def test_wrong_ticket_fails_handshake():
    server = await FakeBmc(ticket="OTHERTICKET0001", expect_ticket=TICKET).start()
    try:
        upstream = RfbUpstream(config_for(server))
        await upstream.login("operator", password=PASSWORD)
        with pytest.raises(Problem) as excinfo:
            await upstream.open()
        assert excinfo.value.code in ("bmc_auth_failed", "upstream_handshake_failed")
        assert await upstream.close() in ("ok", "not_needed")
    finally:
        await server.stop()


async def test_auth_result_rejected():
    server = await FakeBmc(auth_result=2).start()
    try:
        upstream = RfbUpstream(config_for(server))
        await upstream.login("operator", password=PASSWORD)
        with pytest.raises(Problem):
            await upstream.open()
        await upstream.close()
    finally:
        await server.stop()


async def test_login_rejected(fake_bmc):
    upstream = RfbUpstream(config_for(fake_bmc))
    with pytest.raises(Problem) as excinfo:
        await upstream.login("operator", password="wrong")
    assert excinfo.value.code == "bmc_auth_failed"
    assert await upstream.close() == "not_needed"


async def test_login_non_200():
    server = await FakeBmc(fail_login_status=500).start()
    try:
        upstream = RfbUpstream(config_for(server))
        with pytest.raises(Problem) as excinfo:
            await upstream.login("operator", password=PASSWORD)
        assert excinfo.value.code == "bmc_auth_failed"
        await upstream.close()
    finally:
        await server.stop()


async def test_bootstrap_redirect_means_unauthenticated():
    server = await FakeBmc(bootstrap_redirect=True).start()
    try:
        upstream = RfbUpstream(config_for(server))
        await upstream.login("operator", password=PASSWORD)
        with pytest.raises(Problem) as excinfo:
            await upstream.open()
        assert excinfo.value.code == "bmc_auth_failed"
        await upstream.close()
    finally:
        await server.stop()


async def test_bootstrap_without_ticket():
    server = await FakeBmc(bootstrap_ticket=False).start()
    try:
        upstream = RfbUpstream(config_for(server))
        await upstream.login("operator", password=PASSWORD)
        with pytest.raises(Problem) as excinfo:
            await upstream.open()
        assert excinfo.value.code == "bmc_auth_failed"
        await upstream.close()
    finally:
        await server.stop()


async def test_oversized_upstream_frame():
    server = await FakeBmc(oversized_frame=True).start()
    try:
        upstream = RfbUpstream(config_for(server))
        await upstream.login("operator", password=PASSWORD)
        await upstream.open()
        with pytest.raises(Problem) as excinfo:
            await upstream.wait_frames(1, timeout=5)
        assert excinfo.value.code == "upstream_frame_too_large"
        await upstream.close()
    finally:
        await server.stop()


async def test_text_frame_rejected():
    server = await FakeBmc(text_frame=True).start()
    try:
        upstream = RfbUpstream(config_for(server))
        await upstream.login("operator", password=PASSWORD)
        await upstream.open()
        with pytest.raises(Problem) as excinfo:
            await upstream.wait_frames(1, timeout=5)
        assert excinfo.value.code == "upstream_invalid_response"
        await upstream.close()
    finally:
        await server.stop()


async def test_frame_budget_is_enforced():
    server = await FakeBmc().start()
    try:
        upstream = await opened(server, max_frames=5)
        with pytest.raises(Problem) as excinfo:
            await upstream.wait_frames(1, timeout=5)
        assert excinfo.value.code == "upstream_budget_exceeded"
        await upstream.close()
    finally:
        await server.stop()


async def test_unreachable_websocket_is_reported():
    server = await FakeBmc().start()
    try:
        upstream = RfbUpstream(config_for(server, ws_path="/missing"))
        await upstream.login("operator", password=PASSWORD)
        with pytest.raises(Problem) as excinfo:
            await upstream.open()
        assert excinfo.value.code in ("upstream_unavailable", "upstream_invalid_response")
        await upstream.close()
    finally:
        await server.stop()


async def test_handshake_timeout_is_bounded():
    server = await FakeBmc().start()
    try:
        upstream = RfbUpstream(config_for(server, handshake_timeout=0.2))
        await upstream.login("operator", password=PASSWORD)
        upstream.cfg.__class__
        upstream._ticket = TICKET
        upstream._ws = _SilentSocket()
        with pytest.raises(Problem) as excinfo:
            await upstream._handshake()
        assert excinfo.value.code in ("upstream_handshake_failed", "upstream_unavailable")
        await upstream.close()
    finally:
        await server.stop()


class _SilentSocket:
    async def receive(self):
        await asyncio.sleep(1)
        return type("Message", (), {"type": web.WSMsgType.CLOSE, "data": b""})()

    async def close(self, code=1000):
        return None


def test_config_rejects_dangerous_combinations():
    with pytest.raises(ValueError):
        UpstreamConfig(host="10.0.0.1", scheme="http")
    with pytest.raises(ValueError):
        UpstreamConfig(host="10.0.0.1", scheme="http", cert_sha256="a" * 64)
    with pytest.raises(ValueError):
        UpstreamConfig(host="10.0.0.1", login_path="/cgi/../cgi/login.cgi")
    with pytest.raises(ValueError):
        UpstreamConfig(host="10.0.0.1", login_path="/cgi/login.cgi?x=1")
    with pytest.raises(ValueError):
        UpstreamConfig(host="10.0.0.1", max_redirects=1)
    with pytest.raises(ValueError):
        UpstreamConfig(host="10.0.0.1", port=0)
    with pytest.raises(ValueError):
        UpstreamConfig(host="10.0.0.1", max_frame_bytes=1024)
    with pytest.raises(ValueError):
        UpstreamConfig(host="10.0.0.1", cert_sha256="zz")
    with pytest.raises(ValueError):
        UpstreamConfig(host="")
    assert UpstreamConfig(host="127.0.0.1", port=8443, scheme="http").base_url == "http://127.0.0.1:8443"


def test_absorb_set_cookie_keeps_exactly_one_live_sid():
    measured = ["SID=; expires=Thursday,01-Jan-1970 00:00:00 GMT; Secure; HttpOnly",
                "SID=live-session; path=/; Secure; HttpOnly"]
    assert absorb_set_cookie(measured) == {"SID": "live-session"}
    assert absorb_set_cookie(["SID=a", "SID=b"]) == {"SID": "b"}
    assert absorb_set_cookie(["malformed", "", "x=" * 5000]) == {}
    assert absorb_set_cookie([]) == {}


def test_extract_ticket_variants():
    assert extract_ticket(b'<input id="entry_value" value="ABCDEFGH12">') == "ABCDEFGH12"
    assert extract_ticket(b"<input value='ABCDEFGH12' id='entry_value'>") == "ABCDEFGH12"
    with pytest.raises(Problem):
        extract_ticket(b"<html>nothing</html>")
    with pytest.raises(Problem):
        extract_ticket(b'<input id="entry_value" value="short">')
    with pytest.raises(Problem):
        extract_ticket(b'<input id="entry_value" value="' + b"A" * (MAX_TICKET_CHARS + 1) + b'">')


def test_encode_auth_response_matches_measured_shape():
    assert encode_auth_response("ABCDEFGH") == b"ABCDEFGH" + b"\x00" * 40
    assert len(encode_auth_response("A" * 24)) == 48
    with pytest.raises(Problem):
        encode_auth_response("short")
    with pytest.raises(Problem):
        encode_auth_response("A" * 25)
    with pytest.raises(Problem):
        encode_auth_response("TICKET\x01VALUE")


def test_set_encodings_wire_format():
    data = set_encodings((87, 0))
    assert data[:4] == bytes([2, 0, 0, 2])
    assert struct.unpack_from(">2i", data, 4) == (87, 0)
    with pytest.raises(Exception):
        set_encodings(())


def test_transport_defaults_match_the_adapter_console_spec():
    spec = SupermicroX10IKVMAdapter().console_spec()
    config = UpstreamConfig(host="192.0.2.11")
    assert config.login_path == spec.login_path
    assert config.bootstrap_path == spec.entry_path
    assert config.ws_path == spec.websocket_path
    assert config.port == spec.websocket_port
    assert {"https": "wss", "http": "ws"}[config.scheme] == spec.websocket_scheme
    assert ENCODING_AST2100 in DEFAULT_ENCODINGS
    assert spec.max_frame_bytes >= config.max_frame_bytes
