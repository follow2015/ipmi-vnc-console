"""A synthetic BMC with injectable faults."""
from __future__ import annotations

import asyncio
import struct

from aiohttp import web

from kvmhub.rfb_upstream import RfbUpstream, UpstreamConfig, encode_auth_response


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
            index += 10
        elif kind == 4:
            down, keysym = struct.unpack_from(">B2xI", data, index + 1)
            out.append(("KeyEvent", down, keysym))
            index += 8
        elif kind == 5:
            mask, x, y = struct.unpack_from(">BHH", data, index + 1)
            out.append(("PointerEvent", mask, x, y))
            index += 6
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
                 send_updates: int = 2, payload_bytes: int = 32,
                 version: bytes = b"RFB 055.008\n", silent: bool = False,
                 drop_after_frames: int | None = None, close_code: int = 1011,
                 abort: bool = False, stall_after_frames: int | None = None,
                 stall_seconds: float = 0.0, resize_after_frames: int | None = None,
                 resize_to: tuple[int, int] = (640, 480),
                 drop_connections: int = 1, server_init_after: bytes | None = None):
        self.ticket, self.password = ticket, password
        self.version = version
        self.client_version: bytes | None = None
        self.expect_ticket = ticket if expect_ticket is None else expect_ticket
        self.bootstrap_redirect = bootstrap_redirect
        self.bootstrap_ticket = bootstrap_ticket
        self.fail_login_status = fail_login_status
        self.auth_result = auth_result
        self.oversized_frame = oversized_frame
        self.text_frame = text_frame
        self.send_updates = send_updates
        self.payload_bytes = payload_bytes
        self.silent = silent
        self.drop_after_frames = drop_after_frames
        self.close_code = close_code
        self.abort = abort
        self.drop_connections = drop_connections
        self.server_init = SERVER_INIT
        self.server_init_after = server_init_after
        self.stall_after_frames = stall_after_frames
        self.stall_seconds = stall_seconds
        self.resize_after_frames = resize_after_frames
        self.resize_to = resize_to
        self._silent_stop = asyncio.Event()
        self.ws_headers: dict[str, str] = {}
        self.client_messages: list[tuple] = []
        self.console_opens = 0
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
        self._silent_stop.set()
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
        ws = web.WebSocketResponse(max_msg_size=4 * 1024 * 1024, autoping=not self.silent)
        await ws.prepare(request)
        self.ws_started = True
        self.console_opens += 1
        opens = self.console_opens
        await ws.send_bytes(self.version)
        self.client_version = await self._recv(ws)
        assert self.client_version == self.version
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
        init = self.server_init if (self.server_init_after is None or opens == 1) else self.server_init_after
        await ws.send_bytes(init)
        if self.silent:
            await self._silent_stop.wait()
            return ws
        self.client_messages.extend(parse_client_messages(await self._recv(ws)))
        for index in range(self.send_updates):
            if self.stall_after_frames is not None and index >= self.stall_after_frames:
                await asyncio.sleep(self.stall_seconds)
            size = (self.resize_to
                    if self.resize_after_frames is not None and index >= self.resize_after_frames
                    else None)
            if self.oversized_frame:
                await ws.send_bytes(b"\x00\x00\x00\x01" + b"\x00" * 1_500_000)
            elif self.text_frame:
                await ws.send_str("rfb text frame")
            else:
                await ws.send_bytes(self._framebuffer_update(index, size))
            if (self.drop_after_frames is not None and index + 1 >= self.drop_after_frames
                    and opens <= self.drop_connections):
                if self.abort:
                    request.transport.abort()
                    return ws
                await ws.close(code=self.close_code, message=b"injected drop")
                return ws
        while True:
            try:
                data = await self._recv(ws)
            except (asyncio.TimeoutError, AssertionError, ConnectionError):
                break
            if not data:
                break
            self.client_messages.extend(parse_client_messages(data))
        return ws

    def _framebuffer_update(self, index: int, size: tuple[int, int] | None = None) -> bytes:
        width, height = size or (1024, 768)
        header = struct.pack(">BBH", 0, 0, 1)
        rect = struct.pack(">HHHHiii", 0, 0, width, height, 87, 0, self.payload_bytes)
        return header + rect + bytes([index + 1]) * self.payload_bytes

    @staticmethod
    async def _recv(ws: web.WebSocketResponse) -> bytes:
        message = await ws.receive(timeout=5)
        if message.type is web.WSMsgType.BINARY:
            return message.data
        if message.type is web.WSMsgType.TEXT:
            raise AssertionError("unexpected text frame from client")
        raise ConnectionError("closed")


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
