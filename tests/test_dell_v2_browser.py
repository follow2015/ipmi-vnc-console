"""Real fixed noVNC build rendering a standard-RFB source (the Dell VNC wire)."""
import asyncio
import os
from pathlib import Path
import shutil
import struct
import time

import pytest
from aiohttp import web, WSMsgType
from aiohttp.test_utils import TestServer

from kvmhub.passthrough import RfbPassthroughSession
from kvmhub.rfb_server import build_server_init_32bpp
from kvmhub.rfb_tcp_upstream import BROWSER_RFB_VERSION, StandardRfbBrowserHandshake
from kvmhub.video import client_v2
from tools.browser_e2e import _find_chromium, _find_playwright

W, H = 64, 64


def _server_init() -> bytes:
    return build_server_init_32bpp(W, H, 'synthetic')


def _frame(rgb: tuple[int, int, int]) -> bytes:
    rect = struct.pack(">HHHHI", 0, 0, W, H, 7)
    return struct.pack(">BBH", 0, 0, 1) + rect + b"\x80" + bytes(rgb)


class SyntheticStandardRfbUpstream:

    def __init__(self) -> None:
        self.server_init_raw = _server_init()
        self.closed = False
        self.started = time.monotonic()
        self._emit = None

    async def relay(self, emit) -> None:
        self._emit = emit
        while not self.closed:
            await asyncio.sleep(0.1)

    async def send_raw(self, payload: bytes) -> None:
        if not payload:
            return
        kind = payload[0]
        if kind != 3 or self._emit is None:
            return
        colour = ((220, 30, 10) if time.monotonic() - self.started < 2.0
                  else (10, 30, 220))
        await self._emit(_frame(colour))

    async def drop_websocket(self) -> None:
        return None

    async def close(self) -> None:
        self.closed = True


async def test_standard_vnc_wire_renders_in_the_fixed_v2_client():
    node = shutil.which('node')
    playwright = os.environ.get('KVM_PLAYWRIGHT') or _find_playwright()
    chrome = os.environ.get('KVM_CHROMIUM') or _find_chromium()
    if not (node and playwright and chrome):
        pytest.skip('Playwright/Chromium required')

    counts = {'closed': 0}
    upstream = SyntheticStandardRfbUpstream()

    async def index(request):
        return web.Response(text=client_v2.HTML, content_type='text/html')

    async def asset(request):
        kind, body = client_v2.fetch(request.path)
        return web.Response(body=body, content_type=kind)

    async def meta(request):
        return web.json_response({'address': 'synthetic-vnc', 'input_protocol': 'standard8'})

    async def keymap(request):
        from kvmhub.platform.text_input import keymap_document
        return web.json_response(keymap_document())

    async def limits(request):
        return web.json_response({'closing': False})

    async def end(request):
        counts['closed'] += 1
        return web.json_response({'ok': True})

    async def console(request):
        session = RfbPassthroughSession(
            upstream,
            StandardRfbBrowserHandshake(
                upstream.server_init_raw,
                version=(BROWSER_RFB_VERSION + '\n').encode('ascii')))
        await session.start()
        ws = web.WebSocketResponse(protocols=['binary'])
        await ws.prepare(request)

        async def incoming():
            async for message in ws:
                if message.type == WSMsgType.BINARY:
                    await session.send_bytes(message.data)

        async def outgoing():
            async for message in session:
                await ws.send_bytes(message.data)

        tasks = [asyncio.create_task(incoming()), asyncio.create_task(outgoing())]
        try:
            done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                task.result()
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            await session.close()
        return ws

    app = web.Application()
    app.router.add_get('/', index)
    app.router.add_get('/_platform/client-v2/{name}', asset)
    app.router.add_get('/_platform/meta', meta)
    app.router.add_get('/_platform/keymap', keymap)
    app.router.add_get('/_platform/limits', limits)
    app.router.add_post('/_platform/close', end)
    app.router.add_get('/console', console)
    try:
        async with TestServer(app) as server:
            process = await asyncio.create_subprocess_exec(node,
                str(Path(__file__).with_name('fixtures') / 'huawei_v2_browser.cjs'),
                str(server.make_url('/')),
                env=dict(os.environ, KVM_PLAYWRIGHT=str(playwright), KVM_CHROMIUM=str(chrome)),
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            try:
                stdout, stderr = await asyncio.wait_for(process.communicate(), 30)
            finally:
                if process.returncode is None:
                    process.kill()
                    await process.wait()
        assert process.returncode == 0, stderr.decode()[-4000:]
        assert b'"first_screen":true' in stdout
        assert b'"incremental":true' in stdout
    finally:
        await upstream.close()
    assert counts['closed'] == 1
