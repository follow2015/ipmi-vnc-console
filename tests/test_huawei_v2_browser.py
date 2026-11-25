"""Real standard client -> V1 bridge -> real child, with synthetic JPEG source."""
import asyncio
import os
from pathlib import Path
import shutil

import pytest
from aiohttp import web, WSMsgType
from aiohttp.test_utils import TestServer

from kvmhub.video import client_v2
from kvmhub.video.huawei_session import HuaweiV1RfbSession
from kvmhub.video.runtime import ManagedDecoder
from kvmhub.video.synthetic import jpeg_block
from tools.browser_e2e import _find_chromium, _find_playwright


async def test_standard_client_renders_full_and_incremental_through_v1_bridge(monkeypatch):
    node = shutil.which('node')
    playwright = os.environ.get('KVM_PLAYWRIGHT') or _find_playwright()
    chrome = os.environ.get('KVM_CHROMIUM') or _find_chromium()
    if not (node and playwright and chrome):
        pytest.skip('Playwright/Chromium required')
    header, red = jpeg_block((220, 30, 10))
    _, blue = jpeg_block((10, 30, 220))
    monkeypatch.setattr('kvmhub.video.huawei_session.jpeg_header', lambda q: header)
    counts = {'input': 0, 'closed': 0, 'frames': 0, 'ledger': None}
    class Source:
        tag_id = 1
        async def frames(self):
            for index in range(100):
                yield (red if index < 10 else blue), 64, 64, 0
                await asyncio.sleep(.05)
        async def send_input(self, packet):
            counts['input'] += 1
    async def permit():
        return None
    async def index(request):
        return web.Response(text=client_v2.HTML, content_type='text/html')
    async def asset(request):
        typ, body = client_v2.fetch(request.path)
        return web.Response(body=body, content_type=typ)
    async def meta(request):
        return web.json_response({'address': 'synthetic'})
    async def keymap(request):
        from kvmhub.platform.text_input import keymap_document
        return web.json_response(keymap_document())
    async def end(request):
        counts['closed'] += 1
        return web.json_response({'ok': True})
    async def limits(request):
        return web.json_response({'closing': False})
    async def console(request):
        bridge = HuaweiV1RfbSession(Source(), 64, 64, before_resync=permit,
            decoder=ManagedDecoder(require_hard_cpu_limit=False,
                before_resync=permit, require_resync_permit=True))
        await bridge.start()
        ws = web.WebSocketResponse(protocols=['binary'])
        await ws.prepare(request)
        async def incoming():
            async for message in ws:
                if message.type == WSMsgType.BINARY:
                    await bridge.send_bytes(message.data)
        async def outgoing():
            async for message in bridge:
                async with asyncio.timeout(bridge.send_timeout):
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
            counts['frames'] = bridge.frames
            await bridge.close()
            counts['ledger'] = bridge.video.decoder.ledger.memory
        return ws
    app = web.Application()
    app.router.add_get('/', index)
    app.router.add_get('/_platform/client-v2/{name}', asset)
    app.router.add_get('/_platform/meta', meta)
    app.router.add_get('/_platform/keymap', keymap)
    app.router.add_get('/_platform/limits', limits)
    app.router.add_post('/_platform/close', end)
    app.router.add_get('/console', console)
    async with TestServer(app) as server:
        process = await asyncio.create_subprocess_exec(node,
            str(Path(__file__).with_name('fixtures') / 'huawei_v2_browser.cjs'),
            str(server.make_url('/')), env=dict(os.environ, KVM_PLAYWRIGHT=str(playwright),
                KVM_CHROMIUM=str(chrome)), stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), 30)
        finally:
            if process.returncode is None:
                process.kill()
                await process.wait()
        assert process.returncode == 0, stderr.decode()[-4000:]
    assert counts['frames'] > 10 and counts['input'] >= 10
    assert counts['closed'] == 1 and counts['ledger'] == 0
