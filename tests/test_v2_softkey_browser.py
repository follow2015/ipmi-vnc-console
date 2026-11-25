"""Real noVNC 1.7 client exercising the V2-native soft keyboard."""
import asyncio
from collections import Counter
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


async def test_v2_softkey_sends_paired_public_rfb_key_events(monkeypatch):
    node = shutil.which('node')
    playwright = os.environ.get('KVM_PLAYWRIGHT') or _find_playwright()
    chrome = os.environ.get('KVM_CHROMIUM') or _find_chromium()
    if not (node and playwright and chrome):
        pytest.skip('Playwright/Chromium required')
    header, red = jpeg_block((220, 30, 10))
    _, blue = jpeg_block((10, 30, 220))
    monkeypatch.setattr('kvmhub.video.huawei_session.jpeg_header', lambda q: header)
    counts = {'input': 0, 'rfb_messages': [], 'closed': 0, 'frames': 0}

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

    async def keymap(request):
        from kvmhub.platform.text_input import keymap_document
        return web.json_response(keymap_document())

    async def limits(request):
        return web.json_response({'closing': False})

    async def end(request):
        counts['closed'] += 1
        return web.json_response({'ok': True})

    async def console(request):
        bridge = HuaweiV1RfbSession(Source(), 64, 64, before_resync=permit,
            decoder=ManagedDecoder(require_hard_cpu_limit=False,
                before_resync=permit, require_resync_permit=True))
        original_input = bridge._input

        async def capture(message):
            counts['rfb_messages'].append(bytes(message))
            await original_input(message)

        bridge._input = capture
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
        return ws

    app = web.Application()
    app.router.add_get('/', index)
    app.router.add_get('/_platform/client-v2/{name}', asset)
    app.router.add_get('/_platform/keymap', keymap)
    app.router.add_get('/_platform/limits', limits)
    app.router.add_post('/_platform/close', end)
    app.router.add_get('/console', console)
    async with TestServer(app) as server:
        process = await asyncio.create_subprocess_exec(node,
            str(Path(__file__).with_name('fixtures') / 'v2_softkey_browser.cjs'),
            str(server.make_url('/')), env=dict(os.environ, KVM_PLAYWRIGHT=str(playwright),
                KVM_CHROMIUM=str(chrome)), stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), 60)
        finally:
            if process.returncode is None:
                process.kill()
                await process.wait()
        assert process.returncode == 0, (stdout.decode()[-2000:] + stderr.decode()[-4000:])

    key_events = [p for p in counts['rfb_messages'] if len(p) == 8 and p[0] == 4]
    down = [p for p in key_events if p[1] & 1]
    up = [p for p in key_events if not p[1] & 1]
    assert len(down) >= 6, [(len(p), list(p[:12])) for p in counts['rfb_messages']]
    assert len(down) == len(up), key_events
    assert Counter(p[4:8] for p in down) == Counter(p[4:8] for p in up), key_events
    assert counts['closed'] == 1
