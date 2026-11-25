"""Real shipped noVNC decodes the candidate encoder over a local synthetic WS."""
import asyncio
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct

import pytest
from aiohttp import web, WSMsgType
from aiohttp.test_utils import TestServer

from kvmhub.client_assets import ASSET_DIR, KNOWN_ASSETS
from kvmhub.passthrough import BrowserHandshake, ClientMessageFramer
from kvmhub.rfb_server import RFB_PIXEL_FORMAT_32BPP, build_server_init_32bpp
from kvmhub.video.encoding import encode_snapshot
from kvmhub.video.framebuffer import Fill, Framebuffer, Raw, Rect, Update
from kvmhub.video.requests import RequestStream
from tools.browser_e2e import _find_chromium, _find_playwright


async def test_shipped_client_decodes_tight_without_replacing_client_bundle():
    node = shutil.which('node')
    playwright = os.environ.get('KVM_PLAYWRIGHT') or _find_playwright()
    chromium = os.environ.get('KVM_CHROMIUM') or _find_chromium()
    if not (node and playwright and chromium):
        pytest.skip('Playwright/Chromium required')
    fb = Framebuffer(128, 128)
    red, blue = b'\x00\x00\xff\x00', b'\xff\x00\x00\x00'
    fb.apply(Update(1, 1, (Raw(Rect(0, 0, 128, 128), (red + blue) * (128 * 64)),)))
    counts = {'requests': 0, 'updates': 0, 'tight': 0, 'pixel_format': False}
    scripts = ['util.js','webutil.js','base64.js','websock.js','des.js','keysymdef.js',
               'keyboard.js','input.js','display.js','jsunzip.js','ast2100.js','rfb.js','keysym.js']
    html = '<!doctype html><canvas id="screen" width="128" height="128"></canvas>'
    html += ''.join('<script src="/assets/' + name + '"></script>' for name in scripts)
    html += '<script src="/viewer.js"></script>'

    async def assets(request):
        name = request.match_info['name']
        if name not in KNOWN_ASSETS:
            raise web.HTTPNotFound()
        return web.Response(body=(ASSET_DIR / name).read_bytes(), content_type='application/javascript')

    async def index(request):
        return web.Response(text=html, content_type='text/html')

    async def viewer(request):
        return web.Response(text='''
window.viewer = new RFB({target:document.getElementById('screen'),encrypt:false,
  shared:true,view_only:false,true_color:true,wsProtocols:['binary'],onUpdateState:function(){},
  onFBResize:function(client){
    // This vendor fork omits automatic SetEncodings. Exercise its existing
    // decoder with an explicit negotiation using its own message builder.
    client._sock.send(RFB.messages.clientEncodings(client._encodings,false,true));
  }});
window.viewer.connect(location.hostname, location.port, '', '', 'console');
''', content_type='application/javascript')

    async def console(request):
        ws = web.WebSocketResponse(protocols=['binary'])
        await ws.prepare(request)
        handshake = BrowserHandshake(build_server_init_32bpp(128, 128, 'synthetic'),
            version=b'RFB 003.008\n', security_type=BrowserHandshake.SECURITY_TYPE_NONE)
        framer, client = ClientMessageFramer(), RequestStream(fb)
        await ws.send_bytes(handshake.start())
        tight = False
        async for message in ws:
            if message.type != WSMsgType.BINARY:
                continue
            data = message.data
            if not handshake.completed:
                response, data = handshake.feed(data)
                if response:
                    await ws.send_bytes(response)
                if not handshake.completed:
                    continue
            for packet in framer.feed_messages(data):
                if packet[0] == 0:
                    counts['pixel_format'] = packet[4:] == RFB_PIXEL_FORMAT_32BPP
                elif packet[0] == 2:
                    tight = 7 in struct.unpack('>' + 'i' * ((len(packet) - 4) // 4), packet[4:])
                elif packet[0] == 3:
                    counts['requests'] += 1
                    if counts['updates'] == 1:
                        event = Update(1, 2, (Fill(Rect(0, 0, 16, 16), blue),))
                        fb.apply(event); client.changed(event)
                    _, incremental, x, y, w, h = struct.unpack('>BBHHHH', packet)
                    client.request(Rect(x, y, w, h), incremental=bool(incremental))
                    batch = client.prepare()
                    if batch:
                        for snapshot in batch.snapshots:
                            for payload in encode_snapshot(snapshot, tight=tight):
                                counts['tight'] += int(struct.unpack('>i', payload[12:16])[0] == 7)
                                await ws.send_bytes(payload)
                        client.sent(batch)
                        counts['updates'] += 1
        return ws

    app = web.Application()
    app.router.add_get('/', index)
    app.router.add_get('/viewer.js', viewer)
    app.router.add_get('/assets/{name}', assets)
    app.router.add_get('/console', console)
    async with TestServer(app) as server:
        proc = await asyncio.create_subprocess_exec(node,
            str(Path(__file__).with_name('fixtures') / 'video_pipeline_browser.cjs'),
            str(server.make_url('/')), env=dict(os.environ, KVM_PLAYWRIGHT=str(playwright),
            KVM_CHROMIUM=str(chromium)), stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), 30)
        finally:
            if proc.returncode is None:
                proc.kill(); await proc.wait()
        assert proc.returncode == 0, str(counts) + stderr.decode()[-2500:]
    result = json.loads(stdout)
    assert not result['errors']
    assert counts['requests'] >= 2 and counts['updates'] == 2 and counts['tight'] > 0
    assert counts['pixel_format']
    bgrx = fb.snapshot(Rect(0, 0, 128, 128)).pixels
    rgba = bytearray(len(bgrx))
    rgba[0::4], rgba[1::4], rgba[2::4] = bgrx[2::4], bgrx[1::4], bgrx[0::4]
    rgba[3::4] = b'\xff' * (128 * 128)
    assert result['sha256'] == hashlib.sha256(rgba).hexdigest()
