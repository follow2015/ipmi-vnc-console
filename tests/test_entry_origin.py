"""The entry proxy hands the Worker the origin the *browser* used."""
from __future__ import annotations

from types import SimpleNamespace

from aiohttp import WSMsgType, web
from aiohttp.test_utils import TestClient, TestServer

from kvmhub.platform.bus import AssemblyBus
from kvmhub.platform.redis_state import MemoryState
from kvmhub.route_resolver import BUS_KEY, create_app
from kvmhub import worker as worker_module

SID = "b" * 32


async def _resolver(bus):
    app = create_app()
    app[BUS_KEY] = bus
    return TestClient(TestServer(app))


async def _ws_upstream(seen: list[dict]):
    async def handle(request):
        seen.append({"origin": request.headers.get("Origin"),
                     "host": request.headers.get("Host"),
                     "forwarded_host": request.headers.get("X-Forwarded-Host"),
                     "forwarded_proto": request.headers.get("X-Forwarded-Proto")})
        socket = web.WebSocketResponse(protocols=("binary",))
        await socket.prepare(request)
        async for message in socket:
            if message.type is WSMsgType.BINARY:
                break
        await socket.close()
        return socket

    app = web.Application()
    app.router.add_get("/{tail:.*}", handle)
    server = TestServer(app)
    await server.start_server()
    return server


async def test_websocket_relays_the_browser_origin_untouched():
    seen: list[dict] = []
    upstream = await _ws_upstream(seen)
    bus = AssemblyBus(MemoryState())
    await bus.put_route(SID, {"upstream": f"{upstream.host}:{upstream.port}"}, 60)
    try:
        async with await _resolver(bus) as resolver:
            async with resolver.ws_connect(
                    f"/s/{SID}/console", protocols=("binary",),
                    headers={"Cookie": "session=secret", "Origin": "https://kvm.example",
                             "X-Forwarded-Host": "kvm.example",
                             "X-Forwarded-Proto": "https"}) as ws:
                await ws.send_bytes(b"x")
    finally:
        await upstream.close()
    assert seen and seen[0]["origin"] == "https://kvm.example"
    assert seen[0]["forwarded_host"] == "kvm.example"
    assert seen[0]["forwarded_proto"] == "https"


async def test_websocket_without_origin_uses_the_forwarded_host():
    seen: list[dict] = []
    upstream = await _ws_upstream(seen)
    bus = AssemblyBus(MemoryState())
    await bus.put_route(SID, {"upstream": f"{upstream.host}:{upstream.port}"}, 60)
    try:
        async with await _resolver(bus) as resolver:
            async with resolver.ws_connect(
                    f"/s/{SID}/console", protocols=("binary",),
                    headers={"X-Forwarded-Host": "kvm.example"}) as ws:
                await ws.send_bytes(b"x")
    finally:
        await upstream.close()
    assert seen and seen[0]["origin"] == "https://kvm.example"


def test_request_origin_prefers_the_forwarded_host():
    forwarded = SimpleNamespace(headers={"X-Forwarded-Host": "192.0.2.10",
                                         "X-Forwarded-Proto": "https"},
                                host="127.0.0.1:9443")
    assert worker_module.request_origin(forwarded) == "https://192.0.2.10"
    direct = SimpleNamespace(headers={}, host="w1.kvm.example:9443")
    assert worker_module.request_origin(direct) == "https://w1.kvm.example:9443"


def test_console_script_never_hands_novnc_an_empty_port():
    script = worker_module.REAL_CONSOLE_JS
    assert "location.port || (location.protocol === 'https:' ? '443' : '80')" in script
    assert "rfb.connect(location.hostname, location.port," not in script
