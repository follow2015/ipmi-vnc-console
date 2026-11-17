"""Entry route resolver: one Redis GET, no ticket/cookie/tenant unpacking."""
import asyncio

from aiohttp import ClientSession, WSMsgType, web
from aiohttp.test_utils import TestClient, TestServer

from kvmhub.platform.bus import AssemblyBus
from kvmhub.platform.redis_state import MemoryState
from kvmhub.route_resolver import BUS_KEY, create_app

SID = "a" * 32


async def _client(bus=None):
    app = create_app()
    if bus is not None:
        app[BUS_KEY] = bus
    return TestClient(TestServer(app))


async def test_resolver_returns_private_upstream_header():
    bus = AssemblyBus(MemoryState())
    await bus.put_route(SID, {"upstream": "127.0.0.1:29443"}, 60)
    async with await _client(bus) as client:
        response = await client.get("/route/" + SID)
        assert response.status == 200
        assert response.headers["X-Upstream"] == "127.0.0.1:29443"
        assert await response.text() == ""
        assert response.headers["Cache-Control"] == "no-store"


async def test_missing_route_is_denied_fast():
    async with await _client(AssemblyBus(MemoryState())) as client:
        response = await client.get("/route/" + SID)
        assert response.status == 403


async def test_invalid_sid_is_not_looked_up():
    bus = AssemblyBus(MemoryState())
    async with await _client(bus) as client:
        response = await client.get("/route/not-a-session")
        assert response.status == 404


async def test_malicious_upstream_is_never_echoed():
    bus = AssemblyBus(MemoryState())
    await bus.put_route(SID, {"upstream": "8.8.8.8:9443\r\nX-Evil: 1"}, 60)
    async with await _client(bus) as client:
        response = await client.get("/route/" + SID)
        assert response.status == 403
        assert "X-Evil" not in response.headers


async def test_proxy_relays_http_without_rewriting_the_path():
    async def echo(request):
        return web.Response(text=str(request.rel_url))

    upstream_app = web.Application()
    upstream_app.router.add_route("*", "/{tail:.*}", echo)
    upstream = TestServer(upstream_app)
    await upstream.start_server()
    bus = AssemblyBus(MemoryState())
    await bus.put_route(SID, {"upstream": f"{upstream.host}:{upstream.port}"}, 60)
    try:
        async with await _client(bus) as resolver:
            response = await resolver.get(f"/s/{SID}/_platform/meta?t=1")
            assert response.status == 200
            assert await response.text() == f"/s/{SID}/_platform/meta?t=1"
    finally:
        await upstream.close()


async def test_proxy_relays_websocket_cookie_and_frames():
    async def upstream_ws(request):
        if request.cookies.get("session") != "unit-test-token":
            return web.Response(status=401)
        socket = web.WebSocketResponse(protocols=("binary",))
        await socket.prepare(request)
        async for message in socket:
            if message.type is WSMsgType.BINARY:
                await socket.send_bytes(b"echo:" + message.data)
                break
        await socket.close()
        return socket

    upstream_app = web.Application()
    upstream_app.router.add_get("/{tail:.*}", upstream_ws)
    upstream = TestServer(upstream_app)
    await upstream.start_server()
    bus = AssemblyBus(MemoryState())
    await bus.put_route(SID, {"upstream": f"{upstream.host}:{upstream.port}"}, 60)
    try:
        async with await _client(bus) as resolver:
            async with resolver.ws_connect(
                    f"/s/{SID}/console", protocols=("binary",),
                    headers={"Cookie": "session=unit-test-token", "Origin": "https://example.test"}) as ws:
                await ws.send_bytes(b"ping")
                message = await ws.receive()
                assert message.type is WSMsgType.BINARY
                assert message.data == b"echo:ping"
    finally:
        await upstream.close()


async def test_session_prefix_must_start_the_path():
    bus = AssemblyBus(MemoryState())
    await bus.put_route(SID, {"upstream": "127.0.0.1:29443"}, 60)
    async with await _client(bus) as client:
        response = await client.get(f"/evil/s/{SID}/x")
        assert response.status == 404


async def test_oversized_request_body_is_refused_before_forwarding():
    from kvmhub.route_resolver import MAX_REQUEST_BODY

    seen = []

    async def sink(request):
        seen.append(request.path)
        return web.Response(text="ok")

    upstream_app = web.Application()
    upstream_app.router.add_route("*", "/{tail:.*}", sink)
    upstream = TestServer(upstream_app)
    await upstream.start_server()
    bus = AssemblyBus(MemoryState())
    await bus.put_route(SID, {"upstream": f"{upstream.host}:{upstream.port}"}, 60)
    try:
        async with await _client(bus) as resolver:
            response = await resolver.post(
                f"/s/{SID}/up", data=b"x",
                headers={"Content-Length": str(MAX_REQUEST_BODY + 1)})
            assert response.status == 413
            assert seen == []
    finally:
        await upstream.close()


async def test_websocket_relay_ends_when_the_worker_side_closes_first():
    async def upstream_ws(request):
        socket = web.WebSocketResponse()
        await socket.prepare(request)
        await socket.send_bytes(b"hello")
        await socket.close()
        return socket

    upstream_app = web.Application()
    upstream_app.router.add_get("/{tail:.*}", upstream_ws)
    upstream = TestServer(upstream_app)
    await upstream.start_server()
    bus = AssemblyBus(MemoryState())
    await bus.put_route(SID, {"upstream": f"{upstream.host}:{upstream.port}"}, 60)
    try:
        async with await _client(bus) as resolver:
            async with resolver.ws_connect(f"/s/{SID}/console") as ws:
                assert (await ws.receive()).data == b"hello"
                final = await asyncio.wait_for(ws.receive(), 3)
                assert final.type in (WSMsgType.CLOSE, WSMsgType.CLOSED)
    finally:
        await upstream.close()


def test_app_startup_does_not_assign_new_app_keys():
    import warnings

    async def scenario():
        async with await _client(AssemblyBus(MemoryState())):
            pass

    with warnings.catch_warnings():
        warnings.simplefilter("error")
        asyncio.run(scenario())
