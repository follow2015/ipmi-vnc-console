"""Synthetic BMC. It does not implement any vendor's console protocol."""
import asyncio
import secrets

from aiohttp import WSMsgType, web

STATS_KEY = web.AppKey("stats", dict)
TOKENS_KEY = web.AppKey("tokens", set)


def create_mock(username, password):
    tokens = set()
    stats = {"logins": 0, "logouts": 0, "inputs": 0}

    async def login(request):
        data = await request.json()
        if data != {"username": username, "password": password}:
            return web.json_response({"error": "authentication_failed"}, status=401)
        token = secrets.token_urlsafe(32)
        tokens.add(token)
        stats["logins"] += 1
        response = web.json_response({"token": token}, status=201)
        response.set_cookie("UPSTREAM_SECRET", token, httponly=True, secure=True)
        return response

    async def logout(request):
        token = request.headers.get("X-Mock-Session")
        if token not in tokens:
            raise web.HTTPUnauthorized()
        tokens.discard(token)
        stats["logouts"] += 1
        return web.Response(status=204)

    async def console(request):
        if request.headers.get("X-Mock-Session") not in tokens:
            raise web.HTTPUnauthorized()
        ws = web.WebSocketResponse(protocols=("binary",), max_msg_size=1024*1024, heartbeat=20)
        await ws.prepare(request)

        async def frames():
            seq = 0
            while not ws.closed:
                await ws.send_bytes(f"SYNTHETIC BMC CONSOLE\nFrame {seq}\nKeyboard events received: {stats['inputs']}\nNo connection to physical hardware".encode())
                seq += 1
                await asyncio.sleep(0.5)

        task = asyncio.create_task(frames())
        try:
            async for msg in ws:
                if msg.type == WSMsgType.BINARY:
                    stats["inputs"] += 1
                    await ws.send_bytes(b"INPUT ACK\n" + msg.data[:64])
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        return ws

    app = web.Application(client_max_size=4096)
    app[STATS_KEY] = stats
    app[TOKENS_KEY] = tokens
    app.router.add_post("/session", login)
    app.router.add_delete("/session", logout)
    app.router.add_get("/console", console)
    return app
