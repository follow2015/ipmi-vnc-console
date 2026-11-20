"""Fixed-Host entry proxy for deployments without OpenResty/Lua."""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import re

from aiohttp import (ClientError, ClientSession, ClientTimeout, TCPConnector,
                     WSMsgType, WSServerHandshakeError, web)

from .platform.bus import AssemblyBus
from .platform.redis_state import create_state

SID_RE = re.compile(r"[0-9a-f]{32}\Z")
SESSION_PATH_RE = re.compile(r"/s/([0-9a-f]{32})(?:/|\Z)")
MAX_REQUEST_BODY = 16 * 1024 * 1024
DEFAULT_PORT = 18081
log = logging.getLogger("kvmhub.route_resolver")

BUS_KEY = web.AppKey("bus", AssemblyBus)
STATE_KEY = web.AppKey("state", object)
CLIENTS_KEY = web.AppKey("clients", dict)

HOP_BY_HOP = frozenset({
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "transfer-encoding", "upgrade",
})


def valid_upstream(value: object) -> str:
    if not isinstance(value, str):
        return ""
    try:
        address_text, port_text = value.rsplit(":", 1)
        address = ipaddress.ip_address(address_text)
        port = int(port_text)
        if address.version != 4 or not (address.is_private or address.is_loopback):
            return ""
        if not 1 <= port <= 65535:
            return ""
    except (ValueError, TypeError):
        return ""
    return f"{address}:{port}"


def client_of(app: web.Application) -> ClientSession:
    client = app[CLIENTS_KEY].get("main")
    if client is None:
        raise web.HTTPServiceUnavailable()
    return client


async def upstream_for(request: web.Request, sid: str) -> str:
    route = await request.app[BUS_KEY].get_route(sid)
    upstream = valid_upstream((route or {}).get("upstream"))
    log.info("route lookup sid=%s upstream=%r", sid, upstream)
    return upstream


async def resolve(request: web.Request) -> web.Response:
    sid = request.match_info["sid"]
    if not SID_RE.fullmatch(sid):
        raise web.HTTPNotFound()
    upstream = await upstream_for(request, sid)
    if not upstream:
        raise web.HTTPForbidden()
    return web.Response(text="", headers={
        "X-Upstream": upstream,
        "Cache-Control": "no-store",
    })


def _forward_headers(headers) -> dict[str, str]:
    return {name: value for name, value in headers.items()
            if name.lower() not in HOP_BY_HOP and name.lower() != "host"}


async def proxy_http(request: web.Request, sid: str, upstream: str) -> web.StreamResponse:
    declared = request.headers.get("Content-Length", "")
    if declared and (not declared.isdigit() or int(declared) > MAX_REQUEST_BODY):
        raise web.HTTPRequestEntityTooLarge(
            max_size=MAX_REQUEST_BODY,
            actual_size=int(declared) if declared.isdigit() else 0)
    target = f"http://{upstream}{request.rel_url}"
    headers = _forward_headers(request.headers)
    body = request.content if request.can_read_body else None
    async with client_of(request.app).request(
            request.method, target, headers=headers, data=body,
            allow_redirects=False) as response:
        reply = web.StreamResponse(
            status=response.status,
            headers=_forward_headers(response.headers),
        )
        await reply.prepare(request)
        async for chunk in response.content.iter_chunked(65536):
            await reply.write(chunk)
        await reply.write_eof()
        return reply


async def proxy_websocket(request: web.Request, sid: str, upstream: str) -> web.WebSocketResponse:
    offered = tuple(item.strip() for item in
                    request.headers.get("Sec-WebSocket-Protocol", "").split(",")
                    if item.strip())
    target = f"ws://{upstream}{request.rel_url}"
    headers = {}
    if request.headers.get("Origin"):
        headers["Origin"] = request.headers["Origin"]
    else:
        host = request.headers.get("X-Forwarded-Host") or upstream
        headers["Origin"] = f"https://{host}"
    for name in ("X-Forwarded-Host", "X-Forwarded-Proto", "X-Forwarded-For"):
        if request.headers.get(name):
            headers[name] = request.headers[name]
    if request.headers.get("Cookie"):
        headers["Cookie"] = request.headers["Cookie"]

    async def browser_to_worker():
        async for message in browser:
            if message.type is WSMsgType.BINARY:
                await worker.send_bytes(message.data)
            elif message.type is WSMsgType.TEXT:
                await worker.send_str(message.data)
            elif message.type is WSMsgType.CLOSE:
                await worker.close()
                break
            elif message.type is WSMsgType.ERROR:
                break

    async def worker_to_browser():
        async for message in worker:
            if message.type is WSMsgType.BINARY:
                await browser.send_bytes(message.data)
            elif message.type is WSMsgType.TEXT:
                await browser.send_str(message.data)
            elif message.type is WSMsgType.CLOSE:
                await browser.close(code=message.data or 1000)
                break
            elif message.type is WSMsgType.ERROR:
                break

    try:
        worker_cm = client_of(request.app).ws_connect(
            target, protocols=offered, headers=headers,
            autoping=True, heartbeat=None)
        worker = await worker_cm.__aenter__()
    except WSServerHandshakeError as exc:
        log.warning("worker websocket handshake rejected sid=%s status=%s message=%s",
                    sid, exc.status, str(exc.message)[:256])
        if exc.status == 401:
            raise web.HTTPUnauthorized(text="worker rejected the console") from None
        if exc.status == 403:
            raise web.HTTPForbidden(text="worker rejected the console") from None
        raise web.HTTPBadGateway(text="worker unavailable") from None
    except (ClientError, OSError) as exc:
        log.warning("worker websocket unavailable sid=%s error=%s", sid,
                    str(exc)[:256])
        raise web.HTTPBadGateway(text="worker unavailable") from None
    try:
        agreed = (worker.protocol,) if worker.protocol else ()
        browser = web.WebSocketResponse(protocols=agreed, autoping=True,
                                        heartbeat=None)
        await browser.prepare(request)
        tasks = [asyncio.ensure_future(browser_to_worker()),
                 asyncio.ensure_future(worker_to_browser())]
        try:
            await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
        if not browser.closed:
            await browser.close()
        return browser
    finally:
        await worker_cm.__aexit__(None, None, None)


async def proxy(request: web.Request) -> web.StreamResponse:
    match = SESSION_PATH_RE.match(request.path)
    sid = match.group(1) if match else ""
    if not sid:
        raise web.HTTPNotFound()
    upstream = await upstream_for(request, sid)
    if not upstream:
        raise web.HTTPNotFound()
    if request.headers.get("Upgrade", "").lower() == "websocket":
        return await proxy_websocket(request, sid, upstream)
    return await proxy_http(request, sid, upstream)


def create_app(redis_url: str = "") -> web.Application:
    state = create_state(redis_url)
    bus = AssemblyBus(state)
    app = web.Application()
    app[BUS_KEY] = bus
    app[STATE_KEY] = state
    app[CLIENTS_KEY] = {}
    app.router.add_get("/route/{sid}", resolve)
    app.router.add_route("*", "/{tail:.*}", proxy)

    async def open_client(_app: web.Application) -> None:
        app[CLIENTS_KEY]["main"] = ClientSession(
            connector=TCPConnector(limit=0),
            timeout=ClientTimeout(total=None))

    async def close_resources(_app: web.Application) -> None:
        client = app[CLIENTS_KEY].pop("main", None)
        if client is not None:
            await client.close()
        await state.close()

    app.on_startup.append(open_client)
    app.on_cleanup.append(close_resources)
    return app


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
    try:
        import uvloop
    except ImportError:
        pass
    else:
        uvloop.install()
    port = int(os.getenv("KVMHUB_ROUTE_RESOLVER_PORT", str(DEFAULT_PORT)))
    web.run_app(create_app(os.getenv("KVMHUB_REDIS_URL", "")),
                host="127.0.0.1", port=port)


if __name__ == "__main__":
    main()
