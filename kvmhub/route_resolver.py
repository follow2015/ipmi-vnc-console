"""Fixed-Host entry proxy for deployments without OpenResty/Lua."""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import re

from aiohttp import ClientSession, ClientTimeout, TCPConnector, WSMsgType, web

from .platform.bus import AssemblyBus
from .platform.redis_state import create_state

SID_RE = re.compile(r"[0-9a-f]{32}\Z")
SESSION_PATH_RE = re.compile(r"/s/([0-9a-f]{32})(?:/|\Z)")
DEFAULT_PORT = 18081
log = logging.getLogger("kvmhub.route_resolver")

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


async def upstream_for(request: web.Request, sid: str) -> str:
    route = await request.app["bus"].get_route(sid)
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
    target = f"http://{upstream}{request.rel_url}"
    headers = _forward_headers(request.headers)
    body = request.content if request.can_read_body else None
    async with request.app["client"].request(
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
    browser = web.WebSocketResponse(protocols=offered, autoping=False, heartbeat=None)
    await browser.prepare(request)
    target = f"ws://{upstream}{request.rel_url}"
    headers = {"Origin": f"https://{upstream}"}
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

    async with request.app["client"].ws_connect(
            target, protocols=offered, headers=headers,
            autoping=False, heartbeat=None) as worker:
        await asyncio.gather(browser_to_worker(), worker_to_browser(),
                             return_exceptions=True)
    return browser


async def proxy(request: web.Request) -> web.StreamResponse:
    match = SESSION_PATH_RE.search(request.path)
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
    app["bus"] = bus
    app["state"] = state
    app["client"] = None
    app.router.add_get("/route/{sid}", resolve)
    app.router.add_route("*", "/{tail:.*}", proxy)

    async def open_client(_app: web.Application) -> None:
        app["client"] = ClientSession(connector=TCPConnector(limit=0),
                                      timeout=ClientTimeout(total=None))

    async def close_resources(_app: web.Application) -> None:
        if app["client"] is not None:
            await app["client"].close()
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
