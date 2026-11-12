import asyncio
import contextlib
import html
import logging
import secrets
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import parse_qs

import aiohttp
from aiohttp import WSMsgType, web
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from .adapter import MockAdapter
from .adapters.passthrough import ASSET_PATH as PASSTHROUGH_ASSET_PATH
from .adapters.passthrough import PassthroughAdapter
from .common import (HOST_LABEL, PASSTHROUGH_ADAPTER_ID, SESSION_END_CODES,
                     WORKER_HOST_SUFFIX, Problem, client_tls, digest, user_message,
                     verify)

SESSION_KEY = web.RequestKey("session_id", str)

log = logging.getLogger("kvmhub.worker")

REPORT_RETRY_FIRST = 0.5
REPORT_RETRY_MAX = 30.0

CONNECTION_LIMIT = 4


def connection_limit(adapter) -> int:
    return min(CONNECTION_LIMIT, getattr(adapter, "connection_limit", CONNECTION_LIMIT))


class ManagerRejected(Problem):

    def __init__(self, code: str, upstream_status: int):
        super().__init__(code)
        self.upstream_status = upstream_status

    @property
    def permanent(self) -> bool:
        return 400 <= self.upstream_status < 500 and self.upstream_status not in (408, 429)


def cookie_max_age(hard_until: float, now: float) -> int:
    return max(1, min(14400, int(hard_until - now)))


def upstream_end_reason(upstream) -> str:
    error = getattr(upstream, "error", None)
    return "upstream_unresponsive" if error == "upstream_unresponsive" else "upstream_error"


CONSOLE_HTML = """<!doctype html><html lang="zh-CN"><meta charset="utf-8"><title>模拟 KVM 控制台</title>
<style>body{background:#101c2c;color:#e6eef8;font:16px system-ui;padding:30px}canvas{border:1px solid #456;max-width:100%;background:#08111e}button{padding:10px;margin:10px}#status{min-height:24px}</style>
<h1>模拟 KVM 控制台</h1><p>画面和按键由本机模拟设备产生，不代表真机 KVM 兼容性。</p>
<p id="status">正在连接…</p><canvas id="screen" width="800" height="420" tabindex="0"></canvas>
<p>点击画面后按键可验证输入通道。<button id="close">结束会话</button></p><script src="/_platform/console.js"></script></html>"""
CONSOLE_JS = """const status=document.querySelector('#status'), canvas=document.querySelector('canvas'), ctx=canvas.getContext('2d');let stopped=false;
const ws=new WebSocket('wss://'+location.host+'/console',['binary']);ws.binaryType='arraybuffer';
ws.onopen=()=>{status.textContent='已连接模拟设备';canvas.focus();};
ws.onmessage=e=>{const s=new TextDecoder().decode(e.data);ctx.fillStyle='#08111e';ctx.fillRect(0,0,800,420);ctx.fillStyle='#70dda4';ctx.font='20px monospace';s.split('\\n').forEach((line,i)=>ctx.fillText(line,28,55+i*36));};
ws.onerror=()=>{status.textContent='连接失败，请返回 Manager 查看会话状态。';};
ws.onclose=()=>{status.textContent=stopped?'会话已结束':'连接已断开。请返回 Manager 查看状态并重新申请。';};
canvas.onkeydown=e=>{e.preventDefault();if(ws.readyState===WebSocket.OPEN)ws.send(new TextEncoder().encode(e.key));};
document.querySelector('#close').onclick=async()=>{stopped=true;await fetch('/_platform/close',{method:'POST'});ws.close();};"""

REAL_CONSOLE_HTML = """<!doctype html><html lang="zh-CN"><meta charset="utf-8">
<title>真机 KVM 控制台</title>
<style>
:root{color-scheme:dark}
body{margin:0;background:#0b1220;color:#e6eef8;font:15px/1.5 system-ui,sans-serif;display:flex;flex-direction:column;height:100vh}
header{display:flex;gap:14px;align-items:center;padding:10px 16px;background:#111c2e;border-bottom:1px solid #24344d}
header strong{font-weight:600;white-space:nowrap}
#status{color:#8fb6e8;font-size:13px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
#spacer{flex:1}
#stage{flex:1;display:flex;align-items:flex-start;justify-content:flex-start;overflow:auto;padding:12px;min-height:0}
canvas{background:#000;outline:none;flex:none}
button{font:inherit;padding:6px 14px;border-radius:6px;border:1px solid #3b5a86;background:#1d2f4a;color:#e6eef8;cursor:pointer;white-space:nowrap}
button:hover{background:#25405f}
footer{padding:8px 16px;font-size:12px;color:#7288a6;border-top:1px solid #24344d}
</style>
<header><strong>真机 KVM 控制台</strong><span id="status">正在连接…</span><span id="spacer"></span><button id="close">结束会话</button></header>
<div id="stage"><canvas id="screen" width="1024" height="768" tabindex="0"></canvas></div>
<footer>画面与键鼠经平台网关原样转发；BMC 票据、Cookie 与凭据不下发浏览器。本页不提供电源、重置或用户管理入口。</footer>
<script src="/novnc/include/util.js"></script>
<script src="/novnc/include/webutil.js"></script>
<script src="/novnc/include/base64.js"></script>
<script src="/novnc/include/websock.js"></script>
<script src="/novnc/include/des.js"></script>
<script src="/novnc/include/keysymdef.js"></script>
<script src="/novnc/include/keyboard.js"></script>
<script src="/novnc/include/input.js"></script>
<script src="/novnc/include/display.js"></script>
<script src="/novnc/include/jsunzip.js"></script>
<script src="/novnc/include/ast2100.js"></script>
<script src="/novnc/include/rfb.js"></script>
<script src="/novnc/include/keysym.js"></script>
<script src="/_platform/console.js"></script>
</html>"""

REAL_CONSOLE_JS = """'use strict';
(function () {
  var status = document.getElementById('status');
  var canvas = document.getElementById('screen');
  var ended = false;
  var explained = false;
  // A failing console keeps a short breadcrumb of what it displayed and when.
  // Without it, "the tab just said 'failed'" is all support ever gets.
  var log = window.__kvmStatusLog = [];
  function setStatus(text) {
    log.push([Date.now(), text]);
    if (log.length > 20) log.shift();
    status.textContent = text;
    status.title = text;
  }
  function explain(text) { explained = true; setStatus(text); }

  function describe(counts) {
    if (counts.connections + counts.opening >= counts.limit) {
      explain('此会话的控制台连接已达上限（' + counts.limit + '）。通常是同一会话开了多个标签页；关闭其它标签页后刷新本页。');
      return true;
    }
    return false;
  }
  // The upgrade's 429 is unreadable from the page, and the measured client only
  // reports "failed" after about 17 seconds. Asking first avoids both: the
  // operator is told at once, and no doomed handshake is sent to the BMC.
  function askThenConnect() {
    fetch('/_platform/limits', { cache: 'no-store' }).then(function (response) {
      if (response.status === 401) {
        explain('会话已结束或已失效（可能被撤销、租约到期或凭据过期）。请返回 Manager 查看状态后重新申请。');
        return null;
      }
      return response.ok ? response.json() : null;
    }).then(function (counts) {
      if (!counts) { start(); return; }
      log.push([Date.now(), 'limits ' + JSON.stringify(counts)]);
      if (!describe(counts)) start();
    }).catch(function () { start(); });
  }
  // After a connection is up this only fires when the session ends underneath
  // the page, which is where the 401 branch above earns its keep.
  function recheck() {
    if (ended || explained) return;
    fetch('/_platform/limits', { cache: 'no-store' }).then(function (response) {
      if (response.status === 401) {
        explain('会话已结束或已失效（可能被撤销、租约到期或凭据过期）。请返回 Manager 查看状态后重新申请。');
        return null;
      }
      return response.ok ? response.json() : null;
    }).then(function (counts) { if (counts) describe(counts); }).catch(function () {});
  }

  var rfb;
  function start() {
    try {
      rfb = new RFB({
        target: canvas, encrypt: true, shared: true, view_only: false,
        wsProtocols: ['binary'], true_color: true, local_cursor: true,
        onUpdateState: function (client, state, old, message) {
          if (state === 'normal') { explained = false; setStatus(state); canvas.focus(); return; }
          if (explained) return;
          setStatus(state + (message ? ' · ' + message : ''));
          if (state === 'failed' || state === 'disconnected') recheck();
        },
        // The measured client dereferences the return value of this callback
        // whenever the Insyde extension is active; the default noop returns
        // undefined and silently drops every pointer event.
        onMouseMove: function (x, y) { return { x: x, y: y }; },
        onDesktopName: function (client, name) { document.title = name + ' · 真机 KVM'; },
        onFBResize: function (client, width, height) { canvas.width = width; canvas.height = height; }
      });
    } catch (error) { setStatus('初始化失败：' + error); return; }
    window.__kvm = rfb;
    rfb.connect(location.hostname, location.port, '000000000000000000000000',
                '000000000000000000000000', 'console');
  }
  askThenConnect();
  function endSession() {
    ended = true;
    if (rfb) { try { rfb.disconnect(); } catch (error) {} }
    fetch('/_platform/close', { method: 'POST' }).catch(function () {});
  }
  document.getElementById('close').onclick = endSession;
  window.addEventListener('beforeunload', function () {
    if (rfb) { try { rfb.disconnect(); } catch (error) {} }
  });
})();"""


def make_adapter(info):
    if info["adapter"] == "mock-v1":
        return MockAdapter(info)
    if info["adapter"] == PASSTHROUGH_ADAPTER_ID:
        return PassthroughAdapter(info)
    raise Problem("adapter_not_verified", 403)


@dataclass
class Runtime:
    sid: str
    cookie_hash: str
    adapter: object
    lease_end: float
    ws: set = field(default_factory=set)
    closing: bool = False
    close_lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    next_renew: float = 0
    idle_task: asyncio.Task | None = None
    opening: int = 0


class Gateway:
    RECONNECT_GRACE = 2.0

    def __init__(self, cfg):
        self.cfg = cfg
        self.public = load_pem_public_key(Path(cfg["public_key"]).read_bytes())
        self.sessions: dict[str, Runtime] = {}
        self.traces: dict[str, str] = {}
        self.pending_reports = {}
        self._report_retry: dict[str, tuple[int, float]] = {}
        self.control = None
        self.task = None
        self.watchdogs = set()
        self.accepting = set()

    def trace_for(self, sid):
        if sid is None:
            return uuid.uuid4().hex
        return self.traces.setdefault(sid, uuid.uuid4().hex)

    async def call(self, sid, operation, data=None):
        async with self.control.post(self.cfg["manager_internal"] + f"/internal/v1/sessions/{sid}/{operation}",
                                     json=data or {}, headers={"X-Trace-ID": self.trace_for(sid)},
                                     allow_redirects=False) as response:
            if response.status != 200:
                code = {403: "worker_request_rejected", 409: "ticket_consumed_or_expired",
                        410: "session_revoked"}.get(response.status, "manager_unavailable")
                with contextlib.suppress(Exception):
                    body = await response.json(content_type=None)
                    if isinstance(body, dict) and body.get("error") in SESSION_END_CODES:
                        code = body["error"]
                raise ManagerRejected(code, response.status)
            return await response.json()

    async def start(self, app):
        ctx = client_tls(self.cfg["ca"], self.cfg["client_cert"], self.cfg["client_key"])
        self.control = aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=ctx, limit=8),
                                             headers={"X-Worker-Proof": Path(self.cfg["worker_proof"]).read_text().strip()},
                                             timeout=aiohttp.ClientTimeout(total=2), trust_env=False)
        self.task = asyncio.create_task(self.supervise())

    async def stop(self, app):
        if self.task:
            self.task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self.task
        await asyncio.gather(*(self.finish(s, "worker_shutdown") for s in list(self.sessions.values())))
        for task in list(self.watchdogs):
            task.cancel()
        await asyncio.gather(*self.watchdogs, return_exceptions=True)
        if self.control:
            await self.control.close()

    async def report(self, sid, cleanup, reason):
        self.pending_reports[sid] = {"cleanup": cleanup, "reason": reason}
        try:
            await self.call(sid, "finish", self.pending_reports[sid])
        except ManagerRejected as exc:
            if exc.permanent:
                log.warning("finish report for session %s refused by the Manager "
                            "(%s, HTTP %s); not retrying", sid, exc.code, exc.upstream_status)
                self._forget_report(sid)
            else:
                self._retry_later(sid)
            return
        except (Problem, aiohttp.ClientError, TimeoutError):
            self._retry_later(sid)
            return
        self._forget_report(sid)

    def _forget_report(self, sid):
        self.pending_reports.pop(sid, None)
        self._report_retry.pop(sid, None)

    def _retry_later(self, sid):
        attempts = self._report_retry.get(sid, (0, 0.0))[0] + 1
        delay = min(REPORT_RETRY_FIRST * 2 ** (attempts - 1), REPORT_RETRY_MAX)
        self._report_retry[sid] = (attempts, time.monotonic() + delay)

    def due_reports(self, now):
        return [(sid, report) for sid, report in list(self.pending_reports.items())
                if now >= self._report_retry.get(sid, (0, 0.0))[1]]

    def cancel_idle(self, sess):
        if sess.idle_task and not sess.idle_task.done() and sess.idle_task is not asyncio.current_task():
            sess.idle_task.cancel()
        sess.idle_task = None

    async def idle_finish(self, sess):
        try:
            await asyncio.sleep(self.RECONNECT_GRACE)
            if not sess.ws and not sess.opening and not sess.closing:
                await self.finish(sess, "client_closed")
        except asyncio.CancelledError:
            return

    def schedule_idle_finish(self, sess):
        self.cancel_idle(sess)
        if not sess.ws and not sess.opening and not sess.closing:
            task = asyncio.create_task(self.idle_finish(sess))
            self.watchdogs.add(task)
            task.add_done_callback(self.watchdogs.discard)
            sess.idle_task = task

    async def finish(self, sess, reason):
        async with sess.close_lock:
            if sess.closing:
                return
            sess.closing = True
            self.cancel_idle(sess)
            for ws in list(sess.ws):
                with contextlib.suppress(Exception):
                    async with asyncio.timeout(3):
                        await ws.close(code=1001, message=b"session ended")
            cleaned = await sess.adapter.close()
            await self.report(sess.sid, "confirmed" if cleaned else "pending", reason)
            self.sessions.pop(sess.sid, None)

    async def end_lost_upstream(self, sess, upstream):
        with contextlib.suppress(Exception):
            async with asyncio.timeout(3):
                await upstream.close(code=1000)
        await self.finish(sess, upstream_end_reason(upstream))

    async def supervise(self):
        while True:
            await asyncio.sleep(0.25)
            now = time.monotonic()
            await asyncio.gather(*(self.check_lease(s, now) for s in list(self.sessions.values())))
            for sid, report in self.due_reports(now):
                await self.report(sid, report["cleanup"], report["reason"])

    async def lease_watchdog(self, sess):
        while not sess.closing:
            remaining = sess.lease_end - time.monotonic()
            if remaining <= 0:
                await self.finish(sess, "lease_expired")
                return
            await asyncio.sleep(min(0.1, remaining))

    async def check_lease(self, sess, now):
        if sess.closing:
            return
        if now >= sess.lease_end:
            await self.finish(sess, "lease_expired")
            return
        if now < sess.next_renew:
            return
        sess.next_renew = now + 1
        sent = time.monotonic()
        try:
            async with asyncio.timeout(min(2, sess.lease_end - sent)):
                result = await self.call(sess.sid, "renew")
            sess.lease_end = sent + result["lease_seconds"]
        except Problem as exc:
            await self.finish(sess, "capability_withdrawn" if exc.code == "capability_withdrawn"
                              else "revoked")
        except (aiohttp.ClientError, TimeoutError):
            if time.monotonic() >= sess.lease_end:
                await self.finish(sess, "lease_expired")

    def authenticated(self, request):
        sid = request[SESSION_KEY]
        sess = self.sessions.get(sid)
        if (not sess or sess.closing or time.monotonic() >= sess.lease_end
                or not secrets.compare_digest(digest(request.cookies.get("__Host-kvm_sid", "")), sess.cookie_hash)):
            raise Problem("authentication_required", 401)
        return sess

    async def accept(self, request):
        if request.method != "POST" or request.headers.get("Origin") != self.cfg["manager_origin"]:
            raise Problem("csrf_rejected", 403)
        if request.content_type != "application/x-www-form-urlencoded":
            raise Problem("invalid_request", 400)
        body = await request.text()
        values = parse_qs(body, max_num_fields=2)
        tokens = values.get("ticket", [])
        if len(tokens) != 1:
            raise Problem("invalid_ticket", 401)
        claims = verify(self.public, tokens[0], self.cfg["worker_id"], self.cfg["instance_id"])
        if claims["sid"] != request[SESSION_KEY]:
            raise Problem("invalid_ticket", 403)
        if claims["sid"] in self.sessions or claims["sid"] in self.accepting:
            raise Problem("ticket_consumed_or_expired")
        self.accepting.add(claims["sid"])
        self.traces[claims["sid"]] = claims["trc"]
        started = time.monotonic()
        info = None
        adapter = None
        try:
            info = await self.call(claims["sid"], "exchange", {"ticket": tokens[0]})
            hard_until = info["hard_until"]
            adapter = make_adapter(info)
            deadline = started + info["lease_seconds"]
            async with asyncio.timeout(max(0.01, min(10, deadline-time.monotonic()))):
                await adapter.login(info.pop("username"), info.pop("password"))
                sent = time.monotonic()
                result = await self.call(claims["sid"], "active")
            cookie = secrets.token_urlsafe(32)
            sess = Runtime(claims["sid"], digest(cookie), adapter, sent + result["lease_seconds"])
            self.sessions[sess.sid] = sess
            task = asyncio.create_task(self.lease_watchdog(sess))
            self.watchdogs.add(task)
            task.add_done_callback(self.watchdogs.discard)
        except (Exception, asyncio.CancelledError) as exc:
            if adapter is None:
                if not isinstance(exc, Problem) or exc.code not in (
                        "ticket_consumed_or_expired", "worker_request_rejected", "session_revoked"):
                    await self.report(claims["sid"], "not_needed", "exchange_failed")
            else:
                cleaned = await adapter.close()
                await self.report(claims["sid"], "confirmed" if cleaned else "pending", "login_failed")
            raise
        finally:
            self.accepting.discard(claims["sid"])
            if info is not None:
                info.clear()
        response = web.Response(text='<!doctype html><html lang="zh-CN"><meta charset="utf-8"><title>接入成功</title><p>正在打开控制台。<a href="/">继续</a></p><script src="/_platform/continue.js"></script></html>', content_type="text/html")
        response.set_cookie("__Host-kvm_sid", cookie, secure=True, httponly=True, samesite="Strict",
                            path="/", max_age=cookie_max_age(hard_until, time.time()))
        return response

    async def proxy_ws(self, request, sess):
        if sess.closing:
            raise Problem("session_revoked", 410)
        offered = [p.strip() for p in request.headers.get("Sec-WebSocket-Protocol", "").split(",") if p.strip()]
        if not offered and isinstance(sess.adapter, PassthroughAdapter):
            offered = ["binary"]
        if "binary" not in offered:
            raise Problem("subprotocol_required", 400)
        if len(sess.ws) + sess.opening >= connection_limit(sess.adapter):
            raise Problem("connection_limit")
        sess.opening += 1
        self.cancel_idle(sess)
        try:
            upstream = await sess.adapter.connect(offered)
        except Problem as exc:
            if exc.code != "connection_limit":
                await self.finish(sess, "upstream_error")
            raise
        except (aiohttp.ClientError, TimeoutError):
            await self.finish(sess, "upstream_error")
            raise
        finally:
            sess.opening -= 1
        client = web.WebSocketResponse(protocols=(upstream.protocol,), heartbeat=20, max_msg_size=1024*1024,
                                       writer_limit=65536, compress=False, timeout=2)
        pumps = []
        try:
            if sess.closing or time.monotonic() >= sess.lease_end:
                raise Problem("session_revoked", 410)
            await client.prepare(request)
            self.cancel_idle(sess)
            sess.ws.add(client)

            async def pump(src, dst):
                async for message in src:
                    async with asyncio.timeout(3):
                        if message.type == WSMsgType.BINARY:
                            await dst.send_bytes(message.data)
                        elif message.type == WSMsgType.TEXT:
                            await dst.send_str(message.data)
                        else:
                            break

            to_upstream = asyncio.create_task(pump(client, upstream))
            from_upstream = asyncio.create_task(pump(upstream, client))
            pumps = [to_upstream, from_upstream]
            done, _ = await asyncio.wait(pumps, return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                task.result()
            if from_upstream in done and not sess.closing:
                ending = asyncio.create_task(self.end_lost_upstream(sess, upstream))
                self.watchdogs.add(ending)
                ending.add_done_callback(self.watchdogs.discard)
        finally:
            for task in pumps:
                task.cancel()
            await asyncio.gather(*pumps, return_exceptions=True)
            with contextlib.suppress(Exception):
                async with asyncio.timeout(3):
                    await upstream.close(code=1000)
            sess.ws.discard(client)
            if not sess.ws and not sess.closing and sess.idle_task is None:
                self.schedule_idle_finish(sess)
        return client

    async def handle(self, request):
        if request.path == "/_platform/accept":
            return await self.accept(request)
        if request.path == "/_platform/continue.js" and request.method == "GET" and not request.query_string:
            return web.Response(text="location.replace('/');", content_type="application/javascript")
        sess = self.authenticated(request)
        origin = "https://" + request.host
        if request.path == "/_platform/close" and request.method == "POST":
            if request.headers.get("Origin") != origin:
                raise Problem("csrf_rejected", 403)
            await self.finish(sess, "client_closed")
            return web.json_response({"ok": True})
        if request.path == "/_platform/limits" and request.method == "GET":
            return web.json_response({"limit": connection_limit(sess.adapter),
                                      "connections": len(sess.ws),
                                      "opening": sess.opening,
                                      "closing": sess.closing})
        if request.method != "GET" or request.query_string:
            raise Problem("route_denied", 403)
        real = isinstance(sess.adapter, PassthroughAdapter)
        if real and PASSTHROUGH_ASSET_PATH.fullmatch(request.path):
            content_type, body = await sess.adapter.fetch_asset(request.path)
            return web.Response(body=body, content_type=content_type)
        if request.path == "/":
            if real:
                return web.Response(text=REAL_CONSOLE_HTML, content_type="text/html")
            return web.Response(text=CONSOLE_HTML, content_type="text/html")
        if request.path == "/_platform/console.js":
            script = REAL_CONSOLE_JS if real else CONSOLE_JS
            return web.Response(text=script, content_type="application/javascript")
        if request.path == "/console":
            if request.headers.get("Origin") != origin or request.headers.get("Upgrade", "").lower() != "websocket":
                raise Problem("csrf_rejected", 403)
            return await self.proxy_ws(request, sess)
        raise Problem("route_denied", 403)


def create_worker(cfg):
    gateway = Gateway(cfg)

    def error_response(request, code, trace, status):
        if "text/html" in request.headers.get("Accept", ""):
            page = ('<!doctype html><html lang="zh-CN"><meta charset="utf-8"><title>接入失败</title>'
                    f'<h1>接入失败</h1><p>错误码：{html.escape(code)}</p>'
                    f'<p>关联事件 ID：{html.escape(trace)}</p>'
                    '<p>请返回 Manager 查看会话状态或重新申请，不要重复提交票据。</p>'
                    f'<a href="{html.escape(cfg["manager_origin"], quote=True)}">返回 Manager</a></html>')
            return web.Response(text=page, content_type="text/html", status=status)
        return web.json_response({"error": code, "message": user_message(code),
                                  "trace_id": trace}, status=status)

    @web.middleware
    async def guards(request, handler):
        host = request.host.removesuffix(WORKER_HOST_SUFFIX)
        match = HOST_LABEL.fullmatch(host) if request.host.endswith(WORKER_HOST_SUFFIX) else None
        sid = match[1] if match else None
        if sid:
            request[SESSION_KEY] = sid
        fallback = gateway.trace_for(sid)

        def linked():
            return gateway.traces.get(sid, fallback) if sid else fallback

        try:
            if sid is None:
                raise Problem("invalid_host")
            response = await handler(request)
        except Problem as exc:
            response = error_response(request, exc.code, linked(), exc.status)
        except (aiohttp.ClientError, TimeoutError):
            response = error_response(request, "upstream_unavailable", linked(), 502)
        except Exception:
            response = error_response(request, "internal_error", linked(), 500)
        response.headers["X-Trace-ID"] = linked()
        return response

    async def headers(request, response):
        response.headers.update({"Cache-Control": "no-store", "Referrer-Policy": "no-referrer",
                                 "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY",
                                 "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'"})

    app = web.Application(middlewares=[guards], client_max_size=8192)
    app[GATEWAY_KEY] = gateway
    app.on_startup.append(gateway.start)
    app.on_cleanup.append(gateway.stop)
    app.on_response_prepare.append(headers)
    app.router.add_route("*", "/{path:.*}", gateway.handle)
    return app


GATEWAY_KEY = web.AppKey("gateway", Gateway)
