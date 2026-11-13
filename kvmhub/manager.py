import asyncio
import base64
import html
import secrets
import uuid
from contextlib import asynccontextmanager, suppress
from pathlib import Path

from cryptography.hazmat.primitives.serialization import load_pem_private_key
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse

from .common import (INTERNAL_PORT, TRACE_ID, UI_PORT, WORKER_PORT, Problem,
                     digest, end_reason_message, issue, secret_matches, user_message, verify)
from .store import Store

LOGIN = """<!doctype html><html lang="zh-CN"><meta charset="utf-8"><title>KVM Hub</title>
<link rel="stylesheet" href="/style.css"><main><h1>KVM Hub · 本地验证</h1>
<p>仅连接模拟控制台，尚未接入真实 BMC 或 SSO。</p>
<form id="login"><label>本地访问口令 <input name="token" type="password" required autocomplete="off"></label>
<button>登录</button></form><p id="error" role="alert"></p></main><script src="/login.js"></script></html>"""
STYLE = """body{font:16px system-ui;background:#edf1f5;color:#1a2738;margin:0}main{max-width:850px;margin:50px auto;padding:30px;background:white;border-radius:12px}input,button{font:inherit;padding:9px;margin:8px}button{cursor:pointer}article{border-top:1px solid #ddd;padding:16px 0}small{color:#556}#error{color:#a22}a{color:#167}code{overflow-wrap:anywhere}"""
LOGIN_JS = """document.querySelector('#login').onsubmit=async e=>{e.preventDefault();const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token:new FormData(e.target).get('token')})});if(r.ok)location.assign('/');else document.querySelector('#error').textContent='登录失败，请检查本地访问口令。';};"""
APP_JS = """const csrf=document.querySelector('meta[name=csrf]').content;const error=document.querySelector('#error');
async function post(url){const r=await fetch(url,{method:'POST',headers:{'X-CSRF-Token':csrf}});const j=await r.json();if(!r.ok)throw Error((j.message||('操作失败：'+j.error))+'（事件 '+j.trace_id+'）');return j;}
document.querySelectorAll('[data-open]').forEach(b=>b.onclick=async()=>{const w=window.open('about:blank','_blank');if(!w){error.textContent='请允许打开控制台窗口';return;}try{const j=await post('/api/assets/'+b.dataset.open+'/sessions');const f=document.createElement('form');f.method='POST';f.action=j.accept_url;f.target=w.name='kvm-'+j.id;const t=document.createElement('input');t.type='hidden';t.name='ticket';t.value=j.ticket;f.append(t);document.body.append(f);f.submit();f.remove();setTimeout(()=>location.reload(),800);}catch(e){w.close();error.textContent=e.message;}});
document.querySelectorAll('[data-close]').forEach(b=>b.onclick=async()=>{try{await post('/api/sessions/'+b.dataset.close+'/close');location.reload();}catch(e){error.textContent=e.message;}});
document.querySelector('#logout').onclick=async()=>{await post('/api/logout');location.reload();};
document.querySelectorAll('[data-release]').forEach(b=>b.onclick=async()=>{if(!confirm('已核对上游会话确实结束？此操作释放资产名额并写入审计。'))return;try{await post('/api/sessions/'+b.dataset.release+'/release');location.reload();}catch(e){error.textContent=e.message;}});"""


def build_apps(cfg, store=None):
    private = load_pem_private_key(Path(cfg["signing_key"]).read_bytes(), password=None)
    public = private.public_key()
    owns_store = store is None
    store = store or Store(cfg["database"], base64.b64decode(Path(cfg["encryption_key"]).read_bytes()),
                           passthrough_targets=tuple(cfg.get("passthrough_targets", ())))
    browser_sessions = {}

    async def reaper():
        while True:
            store.sweep()
            await asyncio.sleep(1)

    @asynccontextmanager
    async def lifespan(app):
        task = asyncio.create_task(reaper())
        yield
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task
        if owns_store:
            store.close()

    ui = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    internal = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    def install(app, expected_host):
        @app.middleware("http")
        async def guards(request, call_next):
            incoming = request.headers.get("X-Trace-ID", "")
            request.state.trace = incoming if TRACE_ID.fullmatch(incoming) else uuid.uuid4().hex
            if request.headers.get("host") != expected_host:
                return JSONResponse({"error": "invalid_host", "trace_id": request.state.trace,
                                     "message": user_message("invalid_host")}, status_code=421)
            response = await call_next(request)
            response.headers.update({"Cache-Control": "no-store", "Referrer-Policy": "strict-origin",
                                     "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY",
                                     "Content-Security-Policy": f"default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action https://*.kvm.localhost:{WORKER_PORT}",
                                     "X-Trace-ID": request.state.trace})
            return response

        @app.exception_handler(Problem)
        async def problem(request, exc):
            return JSONResponse({"error": exc.code, "message": user_message(exc.code),
                                 "trace_id": request.state.trace}, status_code=exc.status)

    install(ui, f"localhost:{UI_PORT}")
    install(internal, f"localhost:{INTERNAL_PORT}")

    def user(request, mutate=False):
        cookie = request.cookies.get("__Host-manager_sid", "")
        auth = browser_sessions.get(digest(cookie))
        if not auth or auth["expires"] <= store.clock():
            raise Problem("authentication_required", 401)
        if mutate and (request.headers.get("origin") != cfg["manager_origin"]
                       or not secrets.compare_digest(request.headers.get("x-csrf-token", ""), auth["csrf"])):
            raise Problem("csrf_rejected", 403)
        return auth

    def worker_auth(request):
        if not secret_matches(request.headers.get("x-worker-proof", ""), cfg["worker_proof_hash"]):
            raise Problem("worker_authentication_failed", 403)

    async def payload(request):
        if request.headers.get("content-length", "0").isdigit() and int(request.headers.get("content-length", "0")) > 16384:
            raise Problem("request_too_large", 413)
        body = bytearray()
        async for part in request.stream():
            body.extend(part)
            if len(body) > 16384:
                raise Problem("request_too_large", 413)
        try:
            import json
            value = json.loads(body)
            if not isinstance(value, dict):
                raise ValueError()
            return value
        except (ValueError, TypeError):
            raise Problem("invalid_request", 400) from None

    @ui.get("/style.css")
    async def style():
        return HTMLResponse(STYLE, media_type="text/css")

    @ui.get("/login.js")
    async def login_js():
        return HTMLResponse(LOGIN_JS, media_type="application/javascript")

    @ui.get("/app.js")
    async def app_js():
        return HTMLResponse(APP_JS, media_type="application/javascript")

    @ui.post("/api/login")
    async def login(request: Request):
        if request.headers.get("origin") != cfg["manager_origin"]:
            raise Problem("csrf_rejected", 403)
        body = await payload(request)
        token = body.get("token")
        if not isinstance(token, str) or not secret_matches(token, cfg["login_hash"]):
            raise Problem("authentication_failed", 401)
        cookie = secrets.token_urlsafe(32)
        browser_sessions[digest(cookie)] = {"user": "local-admin", "csrf": secrets.token_urlsafe(32),
                                             "expires": store.clock()+3600}
        response = JSONResponse({"ok": True})
        response.set_cookie("__Host-manager_sid", cookie, max_age=3600, secure=True, httponly=True, samesite="strict", path="/")
        return response

    @ui.get("/api/me")
    async def me(request: Request):
        auth = user(request)
        return {"user": auth["user"], "csrf": auth["csrf"]}

    @ui.post("/api/logout")
    async def logout(request: Request):
        user(request, True)
        browser_sessions.pop(digest(request.cookies["__Host-manager_sid"]), None)
        response = JSONResponse({"ok": True})
        response.delete_cookie("__Host-manager_sid", secure=True, httponly=True, samesite="strict")
        return response

    @ui.get("/")
    async def index(request: Request):
        try:
            auth = user(request)
        except Problem:
            return HTMLResponse(LOGIN)
        assets = store.assets(auth["user"])
        sessions = [store.public(r[0], auth["user"]) for r in store.db.execute("SELECT id FROM session WHERE user_id=? ORDER BY created DESC LIMIT 20", (auth["user"],))]
        content = '<!doctype html><html lang="zh-CN"><meta charset="utf-8"><title>KVM Hub</title><link rel="stylesheet" href="/style.css">'
        content += f'<meta name="csrf" content="{html.escape(auth["csrf"], quote=True)}"><main><h1>KVM Hub · 模拟设备验证</h1><p>本页仅用于本机 PoC；没有真实厂商适配器。</p><button id="logout">退出</button><p id="error" role="alert"></p>'
        for a in assets:
            content += f'<article><strong>{html.escape(a["name"])}</strong><button data-open="{a["id"]}">打开控制台</button></article>'
        content += '<h2>最近会话</h2>'
        for s in sessions:
            sid = html.escape(s["id"], quote=True)
            reason = html.escape(s["reason"] or "")
            content += (f'<article><code>{sid}</code><p>{html.escape(s["asset_id"])} · '
                        f'{html.escape(s["status"])} · 清理 {html.escape(s["cleanup"])}</p>')
            if reason:
                sentence = end_reason_message(reason)
                content += (f'<p class="reason">结束原因：<code>{reason}</code>'
                            + (f' {html.escape(sentence)}' if sentence else '') + '</p>')
            content += f'<button data-close="{sid}">结束会话</button>'
            if s["cleanup"] == "pending" and s["status"] in ("closed", "failed", "lost"):
                content += f'<button data-release="{sid}">人工放行（需已核对上游）</button>'
            content += '</article>'
        return HTMLResponse(content + '</main><script src="/app.js"></script></html>')

    @ui.post("/api/assets/{aid}/sessions")
    async def allocate(aid: str, request: Request):
        auth = user(request, True)
        try:
            row = store.allocate(aid, auth["user"], cfg["worker_id"], cfg["instance_id"], request.state.trace)
        except Problem as exc:
            with store.tx():
                store.event(auth["user"], "request_denied", detail={"code": exc.code}, trace=request.state.trace)
            raise
        return {"id": row["id"], "ticket": issue(private, row, store.clock(), trace=request.state.trace),
                "accept_url": f'https://w1-{row["id"]}.kvm.localhost:{WORKER_PORT}/_platform/accept'}

    @ui.get("/api/sessions/{sid}")
    async def status(sid: str, request: Request):
        return store.public(sid, user(request)["user"])

    @ui.post("/api/sessions/{sid}/close")
    async def revoke(sid: str, request: Request):
        store.revoke(sid, user(request, True)["user"], request.state.trace)
        return {"ok": True}

    @ui.post("/api/sessions/{sid}/release")
    async def release(sid: str, request: Request):
        store.confirm_cleanup(sid, user(request, True)["user"], request.state.trace)
        return {"ok": True}

    @ui.get("/api/audit")
    async def audit(request: Request):
        user(request)
        return [dict(r) for r in store.db.execute("SELECT * FROM audit ORDER BY id DESC LIMIT 100")]

    @internal.post("/internal/v1/sessions/{sid}/{operation}")
    async def worker_api(sid: str, operation: str, request: Request):
        worker_auth(request)
        body = await payload(request)
        if operation == "exchange":
            claims = verify(public, body.get("ticket", ""), cfg["worker_id"], cfg["instance_id"])
            if claims["sid"] != sid:
                raise Problem("invalid_ticket", 403)
            return store.exchange(claims, request.state.trace)
        if operation in ("active", "renew"):
            return store.renew(sid, cfg["worker_id"], cfg["instance_id"], operation == "active", trace=request.state.trace)
        if operation == "finish":
            store.finish(sid, cfg["worker_id"], cfg["instance_id"], body.get("cleanup"), body.get("reason"), trace=request.state.trace)
            return {"ok": True}
        raise Problem("unknown_operation", 404)

    ui.state.store = store
    return ui, internal
