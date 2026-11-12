import asyncio
import json
import time
from pathlib import Path

import aiohttp
import pytest
from aiohttp import web
from aiohttp.test_utils import TestServer
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from kvmhub.adapter import MockAdapter
from kvmhub.common import WORKER_PORT, Problem, digest, issue, server_tls
from kvmhub.mock_bmc import create_mock
from kvmhub.worker import GATEWAY_KEY, SESSION_KEY, Gateway, Runtime, create_worker
from tools.bootstrap import generate


@pytest.fixture
def identities(tmp_path):
    directory = generate(tmp_path/"identity")
    return directory, json.loads((directory/"worker.json").read_text())


async def test_bad_certificate_pin_sends_no_credentials(identities):
    directory, cfg = identities
    requests = []

    async def handler(request):
        requests.append(await request.read())
        return web.json_response({"token": "secret"}, status=201)

    app = web.Application()
    app.router.add_post("/session", handler)
    server = TestServer(app, scheme="https")
    await server.start_server(ssl=server_tls(cfg["server_cert"], cfg["server_key"]))
    adapter = MockAdapter({"target": str(server.make_url("/")).rstrip("/"),
                           "fingerprint": "00"*32, "adapter": "mock-v1"})
    try:
        with pytest.raises(aiohttp.ServerFingerprintMismatch):
            await adapter.login("sensitive-user", "sensitive-password")
        assert requests == []
        assert adapter.possible_session is False
        assert await adapter.close() is True
    finally:
        await server.close()


async def test_upstream_handshake_failure_does_not_return_101_and_cleans(identities):
    directory, cfg = identities
    upstream_app = web.Application()
    logged_out = []

    async def login(request):
        return web.json_response({"token": "upstream-token"}, status=201)

    async def deny(request):
        return web.Response(status=503)

    async def logout(request):
        logged_out.append(True)
        return web.Response(status=204)

    upstream_app.router.add_post("/session", login)
    upstream_app.router.add_delete("/session", logout)
    upstream_app.router.add_get("/console", deny)
    upstream = TestServer(upstream_app, scheme="https")
    await upstream.start_server(ssl=server_tls(cfg["server_cert"], cfg["server_key"]))
    cert = x509.load_pem_x509_certificate(Path(cfg["server_cert"]).read_bytes())
    adapter = MockAdapter({"target": str(upstream.make_url("/")).rstrip("/"),
                           "fingerprint": cert.fingerprint(hashes.SHA256()).hex(), "adapter": "mock-v1"})
    await adapter.login("u", "p")
    app = create_worker(cfg)
    app.on_startup.clear()
    app.on_cleanup.clear()
    gateway = app[GATEWAY_KEY]
    reports = []

    async def call(sid, op, data=None):
        reports.append((op, data))
        return {"ok": True}

    gateway.call = call
    from kvmhub.common import digest
    sid = "a"*32
    runtime = Runtime(sid, digest("browser-secret"), adapter, time.monotonic()+30)
    gateway.sessions[sid] = runtime
    async with TestServer(app) as server:
        async with aiohttp.ClientSession() as browser:
            with pytest.raises(aiohttp.WSServerHandshakeError) as error:
                await browser.ws_connect(server.make_url("/console"), protocols=("binary",),
                                         headers={"Host": f"w1-{sid}.kvm.localhost:{WORKER_PORT}",
                                                  "Origin": f"https://w1-{sid}.kvm.localhost:{WORKER_PORT}",
                                                  "Cookie": "__Host-kvm_sid=browser-secret"})
            assert error.value.status == 502
    assert logged_out and reports[-1][1]["cleanup"] == "confirmed"
    await upstream.close()


async def test_local_lease_expires_without_manager(identities):
    _, cfg = identities
    gateway = Gateway(cfg)

    class Adapter:
        closed = False

        async def close(self):
            self.closed = True
            return True

    adapter = Adapter()
    sess = Runtime("sid", "hash", adapter, time.monotonic()+0.05)
    gateway.sessions[sess.sid] = sess

    async def unavailable(*args, **kwargs):
        raise aiohttp.ClientConnectionError()

    gateway.call = unavailable
    await asyncio.wait_for(gateway.lease_watchdog(sess), timeout=1)
    assert adapter.closed and sess.closing and not gateway.sessions
    assert gateway.pending_reports["sid"]["reason"] == "lease_expired"


async def test_failed_logout_is_reported_as_pending(identities):
    directory, cfg = identities
    app = web.Application()

    async def login(request):
        return web.json_response({"token": "token"}, status=201)

    async def logout(request):
        return web.Response(status=503)

    app.router.add_post("/session", login)
    app.router.add_delete("/session", logout)
    server = TestServer(app, scheme="https")
    await server.start_server(ssl=server_tls(cfg["server_cert"], cfg["server_key"]))
    cert = x509.load_pem_x509_certificate(Path(cfg["server_cert"]).read_bytes())
    adapter = MockAdapter({"target": str(server.make_url("/")).rstrip("/"),
                           "fingerprint": cert.fingerprint(hashes.SHA256()).hex(), "adapter": "mock-v1"})
    try:
        await adapter.login("u", "p")
        assert await adapter.close() is False
    finally:
        await server.close()


async def test_bmc_auth_failure_does_not_claim_residual_session(identities):
    directory, cfg = identities
    app = web.Application()

    async def reject(request):
        return web.json_response({"error": "authentication_failed"}, status=401)

    app.router.add_post("/session", reject)
    server = TestServer(app, scheme="https")
    await server.start_server(ssl=server_tls(cfg["server_cert"], cfg["server_key"]))
    cert = x509.load_pem_x509_certificate(Path(cfg["server_cert"]).read_bytes())
    adapter = MockAdapter({"target": str(server.make_url("/")).rstrip("/"),
                           "fingerprint": cert.fingerprint(hashes.SHA256()).hex(), "adapter": "mock-v1"})
    try:
        with pytest.raises(Problem, match="bmc_auth_failed"):
            await adapter.login("u", "p")
        assert adapter.possible_session is False
        assert await adapter.close() is True
    finally:
        await server.close()


async def test_exchange_failure_reports_not_needed(identities):
    directory, cfg = identities
    gateway = Gateway(cfg)
    sid = "b"*32
    manager_cfg = json.loads((directory/"manager.json").read_text())
    private = load_pem_private_key(Path(manager_cfg["signing_key"]).read_bytes(), password=None)
    row = {"id": sid, "user_id": "u", "asset_id": "a", "worker_id": cfg["worker_id"],
           "instance_id": cfg["instance_id"], "jti": "j", "hard_until": time.time()+3600}
    ticket = issue(private, row, time.time())

    class FakeRequest(dict):
        def __init__(self, origin, value):
            super().__init__()
            self.method = "POST"
            self.content_type = "application/x-www-form-urlencoded"
            self.headers = {"Origin": origin}
            self.value = value

        async def text(self):
            return "ticket=" + self.value

    request = FakeRequest(cfg["manager_origin"], ticket)
    request[SESSION_KEY] = sid
    calls = []

    async def fake_call(identifier, operation, data=None):
        calls.append((operation, data))
        if operation == "exchange":
            raise Problem("manager_unavailable", 503)
        return {"ok": True}

    gateway.call = fake_call
    with pytest.raises(Problem, match="manager_unavailable"):
        await gateway.accept(request)
    assert ("finish", {"cleanup": "not_needed", "reason": "exchange_failed"}) in calls


async def test_unexpected_worker_error_returns_stable_error_page(identities):
    _, cfg = identities
    app = create_worker(cfg)
    app.on_startup.clear()
    app.on_cleanup.clear()
    gateway = app[GATEWAY_KEY]

    def boom(request):
        raise RuntimeError("unexpected")

    gateway.authenticated = boom
    host = "w1-" + "c"*32 + f".kvm.localhost:{WORKER_PORT}"
    async with TestServer(app) as server:
        async with aiohttp.ClientSession() as browser:
            async with browser.get(server.make_url("/"), headers={"Host": host, "Accept": "text/html"}) as r:
                assert r.status == 500
                body = await r.text()
                assert "internal_error" in body
                assert "返回 Manager" in body
                assert r.headers.get("X-Trace-ID")
            async with browser.get(server.make_url("/"), headers={"Host": host, "Accept": "application/json"}) as r:
                assert r.status == 500
                payload = await r.json()
                assert payload["error"] == "internal_error" and payload["trace_id"]


async def test_ws_disconnect_allows_reconnect_without_logging_out(identities):
    directory, cfg = identities
    bmc = create_mock("u", "p")
    upstream = TestServer(bmc, scheme="https")
    await upstream.start_server(ssl=server_tls(cfg["server_cert"], cfg["server_key"]))
    cert = x509.load_pem_x509_certificate(Path(cfg["server_cert"]).read_bytes())
    adapter = MockAdapter({"target": str(upstream.make_url("/")).rstrip("/"),
                           "fingerprint": cert.fingerprint(hashes.SHA256()).hex(), "adapter": "mock-v1"})
    await adapter.login("u", "p")
    app = create_worker(cfg)
    app.on_startup.clear()
    app.on_cleanup.clear()
    gateway = app[GATEWAY_KEY]
    reports = []

    async def call(sid, op, data=None):
        reports.append((op, data))
        return {"ok": True}

    gateway.call = call
    sid = "d"*32
    runtime = Runtime(sid, digest("browser-secret"), adapter, time.monotonic()+30)
    gateway.sessions[sid] = runtime
    host = f"w1-{sid}.kvm.localhost:{WORKER_PORT}"
    headers = {"Host": host, "Origin": f"https://{host}", "Cookie": "__Host-kvm_sid=browser-secret"}
    try:
        async with TestServer(app) as server:
            async with aiohttp.ClientSession() as browser:
                first = await browser.ws_connect(server.make_url("/console"), protocols=("binary",), headers=headers)
                assert (await first.receive(timeout=3)).type == aiohttp.WSMsgType.BINARY
                await first.close()
                second = await browser.ws_connect(server.make_url("/console"), protocols=("binary",), headers=headers)
                assert (await second.receive(timeout=3)).type == aiohttp.WSMsgType.BINARY
                await second.close()
        assert runtime.idle_task is not None, "a reconnect grace period must be scheduled"
        gateway.cancel_idle(runtime)
        assert sid in gateway.sessions, "a single WS close must not terminate the session"
        assert not any(op == "finish" for op, _ in reports)
    finally:
        await gateway.finish(runtime, "test_cleanup")
        await upstream.close()


def test_cookie_max_age_never_exceeds_hard_until():
    from kvmhub.worker import cookie_max_age
    now = 1_000_000.0
    assert cookie_max_age(now + 30, now) == 30
    assert cookie_max_age(now + 14_400, now) == 14_400
    assert cookie_max_age(now + 50_000, now) == 14_400
    assert cookie_max_age(now - 1, now) == 1
