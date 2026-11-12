"""Uncertain upstream creation, replay and asynchronous cleanup regressions."""
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

from kvmhub.adapter import MockAdapter
from kvmhub.common import Problem, server_tls
from kvmhub.worker import Gateway, Runtime
from tools.bootstrap import generate


@pytest.fixture
def local(tmp_path):
    directory = generate(tmp_path / "identities")
    cfg = json.loads((directory/"worker.json").read_text())
    cert = x509.load_pem_x509_certificate(Path(cfg["server_cert"]).read_bytes())
    return cfg, cert.fingerprint(hashes.SHA256()).hex()


@pytest.mark.parametrize("failure", ["lost_response", "invalid_json", "no_token", "server_error"])
async def test_uncertain_login_never_claims_no_upstream(local, failure):
    cfg, fingerprint = local
    received = []

    async def login(request):
        received.append(await request.json())
        if failure == "lost_response":
            request.transport.close()
            return web.Response(status=201)
        if failure == "invalid_json":
            return web.Response(status=201, text="not-json")
        if failure == "no_token":
            return web.json_response({}, status=201)
        return web.Response(status=503)

    app = web.Application()
    app.router.add_post("/session", login)
    server = TestServer(app, scheme="https")
    await server.start_server(ssl=server_tls(cfg["server_cert"], cfg["server_key"]))
    adapter = MockAdapter({"target": str(server.make_url("/")).rstrip("/"), "fingerprint": fingerprint, "adapter": "mock-v1"})
    try:
        with pytest.raises((Problem, aiohttp.ClientError)):
            await adapter.login("user", "secret")
        assert len(received) == 1
        assert adapter.possible_session is True
        assert await adapter.close() is False
    finally:
        await adapter.http.close()
        await server.close()


async def test_websocket_redirect_never_receives_upstream_token(local):
    cfg, fingerprint = local
    leaks = []

    async def sink(request):
        leaks.append(dict(request.headers))
        return web.Response()

    sink_app = web.Application()
    sink_app.router.add_get("/sink", sink)
    sink_server = TestServer(sink_app, scheme="https")
    await sink_server.start_server(ssl=server_tls(cfg["server_cert"], cfg["server_key"]))

    async def redirect(request):
        raise web.HTTPFound(str(sink_server.make_url("/sink")))

    upstream_app = web.Application()
    upstream_app.router.add_get("/console", redirect)
    upstream = TestServer(upstream_app, scheme="https")
    await upstream.start_server(ssl=server_tls(cfg["server_cert"], cfg["server_key"]))
    adapter = MockAdapter({"target": str(upstream.make_url("/")).rstrip("/"), "fingerprint": fingerprint, "adapter": "mock-v1"})
    adapter.token = "must-not-leak"
    try:
        with pytest.raises(Problem, match="upstream_redirect_denied"):
            await adapter.connect(["binary"])
        assert leaks == []
    finally:
        await adapter.close()
        await upstream.close()
        await sink_server.close()


async def test_reconnect_grace_really_finishes_and_reports(local):
    cfg, _ = local
    gateway = Gateway(cfg)
    gateway.RECONNECT_GRACE = 0.01
    cleaned = []
    reports = []

    class Adapter:
        async def close(self):
            await asyncio.sleep(0)
            cleaned.append(True)
            return True

    async def call(sid, operation, data=None):
        reports.append((operation, data))
        return {}

    gateway.call = call
    sess = Runtime("test", "hash", Adapter(), time.monotonic()+30)
    gateway.sessions[sess.sid] = sess
    gateway.schedule_idle_finish(sess)
    task = sess.idle_task
    await asyncio.wait_for(task, 1)
    assert cleaned and sess.sid not in gateway.sessions
    assert reports == [("finish", {"cleanup": "confirmed", "reason": "client_closed"})]
