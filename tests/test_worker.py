import asyncio
import json
import time
from pathlib import Path
from types import SimpleNamespace

import aiohttp
import pytest
from aiohttp import web
from aiohttp.test_utils import TestServer
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from kvmhub.adapter import MockAdapter
from kvmhub.adapters.passthrough import PassthroughAdapter
from kvmhub.adapters.passthrough import PassthroughAdapter
from kvmhub.common import WORKER_PORT, Problem, digest, issue, server_tls
from kvmhub.mock_bmc import create_mock
from kvmhub import worker as worker_module
from kvmhub.recovery import RecoveryPolicy
from kvmhub.worker import (GATEWAY_KEY, MAX_TRACES, SESSION_KEY, Gateway, ManagerRejected,
                           Runtime, create_worker, wire_recovery)
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
    _orig_close = adapter.close

    async def _traced_close():
        print("AC1 enter")
        value = await _orig_close()
        print("AC2 exit", value)
        return value

    adapter.close = _traced_close
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


async def test_a_finished_session_leaves_no_trace_behind(identities):
    _, cfg = identities
    gateway = Gateway(cfg)

    class Adapter:
        async def close(self):
            return True

    sess = Runtime("sid", "hash", Adapter(), time.monotonic()+30)
    gateway.sessions[sess.sid] = sess
    gateway.traces[sess.sid] = "trace-from-ticket"

    async def unavailable(*args, **kwargs):
        raise aiohttp.ClientConnectionError()

    gateway.call = unavailable
    await gateway.finish(sess, "client_closed")
    assert sess.sid not in gateway.sessions
    assert sess.sid not in gateway.traces


async def test_an_unknown_host_does_not_grow_the_trace_table(identities):
    _, cfg = identities
    gateway = Gateway(cfg)
    assert gateway.trace_of("never-seen")
    assert gateway.traces == {}


async def test_the_trace_table_is_bounded(identities):
    _, cfg = identities
    gateway = Gateway(cfg)
    for index in range(MAX_TRACES + 10):
        gateway.trace_for(f"sid-{index}")
    assert len(gateway.traces) == MAX_TRACES
    assert f"sid-{MAX_TRACES + 9}" in gateway.traces
    assert "sid-0" not in gateway.traces


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


async def test_an_upstream_close_is_not_reported_as_a_client_close(identities):
    directory, cfg = identities
    logged_out = []

    async def login(request):
        return web.json_response({"token": "upstream-token"}, status=201)

    async def logout(request):
        logged_out.append(True)
        return web.Response(status=204)

    async def console(request):
        ws = web.WebSocketResponse(protocols=("binary",))
        await ws.prepare(request)
        await ws.close()
        return ws

    upstream_app = web.Application()
    upstream_app.router.add_post("/session", login)
    upstream_app.router.add_delete("/session", logout)
    upstream_app.router.add_get("/console", console)
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
    sid = "e"*32
    runtime = Runtime(sid, digest("browser-secret"), adapter, time.monotonic()+30)
    gateway.sessions[sid] = runtime
    host = f"w1-{sid}.kvm.localhost:{WORKER_PORT}"
    headers = {"Host": host, "Origin": f"https://{host}", "Cookie": "__Host-kvm_sid=browser-secret"}
    try:
        async with TestServer(app) as server:
            async with aiohttp.ClientSession() as browser:
                await browser.ws_connect(server.make_url("/console"), protocols=("binary",),
                                         headers=headers)
                for _ in range(250):
                    if runtime.closing or runtime.idle_task is not None:
                        break
                    await asyncio.sleep(0.02)
                assert runtime.idle_task is None, "an upstream loss must not park the session"
                assert runtime.closing, "an upstream close must end the session"
                for _ in range(400):
                    if reports:
                        break
                    await asyncio.sleep(0.02)
                assert reports, "the ended session must be reported"
    finally:
        if sid in gateway.sessions:
            await gateway.finish(runtime, "test_cleanup")
        await upstream.close()
    assert reports[-1][1]["reason"] == "upstream_error"
    assert logged_out, "the BMC session must still be logged out"


def test_upstream_end_reason_keeps_heartbeat_failure_distinct():
    from kvmhub.store import END_REASONS
    from kvmhub.worker import upstream_end_reason
    assert upstream_end_reason(SimpleNamespace(error="upstream_unresponsive")) == "upstream_unresponsive"
    assert upstream_end_reason(SimpleNamespace(error="upstream_frame_too_large")) == "upstream_error"
    assert upstream_end_reason(SimpleNamespace(error=None)) == "upstream_error"
    assert upstream_end_reason(SimpleNamespace()) == "upstream_error"
    for code in ("client_message_denied", "client_message_malformed"):
        assert upstream_end_reason(SimpleNamespace(error=code)) == code
        assert code in END_REASONS
    assert set(END_REASONS) >= {"upstream_error", "upstream_unresponsive", "client_closed"}


def test_a_spent_rebuild_has_its_own_end_reason():
    from kvmhub.store import END_REASONS
    from kvmhub.worker import upstream_end_reason
    spent = SimpleNamespace(error="upstream_silent",
                            recovery=SimpleNamespace(state="given_up", attempts=2))
    assert upstream_end_reason(spent) == "upstream_reconnect_failed"
    assert "upstream_reconnect_failed" in END_REASONS
    assert upstream_end_reason(SimpleNamespace(
        error="upstream_unresponsive",
        recovery=SimpleNamespace(state="relaying", attempts=0))) == "upstream_unresponsive"
    assert upstream_end_reason(SimpleNamespace(
        error="client_message_denied",
        recovery=SimpleNamespace(state="relaying", attempts=0))) == "client_message_denied"


def test_cookie_max_age_never_exceeds_hard_until():
    from kvmhub.worker import cookie_max_age
    now = 1_000_000.0
    assert cookie_max_age(now + 30, now) == 30
    assert cookie_max_age(now + 14_400, now) == 14_400
    assert cookie_max_age(now + 50_000, now) == 14_400
    assert cookie_max_age(now - 1, now) == 1



class _Reply:
    def __init__(self, status, body=None):
        self.status, self._body = status, body

    async def json(self, content_type=None):
        if isinstance(self._body, Exception):
            raise self._body
        return self._body


class _FakeControl:

    def __init__(self, status, body=None):
        self.reply = _Reply(status, body)

    def post(self, url, **kwargs):
        reply = self.reply

        class _Context:
            async def __aenter__(self):
                return reply

            async def __aexit__(self, *exc):
                return False

        return _Context()


@pytest.mark.parametrize("status, body, code, permanent", [
    (400, {"error": "invalid_report"}, "manager_unavailable", True),
    (403, {"error": "instance_mismatch"}, "worker_request_rejected", True),
    (404, {"error": "session_not_found"}, "manager_unavailable", True),
    (409, None, "ticket_consumed_or_expired", True),
    (410, {"error": "session_revoked"}, "session_revoked", True),
    (410, {"error": "capability_withdrawn"}, "capability_withdrawn", True),
    (408, None, "manager_unavailable", False),
    (429, None, "manager_unavailable", False),
    (500, None, "manager_unavailable", False),
    (503, ValueError("not json"), "manager_unavailable", False),
])
async def test_manager_refusals_keep_their_code_and_expose_whether_they_are_final(
        identities, status, body, code, permanent):
    _, cfg = identities
    gateway = Gateway(cfg)
    gateway.control = _FakeControl(status, body)
    with pytest.raises(Problem) as excinfo:
        await gateway.call("s" * 32, "finish", {})
    assert excinfo.value.code == code
    assert excinfo.value.upstream_status == status
    assert excinfo.value.permanent is permanent


async def test_permanent_refusal_drops_the_report_instead_of_retrying_forever(identities, caplog):
    _, cfg = identities
    gateway = Gateway(cfg)
    calls = []

    async def refuse(sid, operation, data=None):
        calls.append(operation)
        raise ManagerRejected("manager_unavailable", 400)

    gateway.call = refuse
    with caplog.at_level("WARNING", logger="kvmhub.worker"):
        await gateway.report("sid", "not_needed", "exchange_failed")
    assert calls == ["finish"]
    assert gateway.pending_reports == {} and gateway._report_retry == {}
    assert gateway.due_reports(time.monotonic() + 3600) == []
    assert "sid" in caplog.text and "HTTP 400" in caplog.text


async def test_supervisor_makes_a_single_attempt_for_a_permanently_refused_report(identities):
    _, cfg = identities
    gateway = Gateway(cfg)
    calls = []

    async def refuse(sid, operation, data=None):
        calls.append(sid)
        raise ManagerRejected("manager_unavailable", 404)

    gateway.call = refuse
    gateway.pending_reports["sid"] = {"cleanup": "confirmed", "reason": "client_closed"}
    task = asyncio.create_task(gateway.supervise())
    await asyncio.sleep(0.8)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert calls == ["sid"] and "sid" not in gateway.pending_reports


@pytest.mark.parametrize("failure", [
    lambda: ManagerRejected("manager_unavailable", 503),
    lambda: ManagerRejected("manager_unavailable", 429),
    lambda: Problem("manager_unavailable"),
    lambda: aiohttp.ClientConnectionError(),
    lambda: TimeoutError(),
])
async def test_transient_failures_back_off_exponentially_up_to_a_cap(identities, monkeypatch, failure):
    _, cfg = identities
    gateway = Gateway(cfg)
    clock = [1000.0]
    monkeypatch.setattr(worker_module, "time", SimpleNamespace(monotonic=lambda: clock[0]))

    async def fail(sid, operation, data=None):
        raise failure()

    gateway.call = fail
    pending = {"cleanup": "pending", "reason": "lease_expired"}
    expected = [0.5, 1.0, 2.0, 4.0, 8.0, 16.0, 30.0, 30.0]
    for attempt, delay in enumerate(expected, start=1):
        await gateway.report("sid", "pending", "lease_expired")
        assert gateway.pending_reports == {"sid": pending}
        assert gateway._report_retry["sid"] == (attempt, clock[0] + delay)
        assert gateway.due_reports(clock[0] + delay - 0.01) == []
        assert gateway.due_reports(clock[0] + delay) == [("sid", pending)]
        clock[0] += delay


async def test_a_successful_report_clears_the_retry_state(identities, monkeypatch):
    _, cfg = identities
    gateway = Gateway(cfg)
    clock = [50.0]
    monkeypatch.setattr(worker_module, "time", SimpleNamespace(monotonic=lambda: clock[0]))
    outcomes = [aiohttp.ClientConnectionError(), ManagerRejected("manager_unavailable", 502), None]

    async def flaky(sid, operation, data=None):
        outcome = outcomes.pop(0)
        if outcome is not None:
            raise outcome
        return {"ok": True}

    gateway.call = flaky
    for _ in range(3):
        await gateway.report("sid", "confirmed", "client_closed")
        clock[0] += 60
    assert gateway.pending_reports == {} and gateway._report_retry == {}


async def test_each_pending_report_is_scheduled_independently(identities, monkeypatch):
    _, cfg = identities
    gateway = Gateway(cfg)
    clock = [10.0]
    monkeypatch.setattr(worker_module, "time", SimpleNamespace(monotonic=lambda: clock[0]))

    async def fail(sid, operation, data=None):
        raise ManagerRejected("manager_unavailable", 503)

    gateway.call = fail
    await gateway.report("a", "pending", "revoked")
    clock[0] += 5
    await gateway.report("b", "pending", "revoked")
    assert [sid for sid, _ in gateway.due_reports(clock[0])] == ["a"]


class _StubSocket:

    async def close(self, *args, **kwargs):
        return None


async def test_limits_endpoint_tells_the_page_why_it_cannot_connect(identities):
    _, cfg = identities
    app = create_worker(cfg)
    app.on_startup.clear()
    app.on_cleanup.clear()
    gateway = app[GATEWAY_KEY]
    sid = "e" * 32
    runtime = Runtime(sid, digest("browser-secret"), None, time.monotonic() + 30)
    runtime.ws.update({_StubSocket(), _StubSocket(), _StubSocket()})
    gateway.sessions[sid] = runtime
    host = f"w1-{sid}.kvm.localhost:{WORKER_PORT}"
    headers = {"Host": host, "Cookie": "__Host-kvm_sid=browser-secret"}
    async with TestServer(app) as server:
        async with aiohttp.ClientSession() as browser:
            async with browser.get(server.make_url("/_platform/limits"), headers=headers) as response:
                assert response.status == 200
                body = await response.json()
    assert body == {"limit": 4, "connections": 3, "opening": 0, "closing": False}
    assert "/_platform/limits" in worker_module.REAL_CONSOLE_JS


async def test_limits_endpoint_is_closed_without_the_session_cookie(identities):
    _, cfg = identities
    app = create_worker(cfg)
    app.on_startup.clear()
    app.on_cleanup.clear()
    gateway = app[GATEWAY_KEY]
    sid = "f" * 32
    gateway.sessions[sid] = Runtime(sid, digest("browser-secret"), None, time.monotonic() + 30)
    host = f"w1-{sid}.kvm.localhost:{WORKER_PORT}"
    async with TestServer(app) as server:
        async with aiohttp.ClientSession() as browser:
            url = server.make_url("/_platform/limits")
            async with browser.get(url, headers={"Host": host}) as response:
                assert response.status == 401
            async with browser.get(url, headers={"Host": host,
                                                "Cookie": "__Host-kvm_sid=wrong"}) as response:
                assert response.status == 401


async def test_a_fifth_console_connection_is_a_429_not_a_lost_session(identities):
    _, cfg = identities
    app = create_worker(cfg)
    app.on_startup.clear()
    app.on_cleanup.clear()
    gateway = app[GATEWAY_KEY]
    sid = "a" * 32
    runtime = Runtime(sid, digest("browser-secret"), None, time.monotonic() + 30)
    runtime.ws.update({_StubSocket() for _ in range(4)})
    gateway.sessions[sid] = runtime
    host = f"w1-{sid}.kvm.localhost:{WORKER_PORT}"
    headers = {"Host": host, "Origin": f"https://{host}", "Cookie": "__Host-kvm_sid=browser-secret",
               "Upgrade": "websocket", "Connection": "Upgrade",
               "Sec-WebSocket-Version": "13", "Sec-WebSocket-Protocol": "binary"}
    async with TestServer(app) as server:
        async with aiohttp.ClientSession() as browser:
            async with browser.get(server.make_url("/console"), headers=headers) as response:
                assert response.status == 429
                body = await response.json()
                assert body["error"] == "connection_limit"
                assert "上限" in body["message"]
    assert sid in gateway.sessions and not runtime.closing, \
        "a refused extra console must not end the session the first ones use"
    assert runtime.opening == 0, "a refused connection must not leave the opening counter raised"


class _SingleConsoleAdapter:

    connection_limit = 1

    def __init__(self):
        self.calls = 0

    async def connect(self, offered):
        self.calls += 1
        raise AssertionError("a refused connection must not reach the BMC")


async def test_a_single_console_adapter_lowers_the_limit_the_page_is_told(identities):
    _, cfg = identities
    app = create_worker(cfg)
    app.on_startup.clear()
    app.on_cleanup.clear()
    gateway = app[GATEWAY_KEY]
    sid = "b" * 32
    adapter = _SingleConsoleAdapter()
    runtime = Runtime(sid, digest("browser-secret"), adapter, time.monotonic() + 30)
    runtime.ws.add(_StubSocket())
    gateway.sessions[sid] = runtime
    host = f"w1-{sid}.kvm.localhost:{WORKER_PORT}"
    cookie = {"Host": host, "Cookie": "__Host-kvm_sid=browser-secret"}
    upgrade = dict(cookie, Origin=f"https://{host}", Upgrade="websocket", Connection="Upgrade",
                   **{"Sec-WebSocket-Version": "13", "Sec-WebSocket-Protocol": "binary"})
    async with TestServer(app) as server:
        async with aiohttp.ClientSession() as browser:
            async with browser.get(server.make_url("/_platform/limits"), headers=cookie) as response:
                assert (await response.json())["limit"] == 1
            async with browser.get(server.make_url("/console"), headers=upgrade) as response:
                assert response.status == 429
    assert adapter.calls == 0, "the second tab must be refused before the BMC is contacted"
    assert sid in gateway.sessions and not runtime.closing


async def test_stats_endpoint_separates_a_flapping_link_from_a_second_tab(identities):
    _, cfg = identities
    app = create_worker(cfg)
    app.on_startup.clear()
    app.on_cleanup.clear()
    gateway = app[GATEWAY_KEY]
    sid = "c" * 32
    runtime = Runtime(sid, digest("browser-secret"), None, time.monotonic() + 30)
    runtime.ws.update({_StubSocket(), _StubSocket()})
    runtime.telemetry.note_connection()
    runtime.telemetry.note_connection()
    gateway.sessions[sid] = runtime
    gateway.evidence.add({"sid": "9" * 32, "end_reason": "upstream_error", "cleanup": "pending"})
    host = f"w1-{sid}.kvm.localhost:{WORKER_PORT}"
    headers = {"Host": host, "Cookie": "__Host-kvm_sid=browser-secret"}
    async with TestServer(app) as server:
        async with aiohttp.ClientSession() as browser:
            async with browser.get(server.make_url("/_platform/stats"), headers=headers) as response:
                assert response.status == 200
                assert response.headers["Cache-Control"] == "no-store"
                body = await response.json()
    session = body["session"]
    assert (session["connections"], session["reconnects"]) == (2, 1)
    assert (session["ws_open"], session["state"]) == (2, "live")
    assert session["key_events"] == 0 and session["client_message_types"] == {}
    assert 0 <= session["lease_remaining_s"] <= 30 and session["uptime_s"] >= 0
    assert body["recent_ended"] == [{"sid": "9" * 8 + "…", "end_reason": "upstream_error",
                                     "cleanup": "pending"}], \
        "another session's record keeps its shape but never its addressable id"
    assert "/_platform/stats" in worker_module.REAL_CONSOLE_JS


async def test_stats_endpoint_is_closed_without_the_session_cookie(identities):
    _, cfg = identities
    app = create_worker(cfg)
    app.on_startup.clear()
    app.on_cleanup.clear()
    gateway = app[GATEWAY_KEY]
    sid = "d" * 32
    gateway.sessions[sid] = Runtime(sid, digest("browser-secret"), None, time.monotonic() + 30)
    host = f"w1-{sid}.kvm.localhost:{WORKER_PORT}"
    async with TestServer(app) as server:
        async with aiohttp.ClientSession() as browser:
            url = server.make_url("/_platform/stats")
            async with browser.get(url, headers={"Host": host}) as response:
                assert response.status == 401
            async with browser.get(url, headers={"Host": host,
                                                 "Cookie": "__Host-kvm_sid=wrong"}) as response:
                assert response.status == 401


async def test_every_ending_leaves_one_evidence_record(identities, caplog):
    _, cfg = identities
    gateway = Gateway(cfg)

    class Adapter:
        async def close(self):
            return False

    sess = Runtime("f" * 32, "hash", Adapter(), time.monotonic() + 30)
    gateway.sessions[sess.sid] = sess
    sess.telemetry.note_connection()
    sess.telemetry.note_connection()

    async def unavailable(*args, **kwargs):
        raise aiohttp.ClientConnectionError()

    gateway.call = unavailable
    with caplog.at_level("WARNING", logger="kvmhub.worker"):
        await gateway.finish(sess, "lease_expired")

    record = gateway.evidence.recent(1, mask=False)[0]
    assert record["sid"] == sess.sid
    assert record["end_reason"] == "lease_expired" and record["cleanup"] == "pending"
    assert (record["connections"], record["reconnects"]) == (2, 1)
    assert record["duration_ms"] >= 0
    line = caplog.text
    assert "reason=lease_expired" in line and "cleanup=pending" in line
    assert "reconnects=1" in line


def test_the_recovery_budget_comes_from_config_and_is_clamped(identities):
    _, cfg = identities
    assert Gateway(cfg).recovery == RecoveryPolicy(), "defaults when nothing is configured"
    cfg.update({"upstream_recovery_attempts": 4, "upstream_recovery_max_total": 1,
                "upstream_recovery_delay_seconds": 0.1})
    configured = Gateway(cfg).recovery
    assert (configured.attempts, configured.max_total, configured.first_delay) == (4, 1, 0.1)
    cfg.update({"upstream_recovery_attempts": "many", "upstream_recovery_deadline_seconds": 0})
    assert Gateway(cfg).recovery.attempts == RecoveryPolicy.attempts
    assert Gateway(cfg).recovery.deadline == 1.0


async def test_only_an_adapter_that_can_rebuild_gets_the_policy(identities):
    _, cfg = identities
    policy = Gateway(cfg).recovery
    passthrough = object.__new__(PassthroughAdapter)
    assert wire_recovery(passthrough, policy).recovery is policy
    synthetic = MockAdapter({"target": "https://127.0.0.1:443", "fingerprint": "00" * 32,
                             "adapter": "mock-v1"})
    try:
        assert not hasattr(wire_recovery(synthetic, policy), "recovery")
    finally:
        await synthetic.close()


async def test_stats_shows_a_rebuild_in_flight(identities):
    _, cfg = identities
    app = create_worker(cfg)
    app.on_startup.clear()
    app.on_cleanup.clear()
    gateway = app[GATEWAY_KEY]
    sid = "e" * 32
    runtime = Runtime(sid, digest("browser-secret"), None, time.monotonic() + 30)
    relay = SimpleNamespace(recovery=SimpleNamespace(state="recovering", recoveries=1,
                                                     attempts=2, dropped_input=3),
                            as_dict=lambda: {"recoveries": 1, "recovery_attempts": 2,
                                             "dropped_input": 3})
    runtime.telemetry.note_connection(relay)
    gateway.sessions[sid] = runtime
    host = f"w1-{sid}.kvm.localhost:{WORKER_PORT}"
    headers = {"Host": host, "Cookie": "__Host-kvm_sid=browser-secret"}
    async with TestServer(app) as server:
        async with aiohttp.ClientSession() as browser:
            async with browser.get(server.make_url("/_platform/stats"), headers=headers) as response:
                assert response.status == 200
                session = (await response.json())["session"]
    assert session["state"] == "recovering"
    assert session["recoveries"] == 1 and session["dropped_input"] == 3


def test_the_recovery_budget_comes_from_config_and_is_clamped(identities):
    _, cfg = identities
    assert Gateway(cfg).recovery == RecoveryPolicy(), "defaults when nothing is configured"
    cfg.update({"upstream_recovery_attempts": 4, "upstream_recovery_max_total": 1,
                "upstream_recovery_delay_seconds": 0.1})
    configured = Gateway(cfg).recovery
    assert (configured.attempts, configured.max_total, configured.first_delay) == (4, 1, 0.1)
    cfg.update({"upstream_recovery_attempts": "many", "upstream_recovery_deadline_seconds": 0})
    assert Gateway(cfg).recovery.attempts == RecoveryPolicy.attempts
    assert Gateway(cfg).recovery.deadline == 1.0


async def test_only_an_adapter_that_can_rebuild_gets_the_policy(identities):
    _, cfg = identities
    policy = Gateway(cfg).recovery
    passthrough = object.__new__(PassthroughAdapter)
    assert wire_recovery(passthrough, policy).recovery is policy
    synthetic = MockAdapter({"target": "https://127.0.0.1:443", "fingerprint": "00" * 32,
                             "adapter": "mock-v1"})
    try:
        assert not hasattr(wire_recovery(synthetic, policy), "recovery")
    finally:
        await synthetic.close()


async def test_stats_shows_a_rebuild_in_flight(identities):
    _, cfg = identities
    app = create_worker(cfg)
    app.on_startup.clear()
    app.on_cleanup.clear()
    gateway = app[GATEWAY_KEY]
    sid = "e" * 32
    runtime = Runtime(sid, digest("browser-secret"), None, time.monotonic() + 30)
    relay = SimpleNamespace(recovery=SimpleNamespace(state="recovering", recoveries=1,
                                                     attempts=2, dropped_input=3),
                            as_dict=lambda: {"recoveries": 1, "recovery_attempts": 2,
                                             "dropped_input": 3})
    runtime.telemetry.note_connection(relay)
    gateway.sessions[sid] = runtime
    host = f"w1-{sid}.kvm.localhost:{WORKER_PORT}"
    headers = {"Host": host, "Cookie": "__Host-kvm_sid=browser-secret"}
    async with TestServer(app) as server:
        async with aiohttp.ClientSession() as browser:
            async with browser.get(server.make_url("/_platform/stats"), headers=headers) as response:
                assert response.status == 200
                session = (await response.json())["session"]
    assert session["state"] == "recovering"
    assert session["recoveries"] == 1 and session["dropped_input"] == 3
