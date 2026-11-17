"""Fixed-Host path session addressing (P1, construction design §9.1)."""
import asyncio
import json
import re
import time
from types import SimpleNamespace

import aiohttp
import pytest
from aiohttp import web
from aiohttp.test_utils import TestServer
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from kvmhub import common as common_module
from kvmhub.common import WORKER_PORT, digest, issue, server_tls
from kvmhub import worker as worker_module
from kvmhub.worker import GATEWAY_KEY, Runtime, create_worker
from kvmhub.platform.bus import AssemblyBus
from kvmhub.platform.console import ConsolePlane
from kvmhub.platform.redis_state import MemoryState
from tools.bootstrap import generate


@pytest.fixture
def identities(tmp_path):
    directory = generate(tmp_path / "identity")
    return directory, json.loads((directory / "worker.json").read_text())


@pytest.fixture
def path_mode(monkeypatch):
    monkeypatch.setattr(common_module, "SESSION_MODE", "path", raising=True)
    monkeypatch.setattr(common_module, "BASE_PATH", "", raising=True)
    return "path"


@pytest.fixture
def subpath_mode(monkeypatch):
    monkeypatch.setattr(common_module, "SESSION_MODE", "path", raising=True)
    monkeypatch.setattr(common_module, "BASE_PATH", "/kvm", raising=True)
    return "/kvm"


def _install_session(cfg, sid, *, cookie="browser-secret"):
    app = create_worker(cfg)
    app.on_startup.clear()
    app.on_cleanup.clear()
    gateway = app[GATEWAY_KEY]
    runtime = Runtime(sid, digest(cookie), None, time.monotonic() + 30)
    gateway.sessions[sid] = runtime
    return app, gateway, runtime


def _cookie_header(sid, cookie="browser-secret"):
    name = worker_module.cookie_name_for(sid)
    return {"Cookie": f"{name}={cookie}"}



async def test_query_string_does_not_corrupt_resolved_path(identities, path_mode):
    _, cfg = identities
    sid = "a" * 32
    app, _, _ = _install_session(cfg, sid)
    url = f"/s/{sid}/_platform/meta?t=1&x=2"
    async with TestServer(app) as server:
        async with aiohttp.ClientSession() as browser:
            async with browser.get(server.make_url(url),
                                   headers=_cookie_header(sid)) as response:
                assert response.status == 200
                assert await response.json() == {"address": "未接入", "asset_id": ""}



async def test_fetch_asset_receives_unprefixed_path(identities, path_mode, monkeypatch):
    _, cfg = identities
    sid = "b" * 32
    app, gateway, runtime = _install_session(cfg, sid)

    class _FakeAdapter:
        connection_limit = 4
        asset_pattern = re.compile(r"^/novnc/include/[A-Za-z0-9_.-]{1,64}\.js$")
        calls = []

        async def fetch_asset(self, path):
            self.calls.append(path)
            return "application/javascript", b"// js"

    fake = _FakeAdapter()
    runtime.adapter = fake
    monkeypatch.setattr(worker_module, "PassthroughAdapter", _FakeAdapter, raising=True)
    async with TestServer(app) as server:
        async with aiohttp.ClientSession() as browser:
            async with browser.get(server.make_url(f"/s/{sid}/novnc/include/rfb.js"),
                                   headers=_cookie_header(sid)) as response:
                assert response.status == 200
                assert await response.text() == "// js"
    assert fake.calls == ["/novnc/include/rfb.js"], fake.calls



@pytest.mark.parametrize("evil", [
    "/s/{sid}/%2e%2e%2f%2e%2e%2fetc/passwd",
    "/s/{sid}/novnc/..%2f..%2fetc/passwd",
    "/s/{sid}/%2e%2e/etc/passwd",
    "/s/{sid}/novnc%2f%2finclude/rfb.js",
])
async def test_path_traversal_is_403_and_never_fetches(identities, path_mode, evil):
    _, cfg = identities
    sid = "c" * 32
    app, gateway, runtime = _install_session(cfg, sid)

    class _FakeAdapter:
        connection_limit = 4
        asset_pattern = re.compile(r"^/.*$")
        calls = []

        async def fetch_asset(self, path):
            self.calls.append(path)
            return "text/plain", b"secret"

    fake = _FakeAdapter()
    runtime.adapter = fake
    async with TestServer(app) as server:
        async with aiohttp.ClientSession() as browser:
            async with browser.get(server.make_url(evil.format(sid=sid)),
                                   headers=_cookie_header(sid)) as response:
                assert response.status in (403, 421)
    assert fake.calls == [], fake.calls



def test_cookie_name_is_scoped_to_sid(path_mode):
    a = worker_module.cookie_name_for("a" * 32)
    b = worker_module.cookie_name_for("b" * 32)
    assert a != b
    assert a.startswith("__Secure-kvm_")
    assert "__Host-" not in a


async def test_two_sessions_do_not_share_cookie(identities, path_mode):
    _, cfg = identities
    sid_a, sid_b = "d" * 32, "e" * 32
    app, gateway, _ = _install_session(cfg, sid_a)
    runtime_b = Runtime(sid_b, digest("secret-b"), None, time.monotonic() + 30)
    gateway.sessions[sid_b] = runtime_b
    async with TestServer(app) as server:
        async with aiohttp.ClientSession() as browser:
            url_a = server.make_url(f"/s/{sid_a}/_platform/meta")
            url_b = server.make_url(f"/s/{sid_b}/_platform/meta")
            async with browser.get(url_a, headers=_cookie_header(sid_a, "browser-secret")) as r:
                assert r.status == 200
            async with browser.get(url_b, headers=_cookie_header(sid_b, "secret-b")) as r:
                assert r.status == 200
            async with browser.get(url_a, headers=_cookie_header(sid_a, "secret-b")) as r:
                assert r.status == 401



async def test_accept_303_is_relative(identities, path_mode):
    redirect = worker_module.accept_redirect_location("f" * 32)
    assert redirect == "../"
    assert not redirect.startswith("/")


async def test_path_mode_accept_303_uses_ticket_sid(identities, path_mode, monkeypatch):
    directory, cfg = identities
    private = load_pem_private_key((directory / "signing.key").read_bytes(), password=None)
    sid = "e" * 32
    now = time.time()
    row = {"id": sid, "jti": "f" * 32, "user_id": "user-1", "asset_id": "asset-1",
           "worker_id": cfg["worker_id"], "instance_id": cfg["instance_id"],
           "hard_until": now + 120}
    ticket = issue(private, row, now, trace="a" * 32)

    app = create_worker(cfg)
    app.on_startup.clear()
    app.on_cleanup.clear()
    gateway = app[GATEWAY_KEY]

    async def call(_sid, operation, data=None):
        if operation == "exchange":
            return {"hard_until": now + 120, "lease_seconds": 30,
                    "username": "u", "password": "p"}
        return {"lease_seconds": 30}

    async def apply(_sid, info, **_kwargs):
        return info

    async def report(*args, **kwargs):
        return None

    class FakeAdapter:
        async def login(self, *_args):
            return True

        async def close(self):
            return True

    gateway.call = call
    gateway.apply_assembly = apply
    gateway.report = report
    monkeypatch.setattr(worker_module, "make_adapter", lambda _info: FakeAdapter())
    monkeypatch.setattr(worker_module, "wire_recovery", lambda adapter, _recovery: adapter)

    async with TestServer(app) as server:
        async with aiohttp.ClientSession() as browser:
            response = await browser.post(
                server.make_url(f"/s/{sid}/_platform/accept"),
                data={"ticket": ticket},
                headers={"Origin": cfg["manager_origin"]},
                allow_redirects=False)
            assert response.status == 303
            assert response.headers["Location"] == "../"
            assert f"__Secure-kvm_{sid}=" in response.headers.get("Set-Cookie", "")
            cookie = response.headers["Set-Cookie"].split(";", 1)[0]
            meta = await browser.get(server.make_url(f"/s/{sid}/_platform/meta"),
                                     headers={"Cookie": cookie})
            assert meta.status == 200
            assert (await meta.json())["asset_id"] == "asset-1"
    await gateway.finish(gateway.sessions[sid], "client_closed")


async def test_subpath_redirect_stays_under_base(subpath_mode):
    redirect = worker_module.accept_redirect_location("1" * 32)
    assert redirect == "../"
    assert worker_module.route_prefix_for("1" * 32) == "/kvm/s/" + "1" * 32


def test_route_prefix_includes_base_path(subpath_mode):
    assert worker_module.route_prefix_for("2" * 32) == "/kvm/s/" + "2" * 32


def test_subpath_localizes_manager_api_for_renewal(subpath_mode):
    sid = "4" * 32

    class _Req:
        def get(self, key, default=None):
            return worker_module.route_prefix_for(sid) if key is worker_module.ROUTE_PREFIX_KEY else default

    js = worker_module.localize_console(worker_module.REAL_CONSOLE_JS, _Req())
    assert "'/kvm/api/v2/me'" in js
    assert "'/kvm/api/v2/consoles/open'" in js


def test_console_html_and_js_are_localized(path_mode):
    sid = "3" * 32
    prefix = worker_module.route_prefix_for(sid)
    prefix = prefix[len(common_module.BASE_PATH):]

    class _Req:
        def get(self, key, default=None):
            return prefix if key is worker_module.ROUTE_PREFIX_KEY else default

    req = _Req()
    html = worker_module.localize_console(worker_module.REAL_CONSOLE_HTML, req)
    js = worker_module.localize_console(worker_module.REAL_CONSOLE_JS, req)
    assert f'"{prefix}/novnc/include/rfb.js"' in html
    assert f"'{prefix}/_platform/console.js'" in html or f'"{prefix}/_platform/console.js"' in html
    assert f"'{prefix.lstrip('/')}/console'" in js
    assert '"/novnc/' not in html and "'/novnc/" not in html
    assert "'/_platform/" not in js and '"/_platform/' not in js
    assert "var routeProbeEnabled = true;" in js
    assert "function requestNewConsole()" in js
    assert "response.status === 404" in js


def test_host_mode_does_not_localize(monkeypatch):
    monkeypatch.setattr(common_module, "SESSION_MODE", "host", raising=True)
    original = worker_module.REAL_CONSOLE_HTML
    assert worker_module.localize_console(original, object()) == original
    script = worker_module.REAL_CONSOLE_JS
    assert worker_module.localize_console(script, object()) == script
    assert "var routeProbeEnabled = false;" in script



async def test_host_mode_still_works(identities, monkeypatch):
    monkeypatch.setattr(common_module, "SESSION_MODE", "host", raising=True)
    _, cfg = identities
    sid = "9" * 32
    app, _, _ = _install_session(cfg, sid)
    host = f"w1-{sid}.kvm.localhost:{WORKER_PORT}"
    async with TestServer(app) as server:
        async with aiohttp.ClientSession() as browser:
            url = server.make_url("/_platform/meta")
            async with browser.get(url, headers={
                "Host": host, "Cookie": "__Host-kvm_sid=browser-secret"}) as response:
                assert response.status == 200



def test_accept_template_formats_fixed_host_path(identities):
    sid = "b" * 32
    plane = ConsolePlane(
        private_key=object(), bus=AssemblyBus(MemoryState()), store=object(),
        accept_template="https://192.0.2.10/s/{sid}/_platform/accept")
    assert plane.accept_url(worker_id="w1", sid=sid) == (
        "https://192.0.2.10/s/" + sid + "/_platform/accept")



def test_route_key_can_be_read_and_removed():
    bus = AssemblyBus(MemoryState())
    sid = "c" * 32
    payload = {"upstream": "127.0.0.1:29443", "worker_id": "w1"}
    asyncio.run(bus.put_route(sid, payload, 60))
    assert asyncio.run(bus.get_route(sid)) == payload
    asyncio.run(bus.delete_route(sid))
    assert asyncio.run(bus.get_route(sid)) is None


async def test_worker_finish_deletes_route_at_source(identities):
    _, cfg = identities
    bus = AssemblyBus(MemoryState())
    deleted = []

    async def delete_route(sid):
        deleted.append(sid)

    bus.delete_route = delete_route
    app = create_worker(cfg, assembly_bus=bus)
    app.on_startup.clear()
    app.on_cleanup.clear()
    gateway = app[GATEWAY_KEY]
    sid = "d" * 32

    async def close():
        return True

    sess = Runtime(sid, digest("cookie"), SimpleNamespace(close=close),
                   time.monotonic() + 30)
    gateway.sessions[sid] = sess

    async def no_report(*args, **kwargs):
        return None

    gateway.report = no_report
    await gateway.finish(sess, "client_closed")
    assert deleted == [sid]
    assert sid not in gateway.sessions


def test_worker_upstream_validation_is_shared():
    worker = {"metadata": {"address": "127.0.0.1", "port": 29443}}
    assert ConsolePlane._worker_upstream(worker) == "127.0.0.1:29443"
    for bad in ({"metadata": {}}, {"metadata": {"address": "8.8.8.8", "port": 1}},
                {"metadata": {"address": "127.0.0.1", "port": 0}}):
        try:
            ConsolePlane._worker_upstream(bad)
        except Exception:
            continue
        raise AssertionError(f"invalid upstream accepted: {bad}")
