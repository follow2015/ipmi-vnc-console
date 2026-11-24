"""ATEN Java ticket boundaries, TCP handshake, input framing and cleanup."""
import asyncio
import struct
from xml.etree import ElementTree as ET

import pytest

from kvmhub.aten_java_upstream import AtenJavaUpstream, parse_java_launch
from kvmhub.adapters.aten_java import AtenJavaAdapter
from kvmhub.common import ATEN_JAVA_ADAPTER_ID, Problem
from kvmhub.passthrough import ClientMessageFramer, ClientMessageError, INSYDE_CLIENT_MESSAGES, INSYDE_MESSAGE_SIZES
from kvmhub.worker import make_adapter, input_protocol_for_adapter

HOST = "192.0.2.41"
PIN = "ab" * 32
USER_TICKET = "u" * 16
PASS_TICKET = "p" * 16
INIT = struct.pack(">HH", 720, 400) + bytes([32, 24, 0, 1]) + struct.pack(">HHH", 255, 255, 255) + bytes([16, 8, 0, 0, 0, 0]) + struct.pack(">I", 4) + b"test" + bytes(4) + struct.pack(">I", 7) + bytes([1, 1, 1, 1])


def launch(**changes):
    args = [HOST, USER_TICKET, PASS_TICKET, "test", "5900", "623", "0", "0", "0", "test"]
    for key, val in changes.items():
        args[int(key)] = val
    root = ET.Element("jnlp", codebase=f"https://{HOST}/")
    app = ET.SubElement(root, "application-desc", {"main-class": "tw.com.aten.ikvm.KVMMain"})
    for value in args:
        ET.SubElement(app, "argument").text = value
    return ET.tostring(root)


def test_launcher_returns_only_transient_tokens():
    assert parse_java_launch(launch(), HOST) == (USER_TICKET, PASS_TICKET)


@pytest.mark.parametrize("index,value", [(0, "192.0.2.99"), (4, "22"), (8, "1"),
                                         (1, "short"), (2, "x" * 25), (1, "x" * 15 + "\n")])
def test_launcher_refuses_target_or_protocol_drift(index, value):
    with pytest.raises(ValueError, match="^invalid_java_launch$"):
        parse_java_launch(launch(**{str(index): value}), HOST)


@pytest.mark.parametrize("body", [b"<bad", b"<!DOCTYPE jnlp><jnlp/>",
                                  "<!DOCTYPE jnlp><jnlp/>".encode("utf-16"),
                                  b"x" * (512 * 1024 + 1)])
def test_launcher_is_bounded_and_rejects_entities(body):
    with pytest.raises(ValueError):
        parse_java_launch(body, HOST)


def test_foreign_codebase_rejected():
    with pytest.raises(ValueError):
        parse_java_launch(launch().replace(HOST.encode(), b"192.0.2.99", 1), HOST)


def test_network_and_pin_gate_precede_network(monkeypatch):
    with pytest.raises(Problem, match="bmc_network_not_allowed"):
        AtenJavaUpstream(HOST, PIN, networks=[])
    with pytest.raises(Problem):
        AtenJavaUpstream("localhost", PIN, networks=["127.0.0.0/8"])
    with pytest.raises(Problem, match="invalid_target_policy"):
        AtenJavaUpstream(HOST, "bad", networks=[HOST + "/32"])
    monkeypatch.setenv("KVMHUB_BMC_ALLOWED_NETWORKS", HOST + "/32")
    adapter = make_adapter({"adapter": ATEN_JAVA_ADAPTER_ID, "target": f"https://{HOST}",
                            "fingerprint": PIN, "protocol_versions": ("RFB 003.008",)})
    assert isinstance(adapter, AtenJavaAdapter)
    assert input_protocol_for_adapter(adapter) == "insyde18"


def test_input_frames_cannot_reach_power_or_virtual_media():
    f = ClientMessageFramer(INSYDE_CLIENT_MESSAGES, sizes=INSYDE_MESSAGE_SIZES)
    key = struct.pack(">BBBHI", 4, 0, 1, 0, 4) + bytes(9)
    assert f.feed(key[:7]) == b""
    assert f.feed(key[7:]) == key
    for kind in (6, 21, 23, 24, 59, 60, 61):
        with pytest.raises(ClientMessageError):
            ClientMessageFramer(INSYDE_CLIENT_MESSAGES, sizes=INSYDE_MESSAGE_SIZES).feed(bytes([kind]) + bytes(30))


class FakeHTTP:
    closed = False
    async def close(self):
        self.closed = True


@pytest.mark.asyncio
@pytest.mark.parametrize("fragment", [1, 37])
async def test_real_tcp_handshake_fragmentation_and_cleanup(monkeypatch, fragment):
    errors = []
    done = asyncio.Event()
    async def server(reader, writer):
        try:
            async def send(data):
                for pos in range(0, len(data), fragment):
                    writer.write(data[pos:pos + fragment])
                    await writer.drain()
                    await asyncio.sleep(0)
            await send(b"RFB 003.008\n")
            assert await reader.readexactly(12) == b"RFB 003.008\n"
            await send(b"\x01\x10")
            assert await reader.readexactly(1) == b"\x10"
            await send(bytes(range(24)))
            assert await reader.readexactly(48) == USER_TICKET.encode().ljust(24, b"\0") + PASS_TICKET.encode().ljust(24, b"\0")
            await send(bytes(4))
            assert await reader.readexactly(1) == b"\0"
            await send(INIT + b"\x02")
            assert await reader.read() == b""
        except Exception as exc:
            errors.append(exc)
        finally:
            writer.close()
            done.set()
    srv = await asyncio.start_server(server, "127.0.0.1", 0)
    connect = asyncio.open_connection
    async def dial(host, port):
        assert (host, port) == (HOST, 5900)
        return await connect("127.0.0.1", srv.sockets[0].getsockname()[1])
    monkeypatch.setattr(asyncio, "open_connection", dial)
    http = FakeHTTP()
    monkeypatch.setattr("kvmhub.aten_java_upstream.aiohttp.ClientSession", lambda **kwargs: http)
    upstream = AtenJavaUpstream(HOST, PIN, networks=[HOST + "/32"])
    calls = []
    async def request(path, **kwargs):
        calls.append(path)
        if path == "/cgi/login.cgi":
            upstream._cookies = {"SID": "synthetic-session"}
            return 200, b""
        if "ikvm&" in path:
            return 200, launch()
        return 200, b"<script>SessionTimeout();</script>"
    monkeypatch.setattr(upstream, "_request", request)
    try:
        await upstream.login("synthetic-user", "synthetic-password")
        assert upstream.server_init_raw == INIT
        assert await upstream._read(1) == b"\x02"
        assert await upstream.close()
        await asyncio.wait_for(done.wait(), 2)
        assert not errors
        assert calls[-2:] == ["/cgi/logout.cgi", "/cgi/url_redirect.cgi?url_name=mainmenu"]
        assert http.closed and not upstream._cookies
        assert await upstream.close()
    finally:
        await upstream.close()
        srv.close()
        await srv.wait_closed()


@pytest.mark.asyncio
async def test_cleanup_requires_revocation_confirmation(monkeypatch):
    upstream = AtenJavaUpstream(HOST, PIN, networks=[HOST + "/32"])
    upstream._http = FakeHTTP()
    upstream._cookies = {"SID": "synthetic"}
    upstream._login_attempted = True
    async def request(*args, **kwargs):
        return 200, b"<html>still logged in</html>"
    monkeypatch.setattr(upstream, "_request", request)
    assert not await upstream.close()
    assert upstream.cleanup_outcome == "unconfirmed"


@pytest.mark.asyncio
async def test_timed_out_login_cannot_claim_no_residual_session():
    upstream = AtenJavaUpstream(HOST, PIN, networks=[HOST + "/32"])
    upstream._http = FakeHTTP()
    upstream._login_attempted = True
    assert not await upstream.close()


@pytest.mark.parametrize("changes", [
    {"target": f"https://{HOST}:not-a-port"}, {"rfb_version": "RFB 055.008", "protocol_versions": ["RFB 055.008"]},
    {"message_profile": "standard"}, {"protocol": "supermicro-ikvm-html5"},
    {"login_path": "/cgi/other.cgi"}, {"input_shaping": {"min_hold_ms": 25}},
])
def test_adapter_refuses_unimplemented_profile_settings(changes):
    with pytest.raises(Problem, match="invalid_target_policy"):
        AtenJavaAdapter({"adapter": ATEN_JAVA_ADAPTER_ID, "target": f"https://{HOST}",
                         "fingerprint": PIN, **changes}, networks=[HOST + "/32"])


@pytest.mark.asyncio
async def test_bad_tls_pin_never_sends_credentials(tmp_path):
    import aiohttp
    from aiohttp import web
    from aiohttp.test_utils import TestServer
    import json
    from kvmhub.common import server_tls
    from tools.bootstrap import generate
    root = generate(tmp_path / "identities")
    cfg = json.loads((root / "worker.json").read_text())
    requests = []
    async def handler(request):
        requests.append(await request.read())
        return web.Response(text="unexpected")
    app = web.Application()
    app.router.add_post("/cgi/login.cgi", handler)
    server = TestServer(app, scheme="https")
    await server.start_server(ssl=server_tls(cfg["server_cert"], cfg["server_key"]))
    upstream = AtenJavaUpstream("127.0.0.1", "00" * 32, networks=["127.0.0.1/32"])
    class LocalSession:
        def __init__(self, actual):
            self.actual = actual
        def request(self, method, url, **kwargs):
            return self.actual.request(method, str(server.make_url("/cgi/login.cgi")), **kwargs)
        async def close(self):
            await self.actual.close()
    actual_factory = aiohttp.ClientSession
    from unittest.mock import patch
    with patch("kvmhub.aten_java_upstream.aiohttp.ClientSession",
               side_effect=lambda **kwargs: LocalSession(actual_factory(**kwargs))):
        try:
            with pytest.raises(Problem, match="upstream_unavailable"):
                await upstream.login("synthetic-user", "synthetic-password")
            assert requests == []
            assert await upstream.close()
        finally:
            await upstream.close()
            await server.close()


def test_manager_requires_both_target_and_controlled_network(tmp_path):
    from kvmhub.store import Store
    store = Store(tmp_path / "gate.sqlite", b"k" * 32, passthrough_targets=(f"https://{HOST}",),
                  bmc_allowed_networks=())
    row = {"adapter": ATEN_JAVA_ADAPTER_ID, "target": f"https://{HOST}"}
    try:
        assert not store._adapter_allowed(row)
        import ipaddress
        store.bmc_allowed_networks = (ipaddress.ip_network(HOST + "/32"),)
        assert store._adapter_allowed(row)
        assert not store._adapter_allowed({**row, "target": "https://192.0.2.99"})
        store.passthrough_targets = frozenset()
        assert not store._adapter_allowed(row)
    finally:
        store.close()
