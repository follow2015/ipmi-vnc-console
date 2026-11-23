"""iDRAC built-in VNC (bare TCP RFB) transport and admission tests."""
from __future__ import annotations

import asyncio
import struct

import pytest

from kvmhub.adapters.idrac_vnc import IdracVncAdapter
from kvmhub.common import (IDRAC_VNC_ADAPTER_ID, Problem,
                           require_controlled_host)
from kvmhub.platform.data_plane import assembled_info
from kvmhub.rfb_tcp_upstream import (RfbTcpConfig, RfbTcpUpstream,
                                     StandardRfbBrowserHandshake,
                                     vnc_auth_response, vnc_des_key)
from kvmhub.vnc_des import des_ecb_encrypt
from kvmhub.worker import make_adapter

INFO = {"adapter": IDRAC_VNC_ADAPTER_ID, "target": "https://192.0.2.84"}



def test_des_primitive_matches_known_vector():
    key = bytes.fromhex("133457799BBCDFF1")
    plain = bytes.fromhex("0123456789ABCDEF")
    assert des_ecb_encrypt(plain, key) == bytes.fromhex("85E813540F0AB405")


def test_vnc_key_is_eight_chars_with_reversed_bits():
    assert vnc_des_key("password") == bytes(
        int(f"{b:08b}"[::-1], 2) for b in b"password")
    assert len(vnc_des_key("123456789")) == 8
    with pytest.raises(ValueError):
        vnc_des_key("")


def test_vnc_auth_response_is_two_deterministic_des_blocks():
    challenge = bytes(range(16))
    response = vnc_auth_response(challenge, "admin")
    assert isinstance(response, bytes) and len(response) == 16
    assert response == vnc_auth_response(challenge, "admin")
    assert response != vnc_auth_response(challenge, "other")
    assert challenge == bytes(range(16))
    with pytest.raises(ValueError):
        vnc_auth_response(b"short", "admin")


def test_config_never_reprs_the_password():
    cfg = RfbTcpConfig(host="192.0.2.84", password="synthetic-password")
    assert "synthetic-password" not in repr(cfg)
    with pytest.raises(ValueError):
        RfbTcpConfig(host="user@192.0.2.84", password="x")



def test_standard_browser_handshake_is_credential_free():
    server_init = struct.pack(">HH", 1024, 768) + bytes(16) + struct.pack(">I", 0)
    hs = StandardRfbBrowserHandshake(server_init)
    assert hs.start() == b"RFB 003.008\n"

    out, _ = hs.feed(b"RFB 003.008\n")
    assert out == b"\x01\x01"
    out, _ = hs.feed(b"\x01")
    assert out == b"\x00\x00\x00\x00"
    out, trailing = hs.feed(b"\x00" + b"\x02\x00\x00\x09\x00\x00")
    assert hs.completed is True
    assert out == server_init
    assert trailing == b"\x02\x00\x00\x09\x00\x00"

    with pytest.raises(ValueError):
        hs.feed(b"\x00" * (4096 * 16 + 1))
    out, after = hs.feed(b"\x03\x00\x00\x00\x00")
    assert out == b"" and after == b"\x03\x00\x00\x00\x00"


def test_novnc_text_frames_complete_handshake_then_input_stays_binary():
    from kvmhub.passthrough import RfbPassthroughSession

    server_init = (struct.pack(">HH", 800, 600) + bytes(16)
                   + struct.pack(">I", 7) + b"OpenVNC")

    class _Upstream:
        def __init__(self):
            self.sent = []
        async def relay(self, on_bytes):
            await asyncio.Event().wait()
        async def send_raw(self, data):
            self.sent.append(bytes(data))
        async def close(self):
            pass

    async def scenario():
        up = _Upstream()
        hs = StandardRfbBrowserHandshake(server_init)
        s = RfbPassthroughSession(up, hs)
        await s.start()
        greeting = await s.__anext__()
        assert greeting.data == b"RFB 003.008\n"
        await s.send_str("RFB 003.008\n")
        sec_types = await s.__anext__()
        assert sec_types.data == b"\x01\x01"
        await s.send_str("\x01")
        sec_result = await s.__anext__()
        assert sec_result.data == b"\x00\x00\x00\x00"
        await s.send_str("\x01")
        init = await s.__anext__()
        assert init.data == server_init
        assert hs.completed
        await s.send_str("x")
        assert s.error == "unexpected_text_frame"

    asyncio.run(scenario())


def test_browser_handshake_rejects_wrong_security_type():
    server_init = struct.pack(">HH", 8, 8) + bytes(16) + struct.pack(">I", 0)
    hs = StandardRfbBrowserHandshake(server_init)
    hs.start()
    hs.feed(b"RFB 003.008\n")
    with pytest.raises(ValueError):
        hs.feed(b"\x02")



SERVER_INIT = (struct.pack(">HH", 640, 480) + bytes(16)
               + struct.pack(">I", 5) + b"iDRAC")


def fake_rfb_server(*, password: str = "local-admin", bad_auth: bool = False):
    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            writer.write(b"RFB 003.008\n")
            await writer.drain()
            assert await reader.readexactly(12) == b"RFB 003.008\n"
            writer.write(b"\x01\x02")
            await writer.drain()
            assert await reader.readexactly(1) == b"\x02"
            challenge = bytes(range(16))
            writer.write(challenge)
            await writer.drain()
            expected = vnc_auth_response(challenge, password)
            got = await reader.readexactly(16)
            result = 1 if bad_auth or got != expected else 0
            writer.write(struct.pack(">I", result) + (b"\x00\x00\x00\x04nope" if result else b""))
            await writer.drain()
            if result:
                return
            assert await reader.readexactly(1) == b"\x01"
            writer.write(SERVER_INIT)
            await writer.drain()
            writer.write(b"FRAME")
            await writer.drain()
            await reader.read(10)
            writer.write(b"MORE")
            await writer.drain()
            await asyncio.sleep(0.2)
        finally:
            writer.close()

    return handler


@pytest.mark.asyncio
async def test_upstream_handshakes_relays_and_sends_client_messages():
    server = await asyncio.start_server(fake_rfb_server(), "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    upstream = RfbTcpUpstream(RfbTcpConfig(host="127.0.0.1", port=port, password="local-admin"))
    try:
        await upstream.connect()
        assert upstream.protocol_version == "RFB 003.008"
        assert upstream.stats.security_type == 2
        assert upstream.server_init_raw == SERVER_INIT
        assert (upstream.stats.width, upstream.stats.height) == (640, 480)

        seen: list[bytes] = []

        async def collect(data: bytes):
            seen.append(data)

        relay = asyncio.create_task(upstream.relay(collect))
        await asyncio.sleep(0.05)
        await upstream.send_raw(b"\x03\x00\x00\x00\x00\x00\x02\x80\x00\x3c")
        await asyncio.sleep(0.15)
        relay.cancel()
        with pytest.raises(asyncio.CancelledError):
            await relay
        assert b"FRAME" in b"".join(seen)
        assert "local-admin" not in repr(upstream.cfg)
    finally:
        await upstream.close()
        server.close()
        await server.wait_closed()
    assert upstream.cfg.password == ""


@pytest.mark.asyncio
async def test_bad_vnc_password_maps_to_bmc_auth_failed():
    server = await asyncio.start_server(fake_rfb_server(password="synthetic-password"),
                                        "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    upstream = RfbTcpUpstream(RfbTcpConfig(host="127.0.0.1", port=port, password="wrong"))
    with pytest.raises(Problem) as exc:
        await upstream.connect()
    assert exc.value.code == "bmc_auth_failed"
    await upstream.close()
    server.close()
    await server.wait_closed()



def test_handshake_trace_records_phases_without_sensitive_payload():
    async def scenario():
        server = await asyncio.start_server(fake_rfb_server(), "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        up = RfbTcpUpstream(RfbTcpConfig(host="127.0.0.1", port=port,
                                        password="local-admin"))
        try:
            await up.connect()
            trace = up.stats.trace.as_dict()
            for phase in ("tcp_connect", "greeting", "security_types",
                          "challenge", "security_result", "server_init"):
                assert phase in trace["elapsed_ms"]
                assert trace["elapsed_ms"][phase] >= 0
            assert trace["stage"] == "server_init"
            assert trace["failure_reason"] == ""
            assert trace["offered_security_types"] == [2]
            assert all(isinstance(t, int) for t in trace["offered_security_types"])
            dumped = str(up.stats.as_dict())
            assert "RFB 003.008" in dumped
            assert "iDRAC" not in dumped
            assert "local-admin" not in dumped
        finally:
            await up.close()
            server.close()
            await server.wait_closed()

    asyncio.run(scenario())


def test_failed_greeting_locates_stage_with_stable_reason():
    async def handler(reader, writer):
        writer.write(b"RFB 999.999\n")
        await writer.drain()
        await asyncio.sleep(0.1)
        writer.close()

    async def scenario():
        server = await asyncio.start_server(handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        up = RfbTcpUpstream(RfbTcpConfig(host="127.0.0.1", port=port,
                                        password="local-admin"))
        with pytest.raises(Problem):
            await up.connect()
        trace = up.stats.trace.as_dict()
        assert trace["stage"] == "greeting"
        assert trace["failure_reason"] == "greeting_invalid"
        assert "NOT-RFB" not in str(trace)
        await up.close()
        server.close()
        await server.wait_closed()

    asyncio.run(scenario())


def test_bad_auth_reports_stable_auth_failed_reason():
    async def scenario():
        server = await asyncio.start_server(fake_rfb_server(password="synthetic-password"),
                                            "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        up = RfbTcpUpstream(RfbTcpConfig(host="127.0.0.1", port=port, password="wrong"))
        with pytest.raises(Problem) as exc:
            await up.connect()
        assert exc.value.code == "bmc_auth_failed"
        trace = up.stats.trace.as_dict()
        assert trace["stage"] == "security_result"
        assert trace["failure_reason"] == "auth_failed"
        assert "nope" not in str(trace)
        await up.close()
        server.close()
        await server.wait_closed()

    asyncio.run(scenario())


def test_relay_chunks_are_not_reported_as_framebuffer_updates():
    async def scenario():
        server = await asyncio.start_server(fake_rfb_server(), "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        up = RfbTcpUpstream(RfbTcpConfig(host="127.0.0.1", port=port,
                                        password="local-admin"))
        try:
            await up.connect()
            assert up.stats.frames == 0
            assert up.stats.chunks == 0

            async def collect(data):
                return

            relay = asyncio.create_task(up.relay(collect))
            await asyncio.sleep(0.15)
            relay.cancel()
            with pytest.raises(asyncio.CancelledError):
                await relay
            d = up.stats.as_dict()
            assert d["chunks"] > 0
            assert d["frames"] == d["chunks"]
        finally:
            await up.close()
            server.close()
            await server.wait_closed()

    asyncio.run(scenario())



def test_controlled_network_gate_requires_explicit_cidr():
    for networks in ("", "not-a-cidr"):
        with pytest.raises(Exception):
            require_controlled_host("192.0.2.84", networks)
    require_controlled_host("192.0.2.84", "192.0.2.0/24")
    require_controlled_host("192.0.2.84", ("192.0.2.0/8", "192.0.2.0/24"))
    with pytest.raises(Problem) as exc:
        require_controlled_host("8.8.8.8", "192.0.2.0/24")
    assert exc.value.code == "bmc_network_not_allowed"
    with pytest.raises(Problem):
        require_controlled_host("idrac.example.com", "192.0.2.0/24")


def test_adapter_and_worker_require_controlled_network(monkeypatch):
    monkeypatch.setenv("KVMHUB_BMC_ALLOWED_NETWORKS", "192.0.2.0/24")
    adapter = make_adapter(dict(INFO))
    assert isinstance(adapter, IdracVncAdapter)
    assert adapter.host == "192.0.2.84"
    assert adapter.port == 5901
    with pytest.raises(Problem):
        make_adapter(dict(INFO, target="https://8.8.8.8"))

    monkeypatch.setenv("KVMHUB_BMC_ALLOWED_NETWORKS", "")
    with pytest.raises(Problem):
        make_adapter(dict(INFO))


def test_store_gate_matches_adapter_gate():
    from kvmhub.store import Store

    store = Store.__new__(Store)
    store.passthrough_targets = frozenset({"https://192.0.2.84", "https://8.8.8.8"})
    import ipaddress
    store.bmc_allowed_networks = (ipaddress.ip_network("192.0.2.0/24"),)
    assert store._adapter_allowed({"adapter": IDRAC_VNC_ADAPTER_ID,
                                   "target": "https://192.0.2.84"})
    assert not store._adapter_allowed({"adapter": IDRAC_VNC_ADAPTER_ID,
                                       "target": "https://8.8.8.8"})


def test_assembly_allows_standard_message_profile_for_builtin_vnc():
    info = dict(INFO)
    assembly = {"data_plane": {"adapter": IDRAC_VNC_ADAPTER_ID,
                               "capability_entry": {"adapter": IDRAC_VNC_ADAPTER_ID,
                                                    "protocol_versions": ["RFB 003.008"]}},
                "plan": {"rfb_version": "RFB 003.008", "message_profile": "standard"}}
    applied = assembled_info(info, assembly)
    assert applied["adapter"] == IDRAC_VNC_ADAPTER_ID
    assert applied["message_profile"] == "standard"


def test_worker_serves_real_console_page_for_builtin_vnc():
    import inspect

    from kvmhub import worker

    source = inspect.getsource(worker.Gateway.handle)
    assert "IdracVncAdapter" in source
