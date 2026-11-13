"""Tests for the real-device upstream transport against a synthetic BMC."""
from __future__ import annotations

import asyncio
import struct
from types import SimpleNamespace

import aiohttp
import pytest
from aiohttp import web

from kvmhub.adapters import SupermicroX10IKVMAdapter
from kvmhub.ast2100_protocol import ENCODING_AST2100
from kvmhub.common import Problem
from kvmhub.passthrough import BrowserHandshake
from kvmhub.rfb_upstream import (
    DEFAULT_ENCODINGS,
    MAX_TICKET_CHARS,
    RfbUpstream,
    UpstreamConfig,
    absorb_set_cookie,
    encode_auth_response,
    extract_ticket,
    set_encodings,
)

from tests.support.fake_bmc import PASSWORD, TICKET, FakeBmc, config_for, opened



@pytest.fixture
async def fake_bmc():
    server = await FakeBmc().start()
    try:
        yield server
    finally:
        await server.stop()




async def test_handshake_and_first_frames(fake_bmc):
    upstream = await opened(fake_bmc)
    try:
        assert upstream.server_init is not None
        assert (upstream.stats.width, upstream.stats.height) == (1024, 768)
        assert upstream.stats.frames >= 5
        assert await upstream.wait_frames(2, timeout=5) == 2
        assert upstream.stats.framebuffer_updates == 2
        assert upstream.stats.encodings == {87}
        assert upstream.stats.modes == {0}
        assert 87 in next(m for m in fake_bmc.client_messages if m[0] == "SetEncodings")[1]
        request = next(m for m in fake_bmc.client_messages if m[0] == "FBURequest")
        assert request[2:] == (0, 0, 1024, 768)
    finally:
        assert await upstream.close() == "ok"


async def test_ticket_is_single_use_and_never_exposed(fake_bmc):
    upstream = await opened(fake_bmc)
    try:
        assert upstream._ticket is None
        assert fake_bmc.response_seen == encode_auth_response(TICKET)
        assert TICKET not in repr(upstream.stats.as_dict())
        assert "ticket" not in repr(upstream.stats.as_dict()).lower()
        assert TICKET not in repr(vars(upstream.cfg))
    finally:
        await upstream.close()


async def test_no_subprotocol_and_cookie_authenticated_websocket(fake_bmc):
    upstream = await opened(fake_bmc)
    try:
        assert "sec-websocket-protocol" not in fake_bmc.ws_headers
        assert "cookie" in fake_bmc.ws_headers
        assert "sec-websocket-key" in fake_bmc.ws_headers
        assert fake_bmc.ws_headers["origin"] == f"http://127.0.0.1:{fake_bmc.port}"
    finally:
        await upstream.close()


async def test_pointer_and_key_are_relayed(fake_bmc):
    upstream = await opened(fake_bmc)
    try:
        await upstream.send_pointer(640, 400, 1)
        await upstream.send_key(0xFFE1, True)
        await upstream.send_key(0xFFE1, False)
        await upstream.wait_frames(1, timeout=5)
        for _ in range(100):
            if any(m[0] == "KeyEvent" for m in fake_bmc.client_messages):
                break
            await asyncio.sleep(0.02)
        pointer = [m for m in fake_bmc.client_messages if m[0] == "PointerEvent"]
        keys = [m for m in fake_bmc.client_messages if m[0] == "KeyEvent"]
        assert pointer == [("PointerEvent", 1, 640, 400)]
        assert ("KeyEvent", 1, 0xFFE1) in keys and ("KeyEvent", 0, 0xFFE1) in keys
    finally:
        await upstream.close()


async def test_close_logs_out_and_is_idempotent(fake_bmc):
    upstream = await opened(fake_bmc)
    assert await upstream.close() == "ok"
    assert fake_bmc.logged_out is True
    assert await upstream.close() == "ok"


async def test_wrong_ticket_fails_handshake():
    server = await FakeBmc(ticket="OTHERTICKET0001", expect_ticket=TICKET).start()
    try:
        upstream = RfbUpstream(config_for(server))
        await upstream.login("operator", password=PASSWORD)
        with pytest.raises(Problem) as excinfo:
            await upstream.open()
        assert excinfo.value.code in ("bmc_auth_failed", "upstream_handshake_failed")
        assert await upstream.close() in ("ok", "not_needed")
    finally:
        await server.stop()


async def test_auth_result_rejected():
    server = await FakeBmc(auth_result=2).start()
    try:
        upstream = RfbUpstream(config_for(server))
        await upstream.login("operator", password=PASSWORD)
        with pytest.raises(Problem):
            await upstream.open()
        await upstream.close()
    finally:
        await server.stop()


async def test_login_rejected(fake_bmc):
    upstream = RfbUpstream(config_for(fake_bmc))
    with pytest.raises(Problem) as excinfo:
        await upstream.login("operator", password="wrong")
    assert excinfo.value.code == "bmc_auth_failed"
    assert await upstream.close() == "not_needed"


async def test_login_non_200():
    server = await FakeBmc(fail_login_status=500).start()
    try:
        upstream = RfbUpstream(config_for(server))
        with pytest.raises(Problem) as excinfo:
            await upstream.login("operator", password=PASSWORD)
        assert excinfo.value.code == "bmc_auth_failed"
        await upstream.close()
    finally:
        await server.stop()


async def test_bootstrap_redirect_means_unauthenticated():
    server = await FakeBmc(bootstrap_redirect=True).start()
    try:
        upstream = RfbUpstream(config_for(server))
        await upstream.login("operator", password=PASSWORD)
        with pytest.raises(Problem) as excinfo:
            await upstream.open()
        assert excinfo.value.code == "bmc_auth_failed"
        await upstream.close()
    finally:
        await server.stop()


async def test_bootstrap_without_ticket():
    server = await FakeBmc(bootstrap_ticket=False).start()
    try:
        upstream = RfbUpstream(config_for(server))
        await upstream.login("operator", password=PASSWORD)
        with pytest.raises(Problem) as excinfo:
            await upstream.open()
        assert excinfo.value.code == "bmc_auth_failed"
        await upstream.close()
    finally:
        await server.stop()


async def test_oversized_upstream_frame():
    server = await FakeBmc(oversized_frame=True).start()
    try:
        upstream = RfbUpstream(config_for(server))
        await upstream.login("operator", password=PASSWORD)
        await upstream.open()
        with pytest.raises(Problem) as excinfo:
            await upstream.wait_frames(1, timeout=5)
        assert excinfo.value.code == "upstream_frame_too_large"
        await upstream.close()
    finally:
        await server.stop()


async def test_text_frame_rejected():
    server = await FakeBmc(text_frame=True).start()
    try:
        upstream = RfbUpstream(config_for(server))
        await upstream.login("operator", password=PASSWORD)
        await upstream.open()
        with pytest.raises(Problem) as excinfo:
            await upstream.wait_frames(1, timeout=5)
        assert excinfo.value.code == "upstream_invalid_response"
        await upstream.close()
    finally:
        await server.stop()


async def test_frame_budget_is_enforced():
    server = await FakeBmc().start()
    try:
        upstream = await opened(server, max_frames=5)
        with pytest.raises(Problem) as excinfo:
            await upstream.wait_frames(1, timeout=5)
        assert excinfo.value.code == "upstream_budget_exceeded"
        await upstream.close()
    finally:
        await server.stop()


class _FramesWs:

    def __init__(self, frames: int, size: int = 24):
        self.left, self.size = frames, size

    async def receive(self):
        if self.left == 0:
            return SimpleNamespace(type=aiohttp.WSMsgType.CLOSED, data=None)
        self.left -= 1
        return SimpleNamespace(type=aiohttp.WSMsgType.BINARY, data=b"\x00" * self.size)


async def _run_relay(frames: int, *, size: int = 24, **cfg):
    upstream = RfbUpstream(UpstreamConfig(host="127.0.0.1", cert_sha256="ab" * 32, **cfg))
    upstream._ws, upstream.server_init = _FramesWs(frames, size), object()
    delivered: list[bytes] = []

    async def sink(data):
        delivered.append(data)

    try:
        await upstream.relay(sink)
    except Problem as exc:
        return delivered, exc.code
    finally:
        await upstream.http.close()
    return delivered, None


async def test_relay_frame_budget_applies_by_default():
    delivered, code = await _run_relay(10, max_frames=5)
    assert code == "upstream_budget_exceeded"
    assert len(delivered) == 5


async def test_relay_byte_budget_applies_by_default():
    delivered, code = await _run_relay(10, size=4096, max_frames=100, max_frame_bytes=4096,
                                       max_total_bytes=4096 * 3)
    assert code == "upstream_budget_exceeded"
    assert len(delivered) == 3


async def test_live_relay_outlives_the_probe_budget_when_not_enforced():
    delivered, code = await _run_relay(50, max_frames=5, enforce_relay_budget=False)
    assert code is None
    assert len(delivered) == 50


async def test_unenforced_relay_budget_still_caps_each_frame():
    delivered, code = await _run_relay(3, size=5000, max_frame_bytes=4096, enforce_relay_budget=False)
    assert code == "upstream_frame_too_large"
    assert delivered == []


async def test_handshake_budget_still_applies_when_relay_budget_is_off():
    server = await FakeBmc().start()
    try:
        upstream = await opened(server, max_frames=5, enforce_relay_budget=False)
        with pytest.raises(Problem) as excinfo:
            await upstream.wait_frames(1, timeout=5)
        assert excinfo.value.code == "upstream_budget_exceeded"
        await upstream.close()
    finally:
        await server.stop()


async def test_unreachable_websocket_is_reported():
    server = await FakeBmc().start()
    try:
        upstream = RfbUpstream(config_for(server, ws_path="/missing"))
        await upstream.login("operator", password=PASSWORD)
        with pytest.raises(Problem) as excinfo:
            await upstream.open()
        assert excinfo.value.code in ("upstream_unavailable", "upstream_invalid_response")
        await upstream.close()
    finally:
        await server.stop()


async def test_handshake_timeout_is_bounded():
    server = await FakeBmc().start()
    try:
        upstream = RfbUpstream(config_for(server, handshake_timeout=0.2))
        await upstream.login("operator", password=PASSWORD)
        upstream.cfg.__class__
        upstream._ticket = TICKET
        upstream._ws = _SilentSocket()
        with pytest.raises(Problem) as excinfo:
            await upstream._handshake()
        assert excinfo.value.code in ("upstream_handshake_failed", "upstream_unavailable")
        await upstream.close()
    finally:
        await server.stop()


class _SilentSocket:
    async def receive(self):
        await asyncio.sleep(1)
        return type("Message", (), {"type": web.WSMsgType.CLOSE, "data": b""})()

    async def close(self, code=1000):
        return None


def test_config_rejects_dangerous_combinations():
    with pytest.raises(ValueError):
        UpstreamConfig(host="10.0.0.1", scheme="http")
    with pytest.raises(ValueError):
        UpstreamConfig(host="10.0.0.1", scheme="http", cert_sha256="a" * 64)
    with pytest.raises(ValueError):
        UpstreamConfig(host="10.0.0.1", login_path="/cgi/../cgi/login.cgi")
    with pytest.raises(ValueError):
        UpstreamConfig(host="10.0.0.1", login_path="/cgi/login.cgi?x=1")
    with pytest.raises(ValueError):
        UpstreamConfig(host="10.0.0.1", max_redirects=1)
    with pytest.raises(ValueError):
        UpstreamConfig(host="10.0.0.1", port=0)
    with pytest.raises(ValueError):
        UpstreamConfig(host="10.0.0.1", max_frame_bytes=1024)
    with pytest.raises(ValueError):
        UpstreamConfig(host="10.0.0.1", cert_sha256="zz")
    with pytest.raises(ValueError):
        UpstreamConfig(host="")
    assert UpstreamConfig(host="127.0.0.1", port=8443, scheme="http").base_url == "http://127.0.0.1:8443"


def test_keepalive_is_on_by_default_and_can_be_disabled():
    assert UpstreamConfig(host="192.0.2.11").keepalive_seconds == 20.0
    assert UpstreamConfig(host="192.0.2.11", keepalive_seconds=None).keepalive_seconds is None
    for bad in (0, -1, "20", True, 0.01):
        with pytest.raises(ValueError, match="invalid_keepalive"):
            UpstreamConfig(host="192.0.2.11", keepalive_seconds=bad)


async def test_a_mute_upstream_is_declared_unresponsive():
    server = await FakeBmc(silent=True).start()
    try:
        upstream = RfbUpstream(config_for(server, keepalive_seconds=0.4))
        await upstream.login("operator", password=server.password)
        await upstream.open()

        async def ignore(_data):
            return None

        with pytest.raises(Problem) as error:
            await asyncio.wait_for(upstream.relay(ignore), 10)
        assert error.value.code == "upstream_unresponsive"
        await upstream.close()
    finally:
        await server.stop()


def test_absorb_set_cookie_keeps_exactly_one_live_sid():
    measured = ["SID=; expires=Thursday,01-Jan-1970 00:00:00 GMT; Secure; HttpOnly",
                "SID=live-session; path=/; Secure; HttpOnly"]
    assert absorb_set_cookie(measured) == {"SID": "live-session"}
    assert absorb_set_cookie(["SID=a", "SID=b"]) == {"SID": "b"}
    assert absorb_set_cookie(["malformed", "", "x=" * 5000]) == {}
    assert absorb_set_cookie([]) == {}


def test_extract_ticket_variants():
    assert extract_ticket(b'<input id="entry_value" value="ABCDEFGH12">') == "ABCDEFGH12"
    assert extract_ticket(b"<input value='ABCDEFGH12' id='entry_value'>") == "ABCDEFGH12"
    with pytest.raises(Problem):
        extract_ticket(b"<html>nothing</html>")
    with pytest.raises(Problem):
        extract_ticket(b'<input id="entry_value" value="short">')
    with pytest.raises(Problem):
        extract_ticket(b'<input id="entry_value" value="' + b"A" * (MAX_TICKET_CHARS + 1) + b'">')


def test_encode_auth_response_matches_measured_shape():
    assert encode_auth_response("ABCDEFGH") == b"ABCDEFGH" + b"\x00" * 40
    assert len(encode_auth_response("A" * 24)) == 48
    with pytest.raises(Problem):
        encode_auth_response("short")
    with pytest.raises(Problem):
        encode_auth_response("A" * 25)
    with pytest.raises(Problem):
        encode_auth_response("TICKET\x01VALUE")


def test_set_encodings_wire_format():
    data = set_encodings((87, 0))
    assert data[:4] == bytes([2, 0, 0, 2])
    assert struct.unpack_from(">2i", data, 4) == (87, 0)
    with pytest.raises(Exception):
        set_encodings(())


def test_transport_defaults_match_the_adapter_console_spec():
    spec = SupermicroX10IKVMAdapter().console_spec()
    config = UpstreamConfig(host="192.0.2.11")
    assert config.login_path == spec.login_path
    assert config.bootstrap_path == spec.entry_path
    assert config.ws_path == spec.websocket_path
    assert config.port == spec.websocket_port
    assert {"https": "wss", "http": "ws"}[config.scheme] == spec.websocket_scheme
    assert ENCODING_AST2100 in DEFAULT_ENCODINGS
    assert spec.max_frame_bytes >= config.max_frame_bytes



def test_config_defaults_to_the_single_measured_version():
    assert UpstreamConfig(host="192.0.2.11").protocol_versions == ("RFB 055.008",)


def test_config_accepts_explicit_protocol_versions():
    cfg = UpstreamConfig(host="192.0.2.11",
                         protocol_versions=("RFB 055.008", "RFB 003.008"))
    assert cfg.protocol_versions == ("RFB 055.008", "RFB 003.008")


@pytest.mark.parametrize("bad", [
    (), "RFB 055.008", ("XXXX 003.008",), ("RFB 055.008", "RFB 055.008"),
    ("RFB 055.008\n",), ("",),
])
def test_config_rejects_malformed_protocol_versions(bad):
    with pytest.raises(ValueError, match="invalid_protocol_versions"):
        UpstreamConfig(host="127.0.0.1", scheme="http", protocol_versions=bad)


async def test_upstream_negotiates_an_explicitly_allowed_version(fake_bmc):
    fake_bmc.version = b"RFB 003.008\n"
    upstream = await opened(fake_bmc, protocol_versions=("RFB 055.008", "RFB 003.008"))
    try:
        assert upstream.protocol_version == "RFB 003.008"
        assert fake_bmc.client_version == b"RFB 003.008\n"
        assert upstream.server_init is not None
    finally:
        await upstream.close()


async def test_upstream_refuses_a_version_outside_the_allowance(fake_bmc):
    fake_bmc.version = b"RFB 004.008\n"
    upstream = RfbUpstream(config_for(fake_bmc, protocol_versions=("RFB 055.008", "RFB 003.008")))
    try:
        with pytest.raises(Problem, match="upstream_handshake_failed"):
            await upstream.login("operator", password=fake_bmc.password)
            await upstream.open()
    finally:
        await upstream.close()


async def test_upstream_records_the_default_negotiated_version(fake_bmc):
    upstream = await opened(fake_bmc)
    try:
        assert upstream.protocol_version == "RFB 055.008"
    finally:
        await upstream.close()


async def test_upstream_still_refuses_standard_rfb_by_default(fake_bmc):
    fake_bmc.version = b"RFB 003.008\n"
    upstream = RfbUpstream(config_for(fake_bmc))
    try:
        with pytest.raises(Problem, match="upstream_handshake_failed"):
            await upstream.login("operator", password=fake_bmc.password)
            await upstream.open()
    finally:
        await upstream.close()


async def test_browser_side_greeting_follows_the_negotiated_version(fake_bmc):
    fake_bmc.version = b"RFB 003.008\n"
    upstream = await opened(fake_bmc, protocol_versions=("RFB 055.008", "RFB 003.008"))
    try:
        browser = BrowserHandshake(upstream.server_init_raw, challenge=b"C" * 24,
                                   version=b"RFB 003.008\n")
        assert upstream.protocol_version == "RFB 003.008"
        assert browser.start() == b"RFB 003.008\n"
        out, trailing = browser.feed(b"RFB 003.008\n\x10" + b"X" * 48 + b"\x01")
        assert browser.completed and trailing == b""
        assert out.endswith(upstream.server_init_raw)
    finally:
        await upstream.close()
