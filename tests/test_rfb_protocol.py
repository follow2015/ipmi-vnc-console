"""Tests for the per-brand console protocol strategy."""
from __future__ import annotations

import pytest

from kvmhub.passthrough import client_message_profile as sm_client_message_profile
from kvmhub.rfb_protocol import (
    ConsoleProtocol,
    SupermicroProtocol,
)
from kvmhub.rfb_upstream import (
    absorb_set_cookie,
    encode_auth_response,
    extract_ticket,
)


TICKET = "ABCDEFGH12345678"
HTML = ('<html><input type="hidden" id="entry_value" value="%s"></html>' % TICKET).encode()


def test_supermicro_is_a_console_protocol():
    assert isinstance(SupermicroProtocol(), ConsoleProtocol)


def test_supermicro_login_fields_match_measured_form():
    proto = SupermicroProtocol()
    assert proto.login_fields("operator", "synthetic-password") == {"name": "operator", "pwd": "synthetic-password"}


def test_supermicro_ticket_extraction_matches_legacy_function():
    proto = SupermicroProtocol()
    assert proto.extract_ticket(HTML) == extract_ticket(HTML) == TICKET


def test_supermicro_cookie_absorption_matches_legacy_function():
    values = ["SID=one; Path=/", "SID=two; Path=/", "theme=dark"]
    assert SupermicroProtocol().absorb_cookies(values) == absorb_set_cookie(values) == {
        "SID": "two", "theme": "dark"}


def test_supermicro_auth_response_matches_legacy_function():
    assert SupermicroProtocol().auth_response(TICKET) == encode_auth_response(TICKET)


def test_supermicro_security_scheme_and_client_init_are_measured_values():
    proto = SupermicroProtocol()
    assert proto.security_type() == 16
    assert proto.client_init() == b"\x01"


def test_supermicro_message_profile_delegates_to_measured_mapping():
    proto = SupermicroProtocol()
    for version in ("RFB 003.008", "RFB 055.008", "RFB 999.999", None):
        allowed, sizes = proto.message_profile(version)
        expected_allowed, expected_sizes = sm_client_message_profile(version)
        assert (allowed, sizes) == (expected_allowed, expected_sizes)


def test_console_protocol_is_abstract_about_login_fields():
    with pytest.raises(TypeError):
        ConsoleProtocol()


def test_custom_protocol_can_override_login_fields_for_another_brand():
    class OtherBrand(ConsoleProtocol):
        def login_fields(self, user, pwd):
            return {"username": user, "password": pwd}

    with pytest.raises(TypeError):
        OtherBrand()


class SpyProtocol(SupermicroProtocol):

    def __init__(self):
        self.calls: list[str] = []

    def login_fields(self, username, password):
        self.calls.append("login_fields")
        return super().login_fields(username, password)

    def absorb_cookies(self, values):
        self.calls.append("absorb_cookies")
        return super().absorb_cookies(values)

    def extract_ticket(self, html):
        self.calls.append("extract_ticket")
        return super().extract_ticket(html)

    def auth_response(self, ticket):
        self.calls.append("auth_response")
        return super().auth_response(ticket)

    def security_type(self):
        self.calls.append("security_type")
        return super().security_type()

    def client_init(self):
        self.calls.append("client_init")
        return super().client_init()


@pytest.mark.asyncio
async def test_upstream_delegates_all_brand_seams_to_injected_protocol(fake_bmc):
    from kvmhub.rfb_upstream import RfbUpstream
    from tests.support.fake_bmc import PASSWORD, config_for

    spy = SpyProtocol()
    upstream = RfbUpstream(config_for(fake_bmc), protocol=spy)
    try:
        await upstream.login("operator", PASSWORD)
        await upstream.open()
        assert "login_fields" in spy.calls
        assert "absorb_cookies" in spy.calls
        assert "extract_ticket" in spy.calls
        assert "auth_response" in spy.calls
        assert "security_type" in spy.calls
        assert "client_init" in spy.calls
    finally:
        await upstream.close()


@pytest.fixture
async def fake_bmc():
    from tests.support.fake_bmc import FakeBmc
    server = await FakeBmc().start()
    try:
        yield server
    finally:
        await server.stop()
