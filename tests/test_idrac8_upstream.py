"""Tests for the iDRAC8 upstream handshake builders and helpers."""
from __future__ import annotations

import pytest

from kvmhub import idrac8_upstream as up

GOLDEN_LOGIN = bytes.fromhex(
    "42454546010200d90d374040313539333530313339300000000000000000000000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000a3130343431383334383500000000000000000000000000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000003b00"
)


def test_user_login_request_matches_captured_viewer_frame():
    frame = up.build_user_login_request("7@@1593501390", "1044183485", client_random=59)
    assert len(frame) == 217
    assert frame == GOLDEN_LOGIN


def test_parse_user_login_request_recovers_fields():
    fields = up.parse_user_login_request(GOLDEN_LOGIN)
    assert fields["user"] == "7@@1593501390"
    assert fields["password"] == "1044183485"
    assert fields["port_id"] == 0
    assert fields["channel_id"] == 0
    assert fields["client_random"] == 59
    assert fields["shared_mode"] == 0
    assert fields["reserved"] == bytes(8)


def test_user_login_request_rejects_invalid_inputs():
    with pytest.raises(up.UpstreamError):
        up.build_user_login_request("u", "p", client_random=-1)
    with pytest.raises(up.UpstreamError):
        up.build_user_login_request("u", "p", port_id=b"x" * 256)


def test_client_info_negotiates_cleartext_video():
    assert len(up.CLIENT_INFO_JSON) == 242
    assert b'"encryption_type": "none"' in up.CLIENT_INFO_JSON


class _CookieResponse:
    def __init__(self, raw_cookies):
        self.headers = _CookieHeaders(raw_cookies)


class _CookieHeaders:
    def __init__(self, raw_cookies):
        self._raw = raw_cookies

    def getall(self, key, default=None):
        return self._raw if key == "Set-Cookie" else (default or [])


class _EmptyJarSession:
    cookie_jar = []


def test_session_cookie_extracts_odd_idrac_cookie():
    raw = ["-http-session-=5::http.session::abcdef; path=/; secure; httponly"]
    response = _CookieResponse(raw)
    assert up._session_cookie(response, _EmptyJarSession()) == raw[0].split(";")[0]


def test_session_cookie_falls_back_to_jar():
    class Morsel:
        key, value = "-http-session-", "abc"

    class Session:
        cookie_jar = [Morsel()]

    class NoHeaders:
        headers = None

    assert up._session_cookie(NoHeaders(), Session()) == "-http-session-=abc"


@pytest.mark.asyncio
async def test_login_sets_tokenvalue_cookie_from_st1(monkeypatch):
    import aiohttp

    captured = {}

    class FakeLoginResponse:
        status = 200
        headers = _CookieHeaders(
            ["-http-session-=1::http.session::abc; path=/; secure; httponly"])

        async def text(self):
            return ("<root><authResult>0</authResult>"
                    "<forwardUrl>index.html?ST1=deadbeef,ST2=cafebabe</forwardUrl></root>")

    class FakeSsnResponse:
        async def text(self):
            return '{"getSsnVar":{"aimSession":"7"}}'

    class FakeCredResponse:
        async def text(self):
            return '{"aimGetProp":{"tempUser":"7@@1","tempPass":"2"}}'

    class FakeSession:
        def __init__(self, **_kwargs):
            self.cookie_jar = []

        async def post(self, url, **kwargs):
            return FakeLoginResponse()

        async def get(self, url, **kwargs):
            if "getSsnVar" in url:
                captured["ssn_cookie"] = kwargs["headers"]["Cookie"]
                return FakeSsnResponse()
            if "setTempCredential" in url:
                return FakeCredResponse()
            return FakeLoginResponse()

        async def close(self):
            pass

    monkeypatch.setattr(aiohttp, "ClientSession", FakeSession)
    client = up.Idrac8Upstream("192.0.2.84")
    creds = await client._fetch_temp_credentials(client._http or FakeSession())
    assert "tokenvalue=deadbeef" in captured["ssn_cookie"]
    assert creds.cookie.endswith("tokenvalue=deadbeef")


def test_to_rfb_rgb24_converts_argb_words():
    pixels = [0xFF102030, 0xFF000000, 0xFFFFFFFF]
    assert up.to_rfb_rgb24(pixels) == bytes.fromhex("102030000000ffffff")


def test_upstream_urls_are_derived_from_host():
    client = up.Idrac8Upstream("192.0.2.84", port=5900, username="root", password="synthetic-password")
    assert client.base_url == "https://192.0.2.84"
    assert client.ws_url == "wss://192.0.2.84:5900/"


@pytest.mark.asyncio
async def test_close_and_read_without_connect_are_safe():
    client = up.Idrac8Upstream("192.0.2.84")
    with pytest.raises(up.UpstreamError):
        await client.read_frame()
    await client.close()
    assert client.capabilities is None


@pytest.mark.asyncio
async def test_upstream_handshake_and_frame_read_with_mocked_transport(monkeypatch):
    import json as _json
    import struct as _struct

    import aiohttp

    from kvmhub import idrac8_protocol as wire

    class FakeResponse:
        def __init__(self, text):
            self.status = 200
            self._text = text

        async def text(self):
            return self._text

    class FakeMessage:
        def __init__(self, data, kind=aiohttp.WSMsgType.BINARY):
            self.type = kind
            self.data = data

    class FakeWS:
        def __init__(self, incoming):
            self.incoming = list(incoming)
            self.sent = []
            self.closed = False

        async def send_bytes(self, data):
            self.sent.append(data)

        async def receive(self):
            if not self.incoming:
                return FakeMessage(b"", aiohttp.WSMsgType.CLOSE)
            return self.incoming.pop(0)

        async def close(self):
            self.closed = True

    caps = {
        "version": "3.89.0",
        "protocols": {"AVSP": {
            "version": "2.41",
            "video_socket": {"video_on_secondary_socket": True},
            "dvc_compression": {"compression_modes": ["DVC-15"]},
        }},
    }
    caps_json = _json.dumps(caps).encode() + b" " * 1100
    caps_frame = (b"APCP" + _struct.pack(">I", 20 + len(caps_json))
                  + bytes([0x82, 0x01]) + bytes(10) + caps_json)
    setup_response = wire.build_session_setup()[:8] + b"\x81\x00\x01\x04" + bytes(56)
    video_setup_response = (
        wire.build_session_setup(secondary=True)[:8] + b"\x81\x00\x01\x04" + bytes(56))
    login_response = b"BEEF\x83\x05\x00\x73" + bytes(0x73)
    apcp_secondary = wire.build_apcp_control(0x81, 0x02, 0x00, bytes(8))[:8] + (
        b"\x81\x02\x00\x00" + bytes(8))
    apcp_session_id = wire.build_apcp_control(0x81, 0x03, 0x10, bytes(36))[:8] + (
        b"\x81\x03\x10\x00" + bytes(36))

    def vids(flags, payload):
        total = 20 + len(payload)
        return (b"VIDS" + b"\x00\x81" + _struct.pack(">H", total)
                + b"\xde\xad\xbe\xef" + _struct.pack(">HH", 768, 1024)
                + bytes([flags, 0, 0, 0]) + payload)

    fake_ws = FakeWS([FakeMessage(setup_response), FakeMessage(login_response),
                      FakeMessage(caps_frame), FakeMessage(apcp_secondary),
                      FakeMessage(apcp_session_id)])
    video_ws = FakeWS([FakeMessage(video_setup_response),
                       FakeMessage(vids(0x05, b"head")),
                       FakeMessage(vids(0x06, b"tail"))])

    class Morsel:
        key, value = "-http-session-", "abc"

    class FakeSession:
        def __init__(self, **_kwargs):
            self.cookie_jar = [Morsel()]
            self.gets = []

        async def post(self, url, **_kwargs):
            return FakeResponse(
                "<root><authResult>0</authResult>"
                "<forwardUrl>index.html?ST1=aaa,ST2=bbb</forwardUrl></root>")

        async def get(self, url, **_kwargs):
            self.gets.append(url)
            if "getSsnVar" in url:
                return FakeResponse(_json.dumps({"getSsnVar": {"aimSession": "17"}}))
            if "setTempCredential" in url:
                return FakeResponse(_json.dumps({"aimGetProp": {
                    "tempUser": "17@@123", "tempPass": "456"}}))
            return FakeResponse("ok")

        async def ws_connect(self, url, **_kwargs):
            self.ws_url = url
            self.calls = getattr(self, "calls", 0) + 1
            return fake_ws if self.calls == 1 else video_ws

        async def close(self):
            self.closed = True

    monkeypatch.setattr(aiohttp, "ClientSession", FakeSession)
    monkeypatch.setattr(up, "FRAME_GAP_S", 0)
    client = up.Idrac8Upstream("192.0.2.84", client_random=0x17C2)
    caps_obj = await client.connect()
    assert caps_obj.version == "3.89.0"
    assert caps_obj.video_on_secondary_socket is True
    assert len(fake_ws.sent) == 11
    assert fake_ws.sent[2][:4] == b"BEEF"
    assert fake_ws.sent[4][:4] == b"APCP"
    assert wire.build_video_socket_auth(0x17C2) == video_ws.sent[1]
    frame = await client.read_frame()
    assert frame is not None and frame.payload == b"headtail"
    await client.close()
    assert fake_ws.closed is True and video_ws.closed is True
    assert client._http is None
    assert wire.build_session_close() in fake_ws.sent
    assert wire.build_session_close() in video_ws.sent


@pytest.mark.asyncio
async def test_close_logs_out_with_the_session_cookie(monkeypatch):
    import aiohttp

    logout_headers = {}

    class FakeResponse:
        status = 200
        headers = _CookieHeaders([])

        async def text(self):
            return "ok"

    class FakeSession:
        def __init__(self, **_kwargs):
            self.cookie_jar = []

        async def get(self, url, **kwargs):
            if "logout" in url:
                logout_headers.update(kwargs.get("headers", {}))
            return FakeResponse()

        async def close(self):
            pass

    client = up.Idrac8Upstream("192.0.2.84")
    client._http = FakeSession()
    cookie = "-http-session-=5::http.session::abc; tokenvalue=deadbeef"
    client._session_cookie = cookie
    await client.close()
    assert logout_headers.get("Cookie") == cookie
    assert client._session_cookie == ""
