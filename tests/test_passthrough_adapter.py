"""The real-device adapter must stay unreachable unless explicitly configured."""
import asyncio

import pytest

from kvmhub.adapters.passthrough import (
    ASSET_PATH,
    PassthroughAdapter,
    content_type_for,
)
from kvmhub.common import PASSTHROUGH_ADAPTER_ID, Problem
from kvmhub.store import Store

TARGET = "https://192.0.2.11"
FINGERPRINT = "ab" * 32


def info(**overrides):
    base = {"adapter": PASSTHROUGH_ADAPTER_ID, "target": TARGET, "fingerprint": FINGERPRINT}
    base.update(overrides)
    return base



def test_adapter_accepts_the_measured_target_shape():
    adapter = PassthroughAdapter(info())
    assert adapter.adapter_id == PASSTHROUGH_ADAPTER_ID
    assert adapter.cfg.host == "192.0.2.11"
    assert adapter.cfg.scheme == "https"
    assert adapter.cfg.cert_sha256 == FINGERPRINT


def test_live_relay_is_not_cut_off_by_the_probe_frame_budget():
    cfg = PassthroughAdapter(info()).cfg
    assert cfg.enforce_relay_budget is False
    assert cfg.max_frame_bytes == 1024 * 1024


@pytest.mark.parametrize("overrides", [
    {"adapter": "mock-v1"},
    {"target": "http://192.0.2.11"},
    {"target": "https://192.0.2.11/path"},
    {"target": "https://user:pass@192.0.2.11"},
    {"target": "https://192.0.2.11?x=1"},
    {"fingerprint": "not-hex"},
    {"fingerprint": "ab" * 16},
])
def test_adapter_rejects_anything_outside_the_measured_policy(overrides):
    with pytest.raises(Problem, match="adapter_not_verified|invalid_target_policy"):
        PassthroughAdapter(info(**overrides))



@pytest.mark.parametrize("path", [
    "/novnc/include/rfb.js", "/novnc/include/ast2100.js", "/js/screenshot.js",
    "/css/bootstrap.css", "/images/logo.png", "/favicon.ico",
])
def test_asset_allowlist_accepts_the_vendor_client_files(path):
    assert ASSET_PATH.fullmatch(path)


@pytest.mark.parametrize("path", [
    "/cgi/url_redirect.cgi", "/cgi/login.cgi", "/novnc/include/../../cgi/login.cgi",
    "/js/nav_ui.js.html", "/js/", "/novnc/include/", "/images/x.exe", "/", "/index.html",
])
def test_asset_allowlist_denies_everything_else(path):
    assert not ASSET_PATH.fullmatch(path)


def test_content_type_is_decided_by_extension_not_by_upstream():
    assert content_type_for("/novnc/include/rfb.js") == "application/javascript"
    assert content_type_for("/css/bootstrap.css") == "text/css"
    assert content_type_for("/favicon.ico") == "image/x-icon"
    assert content_type_for("/images/logo.png") == "image/png"
    assert content_type_for("/js/weird.bin") == "application/octet-stream"



def build_store(tmp_path, targets):
    store = Store(tmp_path / "gate.sqlite", b"k" * 32, passthrough_targets=targets)
    store.seed_passthrough(target=TARGET, fingerprint=FINGERPRINT,
                           username="operator", password="placeholder",
                           approver="tests/test_passthrough_adapter.py")
    return store


def test_passthrough_is_unreachable_by_default(tmp_path):
    store = build_store(tmp_path, ())
    try:
        with pytest.raises(Problem, match="adapter_not_verified"):
            store.allocate("real-1", "local-admin", "w1", "i1", "trace")
    finally:
        store.close()


def test_passthrough_requires_the_exact_configured_target(tmp_path):
    store = build_store(tmp_path, ("https://192.0.2.12",))
    try:
        with pytest.raises(Problem, match="adapter_not_verified"):
            store.allocate("real-1", "local-admin", "w1", "i1", "trace")
    finally:
        store.close()


def test_passthrough_is_reachable_only_for_the_listed_target(tmp_path):
    store = build_store(tmp_path, (TARGET,))
    try:
        row = store.allocate("real-1", "local-admin", "w1", "i1", "trace")
        assert row["asset_id"] == "real-1"
        result = store.exchange(
            {"sid": row["id"], "sub": row["user_id"], "aid": row["asset_id"],
             "wid": row["worker_id"], "iid": row["instance_id"], "jti": row["jti"]}, "trace")
        assert result["adapter"] == PASSTHROUGH_ADAPTER_ID
        assert result["username"] == "operator"
    finally:
        store.close()


def test_passthrough_still_needs_a_live_capability(tmp_path):
    store = build_store(tmp_path, (TARGET,))
    try:
        store.db.execute("UPDATE adapter_capability SET status='unverified'")
        with pytest.raises(Problem, match="adapter_not_verified"):
            store.allocate("real-1", "local-admin", "w1", "i1", "trace")
    finally:
        store.close()


def test_passthrough_still_needs_a_matching_vendor_model_firmware(tmp_path):
    store = build_store(tmp_path, (TARGET,))
    try:
        store.db.execute("UPDATE asset SET firmware='9.99'")
        with pytest.raises(Problem, match="adapter_not_verified"):
            store.allocate("real-1", "local-admin", "w1", "i1", "trace")
    finally:
        store.close()


def test_mock_adapter_is_unaffected_by_the_target_list(tmp_path):
    store = Store(tmp_path / "mock.sqlite", b"k" * 32, passthrough_targets=())
    store.seed_mock("https://127.0.0.1:10443", "aa" * 32, "u", "p")
    try:
        assert store.allocate("mock-1", "local-admin", "w1", "i1", "trace")["asset_id"] == "mock-1"
    finally:
        store.close()



class FakeUpstream:
    def __init__(self, server_init_raw):
        self.server_init_raw = server_init_raw
        self.sent = []
        self.pending = b""
        self.closed = False

    async def relay(self, on_bytes):
        if self.pending:
            buffered, self.pending = self.pending, b""
            await on_bytes(buffered)
        await asyncio.Event().wait()

    async def send_raw(self, data):
        self.sent.append(bytes(data))

    async def fetch_asset(self, path):
        return "application/javascript", b"/* " + path.encode() + b" */"

    async def close(self):
        self.closed = True
        return "ok"


def test_connect_requires_a_completed_upstream_handshake():
    adapter = PassthroughAdapter(info())

    async def scenario():
        with pytest.raises(Problem, match="upstream_handshake_failed"):
            await adapter.connect(["binary"])

    asyncio.run(scenario())


def test_connect_rejects_a_second_console_and_allows_a_reconnect():
    adapter = PassthroughAdapter(info())
    adapter.upstream = FakeUpstream(b"\x00" * 40)

    async def scenario():
        first = await adapter.connect(["binary"])
        await first.start()
        with pytest.raises(Problem, match="connection_limit"):
            await adapter.connect(["binary"])
        await first.close()
        second = await adapter.connect(["binary"])
        await second.close()

    asyncio.run(scenario())


def test_connect_requires_the_binary_subprotocol():
    adapter = PassthroughAdapter(info())
    adapter.upstream = FakeUpstream(b"\x00" * 40)

    async def scenario():
        with pytest.raises(Problem, match="subprotocol_required"):
            await adapter.connect(["base64"])

    asyncio.run(scenario())


def test_asset_fetch_is_denied_outside_the_allowlist():
    adapter = PassthroughAdapter(info())
    adapter.upstream = FakeUpstream(b"\x00" * 40)

    async def scenario():
        with pytest.raises(Problem, match="route_denied"):
            await adapter.fetch_asset("/cgi/login.cgi")
        content_type, body = await adapter.fetch_asset("/novnc/include/rfb.js")
        assert content_type == "application/javascript"
        assert b"/novnc/include/rfb.js" in body

    asyncio.run(scenario())


def test_adapter_close_is_safe_before_login():
    assert asyncio.run(PassthroughAdapter(info()).close()) is False



def test_adapter_forwards_the_approved_protocol_versions():
    cfg = PassthroughAdapter(info(protocol_versions=["RFB 055.008", "RFB 003.008"])).cfg
    assert cfg.protocol_versions == ("RFB 055.008", "RFB 003.008")


def test_adapter_uses_the_measured_default_without_an_allowance():
    assert PassthroughAdapter(info()).cfg.protocol_versions == ("RFB 055.008",)


def test_adapter_rejects_a_malformed_allowance():
    with pytest.raises(Problem, match="invalid_target_policy"):
        PassthroughAdapter(info(protocol_versions=["XXXX 003.008"]))


def test_connect_greets_the_browser_with_the_negotiated_version():
    adapter = PassthroughAdapter(info())
    adapter.upstream = FakeUpstream(b"\x00" * 40)
    adapter.upstream.protocol_version = "RFB 003.008"

    async def scenario():
        session = await adapter.connect(["binary"])
        message = await session.__anext__()
        assert message.data == b"RFB 003.008\n"

    asyncio.run(scenario())


def test_connect_accepts_the_measured_insyde_client_messages():
    adapter = PassthroughAdapter(info())
    adapter.upstream = FakeUpstream(b"\x00" * 40)
    pointer = b"\x05\x00\x04\x00\x64\x00\xc8" + b"\x00" * 11
    key = b"\x04\x00\x01\x00\x00\x00\x00\x00\xe1" + b"\x00" * 9

    async def scenario():
        session = await adapter.connect(["binary"])
        await session.send_bytes(b"RFB 055.008\n\x10" + b"A" * 48 + b"\x01")
        await session.send_bytes(b"\x19")
        await session.send_bytes(pointer)
        await session.send_bytes(key)
        await asyncio.sleep(0)
        assert session.error is None
        assert adapter.upstream.sent == [b"\x19", pointer, key]
        await session.close()

    asyncio.run(scenario())
