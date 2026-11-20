"""Worker wiring for the iDRAC8 view-only RFB adapter (no live BMC)."""
from __future__ import annotations

import asyncio

import pytest

from kvmhub import idrac8_dvc as dvc
from kvmhub.adapters.idrac8 import (IDRAC8_KVM_PORT, Idrac8Adapter,
                                    Idrac8RfbSession)
from kvmhub.common import IDRAC8_ADAPTER_ID
from kvmhub.passthrough import AUTH_RESPONSE_BYTES, SECURITY_TYPE_INSYDE
from kvmhub.platform.data_plane import assembled_info
from kvmhub.worker import make_adapter

INFO = {
    "adapter": IDRAC8_ADAPTER_ID,
    "target": "https://192.0.2.84",
    "fingerprint": "ab" * 32,
}


def test_make_adapter_routes_idrac8():
    adapter = make_adapter(dict(INFO))
    assert isinstance(adapter, Idrac8Adapter)
    assert adapter.host == "192.0.2.84"


@pytest.mark.asyncio
async def test_login_retains_upstream_on_failure_for_cleanup(monkeypatch):
    import aiohttp

    from kvmhub.adapters import idrac8 as ad

    attempts = []

    class FakeUpstream:
        def __init__(self, host, port, username, password, **kwargs):
            attempts.append(self)

        async def connect(self):
            raise aiohttp.ClientConnectionResetError()

        async def close(self):
            pass

    monkeypatch.setattr(ad, "Idrac8Upstream", FakeUpstream)
    adapter = Idrac8Adapter(dict(INFO))
    with pytest.raises(aiohttp.ClientConnectionResetError):
        await adapter.login("root", "calvin")
    assert len(attempts) == 4
    assert adapter.upstream is attempts[-1]


@pytest.mark.asyncio
async def test_login_recovers_from_transient_socket_reset(monkeypatch):
    import aiohttp

    from kvmhub.adapters import idrac8 as ad

    class FlakyUpstream:
        instances = []

        def __init__(self, host, port, username, password, **kwargs):
            self.fail = len(self.instances) < 2
            self.instances.append(self)
            self.closed = False

        async def connect(self):
            if self.fail:
                raise aiohttp.ClientConnectionResetError()
            self.capabilities = object()

        async def close(self):
            self.closed = True

    FlakyUpstream.instances = []
    monkeypatch.setattr(ad, "Idrac8Upstream", FlakyUpstream)
    adapter = Idrac8Adapter(dict(INFO))
    await adapter.login("root", "calvin")
    assert len(FlakyUpstream.instances) == 3
    assert adapter.upstream is FlakyUpstream.instances[-1]
    assert adapter.upstream.capabilities is not None


@pytest.mark.asyncio
async def test_login_clears_stale_bmc_sessions_when_recovery_enabled(monkeypatch):
    import aiohttp

    from kvmhub.adapters import idrac8 as ad

    calls = []

    class FailingUpstream:
        def __init__(self, host, port, username, password, **kwargs):
            pass

        async def connect(self):
            raise aiohttp.ClientConnectionResetError()

        async def close(self):
            pass

    monkeypatch.setattr(ad, "Idrac8Upstream", FailingUpstream)
    monkeypatch.setattr(ad, "_clear_bmc_sessions",
                        lambda host, user, password: calls.append((host, user)))
    monkeypatch.setenv(ad.IDRAC8_SESSION_RECOVERY_ENV, "1")
    adapter = Idrac8Adapter(dict(INFO))
    with pytest.raises(aiohttp.ClientConnectionResetError):
        await adapter.login("root", "calvin")
    assert calls == [("192.0.2.84", "root")]


def test_adapter_uses_the_viewer_websocket_port_not_the_https_target_port():
    assert Idrac8Adapter(dict(INFO)).port == IDRAC8_KVM_PORT == 5900
    explicit_https = dict(INFO, target="https://192.0.2.84:8443")
    assert Idrac8Adapter(explicit_https).port == IDRAC8_KVM_PORT


def test_worker_serves_the_real_console_page_for_idrac8():
    import inspect

    from kvmhub import worker

    source = inspect.getsource(worker.Gateway.handle)
    assert "IdracVncAdapter" in source
    assert "(PassthroughAdapter, Idrac8Adapter," in source


def test_make_adapter_rejects_unsafe_target():
    bad = dict(INFO, target="https://user:pw@192.0.2.84/path")
    with pytest.raises(Exception):
        make_adapter(bad)


def test_idrac8_serves_only_the_measured_novnc_bundle():
    adapter = Idrac8Adapter(dict(INFO))
    mime, body = asyncio.run(adapter.fetch_asset("/novnc/include/rfb.js"))
    assert mime == "application/javascript" and body.startswith(b"var RFB")
    for denied in ("/novnc/include/../../etc/passwd", "/novnc/include/secret.txt",
                   "/cgi/login.cgi", "/novnc/include/unknown.js"):
        with pytest.raises(Exception):
            asyncio.run(adapter.fetch_asset(denied))


def test_store_allows_idrac8_only_for_listed_target():
    from kvmhub.store import Store

    store = Store.__new__(Store)
    store.passthrough_targets = frozenset({"https://192.0.2.84"})
    assert store._adapter_allowed({"adapter": IDRAC8_ADAPTER_ID,
                                   "target": "https://192.0.2.84"})
    assert not store._adapter_allowed({"adapter": IDRAC8_ADAPTER_ID,
                                       "target": "https://192.0.2.85"})


def test_assembled_info_accepts_idrac8_capability():
    info = dict(INFO)
    assembly = {"data_plane": {"adapter": IDRAC8_ADAPTER_ID,
                               "capability_entry": {"adapter": IDRAC8_ADAPTER_ID}},
                "plan": {}}
    assert assembled_info(info, assembly)["adapter"] == IDRAC8_ADAPTER_ID


class _FakeUpstream:
    capabilities = object()

    def decoder(self):
        class D:
            def uncompress(self, data, color_mode=True):
                return [0xFF102030] * (1024 * 768)
        return D()

    async def frames(self):
        yield dvc.VidsFrame("VIDS", 20, 0x05, 1024, 768, b"\x02\x00\x00\x00")

    async def close(self):
        pass


@pytest.mark.asyncio
async def test_idrac8_session_handshake_and_frame_push():
    session = Idrac8RfbSession(_FakeUpstream())
    await session.start()
    greeting = await anext(session)
    assert greeting.data.startswith(b"RFB ")

    await session.send_bytes(b"RFB 003.008\n")
    await session.send_bytes(bytes([SECURITY_TYPE_INSYDE]))
    await session.send_bytes(bytes(AUTH_RESPONSE_BYTES))
    await session.send_bytes(b"\x00")
    assert session.handshake.completed is True

    seen = 0
    while seen < 3:
        message = await asyncio.wait_for(anext(session), 2)
        seen += 1
    assert seen >= 3
    await session.close()
    assert session.closed is True
