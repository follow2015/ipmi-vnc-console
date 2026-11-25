"""Huawei iBMC built-in VNC (RFB over TLS) adapter and admission tests."""
from __future__ import annotations

import asyncio
import datetime
import hashlib
import struct

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from kvmhub.adapters.huawei_ibmc_vnc import (HUAWEI_VNC_PORT, PIN_ENV,
                                             HuaweiIbmcVncAdapter)
from kvmhub.common import HUAWEI_IBMC_VNC_ADAPTER_ID, Problem
from kvmhub.rfb_tcp_upstream import (RfbTcpConfig, RfbTcpUpstream,
                                     StandardRfbBrowserHandshake,
                                     vnc_auth_response)
from kvmhub.worker import make_adapter

INFO = {"adapter": HUAWEI_IBMC_VNC_ADAPTER_ID, "target": "https://192.0.2.234"}
SERVER_INIT = (struct.pack(">HH", 1024, 768) + bytes(16)
               + struct.pack(">I", 4) + b"iBMC")


def _self_signed():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "huawei-test")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=1))
            .sign(key, hashes.SHA256()))
    der = cert.public_bytes(serialization.Encoding.DER)
    return key, der



def test_tls_config_defaults_keep_plaintext_compat():
    cfg = RfbTcpConfig(host="192.0.2.84", password="x")
    assert cfg.tls_enabled is False and cfg.tls_cert_sha256 == ""


def test_tls_config_validates_pin_and_never_reprs_password():
    pin = "ab" * 32
    cfg = RfbTcpConfig(host="192.0.2.234", port=5900, password="synthetic-password",
                       tls_enabled=True, tls_cert_sha256=pin)
    assert "synthetic-password" not in repr(cfg)
    assert cfg.tls_enabled and cfg.tls_cert_sha256 == pin
    with pytest.raises(ValueError):
        RfbTcpConfig(host="192.0.2.234", password="x", tls_cert_sha256="nothex")



def _tls_rfb_server(key, cert_der, *, password="synthetic-password"):
    async def handler(reader, writer):
        try:
            writer.write(b"RFB 003.008\n")
            await writer.drain()
            assert await reader.readexactly(12) == b"RFB 003.008\n"
            writer.write(b"\x01\x02")
            await writer.drain()
            assert await reader.readexactly(1) == b"\x02"
            chal = bytes(range(16))
            writer.write(chal)
            await writer.drain()
            got = await reader.readexactly(16)
            ok = got == vnc_auth_response(chal, password)
            writer.write(struct.pack(">I", 0 if ok else 1))
            await writer.drain()
            if not ok:
                return
            assert await reader.readexactly(1) == b"\x01"
            writer.write(SERVER_INIT)
            await writer.drain()
            await asyncio.sleep(1.5)
        finally:
            writer.close()

    async def factory(reader, writer):
        await handler(reader, writer)

    return factory


def _make_ssl_ctx(key, cert_der):
    import ssl
    import tempfile
    import os
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    with tempfile.TemporaryDirectory() as d:
        cert_path = os.path.join(d, "cert.pem")
        key_path = os.path.join(d, "key.pem")
        with open(cert_path, "wb") as f:
            f.write(cert_der and x509.load_der_x509_certificate(cert_der).public_bytes(
                serialization.Encoding.PEM))
        with open(key_path, "wb") as f:
            f.write(key.private_bytes(serialization.Encoding.PEM,
                                      serialization.PrivateFormat.TraditionalOpenSSL,
                                      serialization.NoEncryption()))
        ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
    return ctx


@pytest.mark.asyncio
async def test_tls_upstream_handshake_and_pin_ok():
    key, cert_der = _self_signed()
    pin = hashlib.sha256(cert_der).hexdigest()
    ssl_ctx = _make_ssl_ctx(key, cert_der)
    server = await asyncio.start_server(_tls_rfb_server(key, cert_der),
                                        "127.0.0.1", 0, ssl=ssl_ctx)
    port = server.sockets[0].getsockname()[1]
    up = RfbTcpUpstream(RfbTcpConfig(host="127.0.0.1", port=port,
                                    password="synthetic-password", tls_enabled=True,
                                    tls_cert_sha256=pin))
    try:
        await up.connect()
        assert up.protocol_version == "RFB 003.008"
        assert up.server_init_raw == SERVER_INIT
        assert (up.stats.width, up.stats.height) == (1024, 768)
        assert pin not in str(up.stats.as_dict())
    finally:
        await up.close()
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_tls_upstream_rejects_wrong_pin():
    key, cert_der = _self_signed()
    ssl_ctx = _make_ssl_ctx(key, cert_der)
    server = await asyncio.start_server(_tls_rfb_server(key, cert_der),
                                        "127.0.0.1", 0, ssl=ssl_ctx)
    port = server.sockets[0].getsockname()[1]
    up = RfbTcpUpstream(RfbTcpConfig(host="127.0.0.1", port=port,
                                    password="synthetic-password", tls_enabled=True,
                                    tls_cert_sha256="00" * 32))
    with pytest.raises(Problem) as exc:
        await up.connect()
    assert exc.value.code == "bmc_cert_pin_mismatch"
    assert up.stats.trace.as_dict()["failure_reason"] == "tls_cert_pin_mismatch"
    await up.close()
    server.close()
    await server.wait_closed()



def test_adapter_requires_pin_and_controlled_network(monkeypatch):
    pin = "ab" * 32
    monkeypatch.setenv(PIN_ENV, pin)
    monkeypatch.setenv("KVMHUB_BMC_ALLOWED_NETWORKS", "192.0.2.0/24")
    adapter = make_adapter(dict(INFO))
    assert isinstance(adapter, HuaweiIbmcVncAdapter)
    assert adapter.host == "192.0.2.234"
    assert adapter.port == HUAWEI_VNC_PORT
    assert adapter.pin == pin
    with pytest.raises(Problem):
        make_adapter(dict(INFO, target="https://8.8.8.8"))

    monkeypatch.delenv(PIN_ENV, raising=False)
    with pytest.raises(Problem) as exc:
        make_adapter(dict(INFO))
    assert exc.value.code == "bmc_cert_pin_unconfigured"


def test_vnc_adapter_prefers_asset_fingerprint_over_env_pin(monkeypatch):
    monkeypatch.setenv(PIN_ENV, "ef" * 32)
    monkeypatch.setenv("KVMHUB_BMC_ALLOWED_NETWORKS", "192.0.2.0/24")
    asset_pin = "cd" * 32
    adapter = make_adapter(dict(INFO, fingerprint=asset_pin))
    assert adapter.pin == asset_pin


def test_vnc_adapter_uses_asset_fingerprint_without_env_pin(monkeypatch):
    monkeypatch.delenv(PIN_ENV, raising=False)
    monkeypatch.setenv("KVMHUB_BMC_ALLOWED_NETWORKS", "192.0.2.0/24")
    asset_pin = "cd" * 32
    adapter = make_adapter(dict(INFO, fingerprint=asset_pin))
    assert adapter.pin == asset_pin


def test_vnc_adapter_rejects_malformed_asset_fingerprint(monkeypatch):
    monkeypatch.setenv(PIN_ENV, "ef" * 32)
    monkeypatch.setenv("KVMHUB_BMC_ALLOWED_NETWORKS", "192.0.2.0/24")
    with pytest.raises(Problem) as exc:
        make_adapter(dict(INFO, fingerprint="bad"))
    assert exc.value.code == "bmc_cert_pin_invalid"


def test_store_gate_applies_controlled_network_to_huawei():
    from kvmhub.store import Store
    store = Store.__new__(Store)
    store.passthrough_targets = frozenset({"https://192.0.2.234", "https://8.8.8.8"})
    import ipaddress
    store.bmc_allowed_networks = (ipaddress.ip_network("192.0.2.0/24"),)
    assert store._adapter_allowed({"adapter": HUAWEI_IBMC_VNC_ADAPTER_ID,
                                   "target": "https://192.0.2.234"})
    assert not store._adapter_allowed({"adapter": HUAWEI_IBMC_VNC_ADAPTER_ID,
                                       "target": "https://8.8.8.8"})


def test_browser_handshake_is_credential_free():
    hs = StandardRfbBrowserHandshake(SERVER_INIT)
    assert hs.start() == b"RFB 003.008\n"
    out, _ = hs.feed(b"RFB 003.008\n")
    assert out == b"\x01\x01"
