"""Legacy-BMC TLS compatibility: relax cipher policy only where identity is pinned."""
from __future__ import annotations

import ssl

from demos.redfish_probe import Redfish


def _spy_set_ciphers(monkeypatch):
    calls: list[str] = []
    real = ssl.SSLContext.set_ciphers

    def spy(self, ciphers: str):
        calls.append(ciphers)
        return real(self, ciphers)

    monkeypatch.setattr(ssl.SSLContext, "set_ciphers", spy)
    return calls


def test_ca_trusted_mode_keeps_strict_ciphers(monkeypatch, tmp_path):
    from demos.redfish_probe import legacy_tls_context
    calls = _spy_set_ciphers(monkeypatch)
    context = legacy_tls_context(relaxed_identity=False)
    assert calls == [], "CA-trusted mode must not weaken the cipher policy"
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True


def test_pinned_mode_relaxes_legacy_ciphers(monkeypatch):
    from demos.redfish_probe import legacy_tls_context
    calls = _spy_set_ciphers(monkeypatch)
    context = legacy_tls_context(relaxed_identity=True)
    assert any("SECLEVEL=0" in c for c in calls)
    assert context.check_hostname is False
    assert context.verify_mode == ssl.CERT_NONE


def test_relaxed_context_survives_platform_without_seclevel(monkeypatch):
    from demos.redfish_probe import legacy_tls_context

    def no_seclevel(self, ciphers: str):
        raise ssl.SSLError("unsupported cipher value")

    monkeypatch.setattr(ssl.SSLContext, "set_ciphers", no_seclevel)
    context = legacy_tls_context(relaxed_identity=True)
    assert context.verify_mode == ssl.CERT_NONE, "progressive enhancement: keep working"


def test_pinned_redfish_uses_relaxed_context(monkeypatch):
    calls = _spy_set_ciphers(monkeypatch)
    Redfish("127.0.0.1", 443, cert_sha256="0" * 64)
    assert any("SECLEVEL=0" in c for c in calls)


def test_unpinned_redfish_keeps_strict_context(monkeypatch):
    calls = _spy_set_ciphers(monkeypatch)
    Redfish("127.0.0.1", 443)
    assert calls == [], "no pin and no CA means no reason to relax ciphers"
