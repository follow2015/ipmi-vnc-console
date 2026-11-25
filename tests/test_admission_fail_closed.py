"""Managed admission domains must never silently fall back to the legacy chain."""
from __future__ import annotations

import pytest

from kvmhub.admission_runtime import authority_from_env
from kvmhub.platform import services
from kvmhub.platform.config import Settings
from kvmhub.platform.console import managed_operation_required

DOMAIN = "admission-canary"
KEY = b"0123456789abcdef0123456789abcdef"


def test_managed_domain_without_authority_is_refused():
    assembly = {"g0": {"domain_id": DOMAIN, "ready": True}}
    with pytest.raises(services.PlatformError) as exc:
        managed_operation_required(assembly, (DOMAIN,), None)
    assert exc.value.code == "admission_service_unavailable"
    assert exc.value.status == 503


def test_managed_domain_with_pending_g0_is_refused():
    assembly = {"g0": {"domain_id": DOMAIN, "ready": False}}
    with pytest.raises(services.PlatformError) as exc:
        managed_operation_required(assembly, (DOMAIN,), object())
    assert exc.value.code == "connection_config_pending"
    assert exc.value.status == 409


def test_unmanaged_domain_keeps_the_legacy_path():
    g0 = {"domain_id": "legacy", "ready": False}
    managed, returned = managed_operation_required({"g0": g0}, (DOMAIN,), None)
    assert managed is False
    assert returned is g0


def test_authority_env_refuses_managed_domains_without_a_url(monkeypatch):
    monkeypatch.delenv("KVMHUB_AUTHORITY_URL", raising=False)
    monkeypatch.setenv("KVMHUB_MANAGED_DOMAINS", DOMAIN)
    with pytest.raises(ValueError, match="requires KVMHUB_AUTHORITY_URL"):
        authority_from_env(object())


def test_settings_reject_managed_domains_without_authority_url():
    cfg = Settings(env="test", db_url="sqlite:///:memory:", redis_url="",
                   credential_key=KEY, session_ttl=3600, lease_seconds=30,
                   managed_domains=DOMAIN, bootstrap_admin=None, bootstrap_password=None,
                   strict_prod=False)
    with pytest.raises(ValueError, match="KVMHUB_MANAGED_DOMAINS requires KVMHUB_AUTHORITY_URL"):
        cfg.validate()
