"""One-click BMC identity probe for asset entry."""
from __future__ import annotations

import asyncio
import json
import time
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from kvmhub.platform import bmc_probe, services, vendor_registry
from kvmhub.platform.api import create_app
from kvmhub.platform.config import Settings
from kvmhub.platform.db import init_schema, seed_roles, session_factory, transaction
from kvmhub.platform.models import AuditLog, VendorProfile
from kvmhub.platform.redis_state import MemoryState

KEY = b"0123456789abcdef0123456789abcdef"
ORIGIN = "http://testserver"
ADMIN_PASSWORD = "synthetic-password"
PASSWORD = "unit-test-password"
APPROVED_CODE = "smci-x10-ast2100-rfb003008"


@pytest.fixture
def world(tmp_path, monkeypatch):
    cfg = Settings(env="test", db_url=f"sqlite:///{tmp_path}/control.db", redis_url="",
                   credential_key=KEY, session_ttl=3600, lease_seconds=30,
                   bootstrap_admin=None, bootstrap_password=None, strict_prod=False)
    app = create_app(cfg, state=MemoryState())
    platform = app.state.platform
    with transaction(platform.factory) as db:
        init_schema(platform.engine)
        seed_roles(db)
        vendor_registry.seed_builtin_profiles(db)
        services.create_user(db, "admin", ADMIN_PASSWORD, "admin", actor="test")
        approved = db.query(VendorProfile).filter(VendorProfile.code == APPROVED_CODE).one()
        approved.status = "approved"
        approved.review_due = time.time() + 86400 * 365
        profile_id = approved.id
        cred = services.save_credential(db, platform.cipher, label="lab bmc",
                                        username="root", password=PASSWORD, actor="test")
        credential_id = cred.id
        foreign = services.save_credential(
            db, platform.cipher, label="other tenant", username="root",
            password="sim-password", actor="test", tenant_id="tenant-other")
        foreign_id = foreign.id
    seen: list[tuple] = []

    def fake_probe(host, username, password, *, port=443, timeout=5,
                   allowed_networks=(), require_networks=False):
        seen.append((host, username, password, port, timeout, allowed_networks,
                     require_networks))
        return {
            "fingerprint": "ab" * 32, "redfish_auth": "basic",
            "inventory": {"resources": {"Managers": [
                {"Manufacturer": "Supermicro", "Model": "X10DRT-PS",
                 "FirmwareVersion": "8.78"}], "Systems": [], "Chassis": []}},
        }

    monkeypatch.setattr(bmc_probe, "probe", fake_probe)
    with TestClient(app, base_url=ORIGIN) as c:
        r = c.post("/api/v2/login", json={"username": "admin", "password": ADMIN_PASSWORD})
        assert r.status_code == 200, r.text
        csrf = r.json()["csrf"]
        yield c, {"csrf": csrf, "credential_id": credential_id,
                  "foreign_id": foreign_id, "profile_id": profile_id}, platform, seen
    platform.engine.dispose()


def _headers(world):
    c, ids, _, _ = world
    return {"Origin": ORIGIN, "X-CSRF-Token": ids["csrf"]}


def _post(world, **overrides):
    c, ids, _, _ = world
    body = {"address": "192.0.2.234", "credential_id": ids["credential_id"]}
    body.update(overrides)
    return c.post("/api/v2/assets/probe", headers=_headers(world), json=body)


def test_empty_management_cidrs_are_refused_when_required():
    with pytest.raises(bmc_probe.ProbeError, match="probe_target_not_allowed"):
        bmc_probe.validate_probe_target("192.0.2.234", allowed_networks=(),
                                        require_networks=True)
    assert bmc_probe.validate_probe_target("192.0.2.234")[0] == "192.0.2.234"


def test_probe_fills_identity_and_matches_an_approved_brand(world):
    response = _post(world)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["detection"]["vendor"] == "supermicro"
    assert body["detection"]["model"] == "X10DRT-PS"
    assert body["detection"]["firmware"] == "8.78"
    assert body["certificate_sha256"] == "ab" * 32
    assert body["redfish_auth"] == "basic"
    assert body["usable"] is True
    assert body["profile_id"] == world[1]["profile_id"]
    assert body["profile_code"] == APPROVED_CODE


def test_probe_never_returns_the_credential(world):
    response = _post(world)
    raw = response.text
    assert PASSWORD not in raw
    assert "root" not in raw
    assert "password_cipher" not in raw
    assert world[3][0][1:3] == ("root", PASSWORD)


def test_probe_rejects_when_concurrency_slots_are_exhausted(world):
    c, ids, _, _ = world
    original = c.app.state.probe_semaphore
    c.app.state.probe_semaphore = asyncio.Semaphore(0)
    try:
        r = _post(world)
        assert r.status_code == 429, r.text
        assert r.json()["error"] == "probe_busy"
        assert r.json()["retryable"] is True
        assert world[3] == []
    finally:
        c.app.state.probe_semaphore = original


def test_probe_audit_row_keeps_no_secret(world):
    assert _post(world).status_code == 200
    c, _, platform, _ = world
    with transaction(platform.factory) as db:
        row = db.scalar(select(AuditLog).where(AuditLog.action == "asset_probe"))
    assert row is not None
    detail = row.detail if isinstance(row.detail, dict) else json.loads(row.detail)
    assert PASSWORD not in str(detail)
    assert "root" not in str(detail)
    assert detail["fingerprint_prefix"] == "ab" * 6
    assert detail["profile_id"] == world[1]["profile_id"]


def test_probe_rejects_a_foreign_tenant_credential(world):
    response = _post(world, credential_id=world[1]["foreign_id"])
    assert response.status_code == 404
    assert response.json()["error"] == "credential_not_found"
    assert world[3] == []


def test_probe_requires_address_and_credential(world):
    assert _post(world, address="").status_code == 400
    assert _post(world, credential_id="").status_code == 400


def test_unknown_brand_is_reported_not_approved(world, monkeypatch):
    def unknown(host, username, password, **kwargs):
        return {"fingerprint": "cd" * 32, "redfish_auth": "basic",
                "inventory": {"resources": {"Managers": [
                    {"Manufacturer": "ACME", "Model": "M1", "FirmwareVersion": "1"}]}}}
    monkeypatch.setattr(bmc_probe, "probe", unknown)
    body = _post(world).json()
    assert body["usable"] is False
    assert body["profile_id"] is None
    assert "新品牌适配" in body["note"]
    assert body["detection"]["model"] == "M1"


def test_transient_probe_error_is_marked_retryable_and_audited(world, monkeypatch, caplog):
    def broken(*args, **kwargs):
        raise bmc_probe.ProbeError("certificate_unavailable")
    monkeypatch.setattr(bmc_probe, "probe", broken)
    with caplog.at_level("WARNING"):
        response = _post(world)
    assert response.status_code == 502
    body = response.json()
    assert body["error"] == "asset_probe_failed"
    assert body["retryable"] is True
    assert "certificate_unavailable" in caplog.text
    assert "192.0.2.234" in caplog.text
    assert PASSWORD not in caplog.text
    c, _, platform, _ = world
    with transaction(platform.factory) as db:
        row = db.scalar(select(AuditLog).where(AuditLog.action == "asset_probe_failed"))
    assert row is not None
    detail = row.detail if isinstance(row.detail, dict) else json.loads(row.detail)
    assert detail["error"] == "certificate_unavailable"
    assert detail["retryable"] is True
    assert PASSWORD not in str(detail)


def test_auth_failure_is_not_retryable(world, monkeypatch):
    def denied(*args, **kwargs):
        raise bmc_probe.ProbeError("probe_auth_failed")
    monkeypatch.setattr(bmc_probe, "probe", denied)
    response = _post(world)
    assert response.status_code == 502
    body = response.json()
    assert body["error"] == "asset_probe_failed"
    assert "retryable" not in body


def test_probe_error_codes_classify_retryability():
    assert bmc_probe.ProbeError("certificate_unavailable").retryable is True
    assert bmc_probe.ProbeError("inventory_unavailable").retryable is True
    assert bmc_probe.ProbeError("probe_auth_failed").retryable is False
    assert bmc_probe.ProbeError("invalid_probe_target").retryable is False
    assert bmc_probe.ProbeError("probe_target_not_allowed").retryable is False


@pytest.mark.parametrize("host", ["127.0.0.1", "::1", "169.254.1.2",
                                  "224.0.0.1", "0.0.0.0", "localhost",
                                  "169.254.169.254", "100.100.100.200",
                                  "fd00:ec2::254", "169.254.170.2"])
def test_probe_refuses_non_bmc_targets(host):
    with pytest.raises(bmc_probe.ProbeError) as exc:
        bmc_probe.validate_probe_host(host)
    assert exc.value.code == "probe_target_not_allowed"


def test_probe_allows_the_private_management_network():
    assert bmc_probe.validate_probe_host("192.0.2.234") == "192.0.2.234"


def test_validate_probe_target_pins_resolved_ip_and_keeps_sni(monkeypatch):
    monkeypatch.setattr(bmc_probe.socket, "getaddrinfo",
                        lambda *a, **k: [(2, 1, 6, "", ("192.0.2.50", 0))])
    connect_ip, sni = bmc_probe.validate_probe_target("bmc.internal.example")
    assert connect_ip == "192.0.2.50"
    assert sni == "bmc.internal.example"


def test_validate_probe_target_rejects_any_unsafe_address(monkeypatch):
    monkeypatch.setattr(
        bmc_probe.socket, "getaddrinfo",
        lambda *a, **k: [(2, 1, 6, "", ("192.0.2.50", 0)),
                         (2, 1, 6, "", ("127.0.0.1", 0))])
    with pytest.raises(bmc_probe.ProbeError) as exc:
        bmc_probe.validate_probe_target("bmc.internal.example")
    assert exc.value.code == "probe_target_not_allowed"


def test_tls_identity_mismatch_is_not_retryable():
    err = bmc_probe.ProbeError("tls_identity_mismatch", retryable=False)
    assert err.retryable is False


def test_probe_rejects_malformed_target():
    with pytest.raises(bmc_probe.ProbeError):
        bmc_probe.validate_probe_host("not a host")


def test_api_passes_controlled_networks_to_probe(world):
    c, ids, platform, seen = world
    object.__setattr__(platform.cfg, "bmc_allowed_networks",
                       "192.0.2.0/24,192.0.2.0/24")
    assert _post(world).status_code == 200
    assert seen[-1][-2] == "192.0.2.0/24,192.0.2.0/24"


def test_probe_refuses_target_outside_controlled_network():
    with pytest.raises(bmc_probe.ProbeError) as exc:
        bmc_probe.probe("8.8.8.8", "root", "synthetic-password",
                        allowed_networks=("192.0.2.0/24",))
    assert exc.value.code == "probe_target_not_allowed"


def test_probe_refuses_hostname_when_controlled_network_configured():
    with pytest.raises(bmc_probe.ProbeError) as exc:
        bmc_probe.validate_probe_target(
            "bmc.internal.example", allowed_networks=("192.0.2.0/24",))
    assert exc.value.code == "probe_target_not_allowed"


def test_probe_rejects_non_redfish_port():
    with pytest.raises(bmc_probe.ProbeError) as exc:
        bmc_probe.probe("192.0.2.234", "root", "synthetic-password", port=22)
    assert exc.value.code == "invalid_probe_port"


def test_a_bmc_without_redfish_is_not_a_transient_probe_failure(monkeypatch):
    from demos.redfish_probe import RedfishError

    from kvmhub.platform import bmc_probe

    class NoRedfish:
        def __init__(self, *args, **kwargs):
            pass

        def json(self, path):
            raise RedfishError("http_404")

        def login(self, username, password):
            raise RedfishError("http_404")

        def logout(self):
            pass

    monkeypatch.setattr(bmc_probe, "Redfish", NoRedfish)
    with pytest.raises(bmc_probe.ProbeError) as exc:
        bmc_probe.read_inventory("192.0.2.50", "bmc.example", 443, 8, "ab" * 32, "u", "p")
    assert exc.value.code == "redfish_not_available"
    assert exc.value.retryable is False
