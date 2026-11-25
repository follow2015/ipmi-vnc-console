"""G0 device status: live authoritative state, tenant-safe shape, readyz."""
from __future__ import annotations

import json
import time
import uuid
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from kvmhub.platform import services, vendor_registry
from kvmhub.platform.api import create_app
from kvmhub.platform.connection_config import resolve_domain_id
from kvmhub.platform.config import Settings
from kvmhub.platform.db import (bootstrap_platform_admin, init_schema, seed_roles,
                                session_factory, transaction)
from kvmhub.platform.models import (AccessGrant, Asset, AssetConnection,
                                    Capability, Credential, DeviceAdmission,
                                    DEFAULT_TENANT_ID, ExecutionDomain,
                                    PlaneProjection)
from kvmhub.platform.redis_state import MemoryState
from kvmhub.platform.security import CredentialCipher
from kvmhub.store import Store
from tools.platform_admin import build_migration_report

KEY = b"0123456789abcdef0123456789abcdef"
ORIGIN = "http://testserver"
ADMIN_PASSWORD = "synthetic-password"
PLATFORM_PASSWORD = "unit-test-password"
DIGEST = "b" * 64
GEN = "gen-status"
POLICY = "policy-status"


@pytest.fixture
def rig(tmp_path):
    cfg = Settings(env="test", db_url="sqlite:///:memory:", redis_url="",
                   credential_key=KEY, session_ttl=3600, lease_seconds=30,
                   bootstrap_admin=None, bootstrap_password=None, strict_prod=False)
    state = MemoryState()
    app = create_app(cfg, state=state)
    platform = app.state.platform
    stamp = time.time()
    asset_id = str(uuid.uuid4())
    with transaction(platform.factory) as db:
        init_schema(platform.engine)
        seed_roles(db)
        vendor_registry.seed_builtin_profiles(db)
        admin = services.create_user(db, "admin", ADMIN_PASSWORD, "admin", actor="test")
        bootstrap_platform_admin(db, "platform-admin", PLATFORM_PASSWORD)
        cap = Capability(id=str(uuid.uuid4()), vendor="Supermicro", model="X10",
                         firmware="1.0", adapter="rfb-vnc", status="verified",
                         evidence="measured", approver="operator",
                         expires=stamp + 86400, created=stamp)
        cred = Credential(id=str(uuid.uuid4()), label="bmc", username_cipher=b"u",
                          password_cipher=b"p", key_version=1, created=stamp)
        db.add_all([cap, cred])
        db.flush()
        db.add(Asset(id=asset_id, tenant_id=DEFAULT_TENANT_ID, name="node",
                     address="192.0.2.10", capability_id=cap.id, credential_id=cred.id,
                     created=stamp, updated=stamp))
        db.add(AccessGrant(tenant_id=DEFAULT_TENANT_ID, user_id=admin.id,
                           asset_id=asset_id, expires=stamp + 86400, created=stamp))
        db.add_all([
            AssetConnection(id=str(uuid.uuid4()), asset_id=asset_id, revision=1,
                            endpoint_json="[]", adapter="rfb-vnc", identity_policy="{}",
                            source_versions_json="{}", secret_ref=cred.id,
                            secret_source="bmc", secret_revision=1, schema="v2",
                            digest=DIGEST, created=stamp),
            PlaneProjection(id=str(uuid.uuid4()), asset_id=asset_id,
                            domain_id="admission-canary", desired_revision=1,
                            desired_digest=DIGEST, applied_revision=1,
                            applied_digest=DIGEST, generation=GEN,
                            policy_fingerprint=POLICY, status="ready", ack_at=stamp),
            ExecutionDomain(domain_id="admission-canary", store_id="status-store",
                            endpoint="https://internal.invalid",
                            supported_schema='["v2"]', policy_fingerprint=POLICY,
                            generation=GEN, health="healthy"),
            DeviceAdmission(id=str(uuid.uuid4()), asset_id=asset_id, revision=1,
                            state="approved", tenant_id=DEFAULT_TENANT_ID,
                            domain_id="admission-canary", approver="operator",
                            evidence="measured", expires=stamp + 86400,
                            review_due=stamp + 86400, created=stamp),
        ])
    with TestClient(app, base_url=ORIGIN) as client:
        yield SimpleNamespace(client=client, platform=platform, asset_id=asset_id,
                              factory=platform.factory, engine=platform.engine)
    platform.engine.dispose()


def _tenant_login(rig):
    response = rig.client.post("/api/v2/login", json={"username": "admin",
                                                      "password": ADMIN_PASSWORD})
    assert response.status_code == 200, response.text
    return response.json()["csrf"]


def _platform_login(rig):
    response = rig.client.post("/api/v2/platform/login",
                               json={"username": "platform-admin",
                                     "password": PLATFORM_PASSWORD})
    assert response.status_code == 200, response.text
    return response.json()["csrf"]


def _headers(csrf, **extra):
    return {"Origin": ORIGIN, "X-CSRF-Token": csrf, **extra}


def test_status_is_recomputed_from_the_database_after_revoke(rig):
    csrf = _tenant_login(rig)
    url = f"/api/v2/assets/{rig.asset_id}/admission"
    first = rig.client.get(url, headers=_headers(csrf))
    assert first.status_code == 200, first.text
    assert first.json()["state"] == "available"

    with transaction(rig.factory) as db:
        db.add(DeviceAdmission(id=str(uuid.uuid4()), asset_id=rig.asset_id,
                               revision=2, state="revoked",
                               tenant_id=DEFAULT_TENANT_ID,
                               domain_id="admission-canary", created=time.time()))
    second = rig.client.get(url, headers=_headers(csrf))
    assert second.json()["state"] == "unavailable"
    assert second.json()["reason"] == "admission_revoked"
    assert second.json()["available"] is False


def test_pending_asset_does_not_degrade_readyz(rig):
    with transaction(rig.factory) as db:
        db.add(DeviceAdmission(id=str(uuid.uuid4()), asset_id=rig.asset_id,
                               revision=2, state="pending",
                               tenant_id=DEFAULT_TENANT_ID,
                               domain_id="admission-canary", created=time.time()))
    ready = rig.client.get("/readyz")
    assert ready.status_code == 200, ready.text
    assert ready.json()["checks"]["database"] is True
    csrf = _tenant_login(rig)
    status = rig.client.get(f"/api/v2/assets/{rig.asset_id}/admission",
                            headers=_headers(csrf))
    assert status.json()["state"] == "pending"


def test_tenant_status_shape_has_no_internal_or_ipmi_fields(rig):
    csrf = _tenant_login(rig)
    response = rig.client.get(f"/api/v2/assets/{rig.asset_id}/admission",
                              headers=_headers(csrf))
    payload = response.json()
    assert payload["asset_id"] == rig.asset_id
    assert "checked_at" in payload
    assert "desired" not in payload and "applied" not in payload
    text = json.dumps(payload)
    for hidden in ("192.0.2.10", "generation", "policy_fingerprint", "error", "address"):
        assert hidden not in text


def test_platform_status_exposes_desired_and_applied(rig):
    csrf = _platform_login(rig)
    response = rig.client.get(
        f"/api/v2/platform/assets/{rig.asset_id}/admission", headers=_headers(csrf))
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["desired"]["revision"] == 1
    assert payload["desired"]["digest"] == DIGEST
    assert payload["applied"]["digest"] == DIGEST
    assert payload["state"] == "available"


def test_migration_report_includes_g0_diffs(tmp_path, rig):
    store = Store(str(tmp_path / "data.db"), KEY)
    try:
        with transaction(rig.factory) as db:
            row = db.scalar(select(PlaneProjection).where(
                PlaneProjection.asset_id == rig.asset_id))
            row.desired_revision = 2
            row.desired_digest = "c" * 64
            row.generation = "old-gen"
            row.policy_fingerprint = "old-policy"
            row.status = "pending"
            report = build_migration_report(db=db, store=store, now=time.time())
        assert any(row["asset"] == rig.asset_id
                   for row in report["categories"]["projection_revision_behind"])
        assert any(row["asset"] == rig.asset_id
                   for row in report["categories"]["domain_generation_mismatch"])
        assert any(row["asset"] == rig.asset_id
                   for row in report["categories"]["domain_policy_mismatch"])
    finally:
        store.close()


def test_status_follows_the_assets_own_domain(rig):
    stamp = time.time()
    with transaction(rig.factory) as db:
        db.add(ExecutionDomain(domain_id="domain-b", store_id="status-store-b",
                               endpoint="https://internal.invalid",
                               supported_schema='["v2"]', policy_fingerprint=POLICY,
                               generation=GEN, health="healthy"))
        db.add(PlaneProjection(id=str(uuid.uuid4()), asset_id=rig.asset_id,
                               domain_id="domain-b", desired_revision=1,
                               desired_digest=DIGEST, applied_revision=1,
                               applied_digest=DIGEST, generation=GEN,
                               policy_fingerprint=POLICY, status="ready", ack_at=stamp))
        db.scalar(select(DeviceAdmission).where(
            DeviceAdmission.asset_id == rig.asset_id).order_by(
                DeviceAdmission.revision.desc()).limit(1)).domain_id = "domain-b"
        db.flush()

    csrf = _platform_login(rig)
    response = rig.client.get(
        f"/api/v2/platform/assets/{rig.asset_id}/admission", headers=_headers(csrf))
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["available"] is True
    assert body["desired"]["domain_id"] == "domain-b"


def test_multiple_domains_without_assignment_are_refused(rig):
    with transaction(rig.factory) as db:
        db.add(ExecutionDomain(domain_id="domain-c", store_id="status-store-c",
                               endpoint="https://internal.invalid",
                               supported_schema='["v2"]', policy_fingerprint=POLICY,
                               generation=GEN, health="healthy"))
        db.flush()
    with transaction(rig.factory) as db:
        with pytest.raises(services.PlatformError) as exc:
            resolve_domain_id(db, "unassigned-asset")
    assert exc.value.code == "execution_domain_unavailable"
