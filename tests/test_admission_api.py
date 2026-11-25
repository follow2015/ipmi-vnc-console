"""G1 authority listener: mTLS role, authoritative checks, short-lived permit."""
import json
import socket
import time
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest
from aiohttp.test_utils import TestClient, TestServer
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from kvmhub.platform import admission_api
from kvmhub.operation_permit import verify_operation_permit
from kvmhub.platform.db import (init_schema, make_engine, seed_default_tenant,
                                seed_roles, session_factory, transaction)
from kvmhub.platform.models import (AccessGrant, Asset, AssetConnection, Capability,
                                    Credential, DeviceAdmission, DEFAULT_TENANT_ID,
                                    ExecutionDomain, PlaneProjection, Tenant, User)
from tools.bootstrap import generate

DIGEST = "e" * 64
GEN = "gen-authority"
DOMAIN = "admission-canary"


def _cert_cn(value):
    return {"subject": ((("commonName", value),),)}


@pytest.fixture
def rig(tmp_path, monkeypatch):
    identity = generate(tmp_path / "identity")
    cfg = json.loads((identity / "manager.json").read_text())
    engine = make_engine(f"sqlite:///{tmp_path / 'control.db'}")
    init_schema(engine)
    factory = session_factory(engine)
    stamp = time.time()
    user_id, asset_id = str(uuid.uuid4()), str(uuid.uuid4())
    with transaction(factory) as db:
        seed_roles(db)
        seed_default_tenant(db, now=stamp)
        db.add_all([
            User(id=user_id, tenant_id=DEFAULT_TENANT_ID, username="operator",
                 display_name="operator", password_hash="x", is_active=True,
                 created=stamp),
            Capability(id="cap-authority", vendor="Supermicro", model="X10",
                       firmware="1.0", adapter="rfb-vnc", status="verified",
                       evidence="measured", approver="operator",
                       expires=stamp + 3600, created=stamp),
            Credential(id="cred-authority", label="bmc", username_cipher=b"u",
                       password_cipher=b"p", key_version=1, created=stamp),
        ])
        db.flush()
        db.add(Asset(id=asset_id, tenant_id=DEFAULT_TENANT_ID, name="node",
                     address="192.0.2.10", credential_id="cred-authority",
                     capability_id="cap-authority", created=stamp, updated=stamp))
        db.add_all([
            AccessGrant(tenant_id=DEFAULT_TENANT_ID, user_id=user_id,
                        asset_id=asset_id, expires=stamp + 3600, created=stamp),
            AssetConnection(id="conn-authority", asset_id=asset_id, revision=3,
                            endpoint_json="[]", adapter="rfb-vnc",
                            identity_policy="{}", source_versions_json="{}",
                            secret_ref="cred-authority", secret_source="bmc",
                            secret_revision=1, schema="v2", digest=DIGEST,
                            created=stamp),
            PlaneProjection(id="proj-authority", asset_id=asset_id, domain_id=DOMAIN,
                            desired_revision=3, desired_digest=DIGEST,
                            applied_revision=3, applied_digest=DIGEST,
                            generation=GEN, policy_fingerprint="policy-authority",
                            status="ready", error="", ack_at=stamp),
            ExecutionDomain(domain_id=DOMAIN, store_id="store-authority",
                            endpoint="https://internal.invalid",
                            supported_schema='["v2"]',
                            policy_fingerprint="policy-authority",
                            generation=GEN, health="healthy"),
            DeviceAdmission(id="adm-authority", asset_id=asset_id, revision=2,
                            state="approved", tenant_id=DEFAULT_TENANT_ID,
                            domain_id=DOMAIN, approver="operator", evidence="measured",
                            expires=stamp + 3600, review_due=stamp + 3600,
                            created=stamp),
        ])
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    host = f"127.0.0.1:{port}"
    app = admission_api.create_admission_app(cfg, factory, expected_host=host)
    monkeypatch.setattr(admission_api, "peer_certificate",
                        lambda _transport: _cert_cn("kvmhub-authority-client"))
    public_key = load_pem_private_key(
        Path(cfg["signing_key"]).read_bytes(), password=None).public_key()
    body = {
        "schema": "g1-v2", "operation": "exchange", "sid": "sid-authority",
        "asset_id": asset_id, "user_id": user_id, "tenant_id": DEFAULT_TENANT_ID,
        "domain_id": DOMAIN, "worker_id": cfg["worker_id"],
        "instance_id": cfg["instance_id"], "connection_revision": 3,
        "admission_revision": 2, "digest": DIGEST, "generation": GEN,
        "session_started_at": stamp, "hard_until": stamp + 30,
    }
    yield SimpleNamespace(app=app, port=port, cfg=cfg, factory=factory, engine=engine,
                          body=body, public_key=public_key, asset_id=asset_id,
                          host=host)
    engine.dispose()


def client(rig) -> TestClient:
    return TestClient(TestServer(rig.app, port=rig.port))


async def test_authority_issues_bound_permit(rig):
    async with client(rig) as http:
        response = await http.post("/authority/v2/authorize", json=rig.body,
                                   headers={"Host": rig.host})
        assert response.status == 200, await response.text()
        payload = await response.json()
    claims = verify_operation_permit(rig.public_key, payload["permit"],
                                     expected={"op": "exchange", "sid": "sid-authority",
                                               "dgs": DIGEST, "aid": rig.asset_id})
    assert claims["aud"] == "kvmhub-device-operation-v2"
    assert payload["lease_not_after"] <= rig.body["hard_until"]


async def test_revoked_asset_is_denied_without_a_permit(rig):
    with transaction(rig.factory) as db:
        stamp = time.time()
        admission = db.get(DeviceAdmission, "adm-authority")
        admission.state = "revoked"
        admission.expires = stamp + 3600
        admission.review_due = stamp + 3600
    async with client(rig) as http:
        response = await http.post("/authority/v2/authorize", json=rig.body,
                                   headers={"Host": rig.host})
        assert response.status == 403
        assert (await response.json())["error"] == "device_not_admitted"


async def test_worker_certificate_is_not_an_authority_client(rig, monkeypatch):
    monkeypatch.setattr(admission_api, "peer_certificate",
                        lambda _transport: _cert_cn(rig.cfg["worker_cert_cn"]))
    async with client(rig) as http:
        response = await http.post("/authority/v2/authorize", json=rig.body,
                                   headers={"Host": rig.host})
        assert response.status == 403
        assert (await response.json())["error"] == "admission_certificate_mismatch"


async def test_unknown_body_field_and_stale_digest_are_denied(rig):
    extra = {**rig.body, "unexpected": "value"}
    async with client(rig) as http:
        response = await http.post("/authority/v2/authorize", json=extra,
                                   headers={"Host": rig.host})
        assert response.status == 409
        assert (await response.json())["error"] == "projection_schema_unsupported"

        stale = {**rig.body, "digest": "f" * 64}
        response = await http.post("/authority/v2/authorize", json=stale,
                                   headers={"Host": rig.host})
        assert response.status == 409
        assert (await response.json())["error"] == "connection_revision_mismatch"


def test_authority_db_timeout_statement_matches_each_backend():
    assert admission_api.authority_db_timeout_statement("sqlite") == "PRAGMA busy_timeout = 300"
    assert admission_api.authority_db_timeout_statement("mysql") == (
        "SET SESSION max_execution_time = 300")
    assert admission_api.authority_db_timeout_statement("postgresql") == (
        "SET LOCAL statement_timeout = '300ms'")
    assert admission_api.authority_db_timeout_statement("mssql") is None


async def test_authority_rejects_wrong_body_types(rig):
    bad = {**rig.body, "connection_revision": "3"}
    async with client(rig) as http:
        response = await http.post("/authority/v2/authorize", json=bad,
                                   headers={"Host": rig.host})
        assert response.status == 400
        assert (await response.json())["error"] == "invalid_request"


async def test_platform_client_cannot_request_worker_operations(rig, monkeypatch):
    monkeypatch.setattr(admission_api, "peer_certificate",
                        lambda _transport: _cert_cn("kvmhub-platform-client"))
    bad = {**rig.body, "operation": "renew"}
    async with client(rig) as http:
        response = await http.post("/authority/v2/authorize", json=bad,
                                   headers={"Host": rig.host})
        assert response.status == 403
        assert (await response.json())["error"] == "permission_denied"


async def test_allocate_permit_carries_absolute_session_ceiling(rig):
    body = {**rig.body, "operation": "allocate",
            "hard_until": rig.body["session_started_at"] + 4 * 3600}
    async with client(rig) as http:
        response = await http.post("/authority/v2/authorize", json=body,
                                   headers={"Host": rig.host})
        assert response.status == 200, await response.text()
        payload = await response.json()
    claims = verify_operation_permit(
        rig.public_key, payload["permit"],
        expected={"op": "allocate", "sid": "sid-authority"})
    authoritative_ceiling = body["session_started_at"] + 3600
    assert payload["lease_not_after"] == authoritative_ceiling
    assert claims["lna"] == authoritative_ceiling
    assert payload["lease_not_after"] > body["session_started_at"] + 30

    async with client(rig) as http:
        response = await http.post(
            "/authority/v2/authorize", json={**body, "operation": "renew"},
            headers={"Host": rig.host})
        assert response.status == 200, await response.text()
        renew_payload = await response.json()
    now = time.time()
    assert now + 25 < renew_payload["lease_not_after"] <= now + 31
