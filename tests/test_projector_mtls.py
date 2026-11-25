"""G0 projector: dedicated mTLS role, no body logging, CAS ACK and replay."""
import asyncio
import json
import socket
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest
from aiohttp.test_utils import TestClient, TestServer
from sqlalchemy import select

from kvmhub import internal_api
from kvmhub.common import Problem, digest as hash_digest
from kvmhub.internal_api import (check_projector_credentials, check_worker_credentials,
                                 create_app)
from kvmhub.platform.db import init_schema, make_engine, session_factory, transaction
from kvmhub.platform.models import (Asset, AssetConnection, Capability, Credential,
                                    ExecutionDomain, PlaneOutbox, PlaneProjection)
from kvmhub.projector import _permanent_failure, run_projector_once
from kvmhub.store import Store
from tools.bootstrap import generate

KEY = b"k" * 32
STAMP = 1_760_000_100.0
ASSET = "asset-projector"
DOMAIN = "admission-canary"
GEN = "gen-alpha"
POLICY = "policy-1"
DIGEST = "a" * 64
SECRET_PASSWORD = "synthetic-password"


class FakeSSL:
    def __init__(self, cn):
        self.cn = cn

    def getpeercert(self):
        if not self.cn:
            return {}
        return {"subject": ((("commonName", self.cn),),)}


class FakeTransport:
    def __init__(self, ssl_object):
        self._ssl = ssl_object

    def get_extra_info(self, name, default=None):
        return self._ssl if name == "ssl_object" else default


def _cert_cn(value):
    return {"subject": ((("commonName", value),),)}


def _secret_provider(db, cipher, asset):
    return {"username": "vnc", "password": SECRET_PASSWORD}, "vnc_hidden"


@pytest.fixture
def rig(tmp_path):
    engine = make_engine(f"sqlite:///{tmp_path / 'control.db'}")
    init_schema(engine)
    factory = session_factory(engine)
    store = Store(tmp_path / "plane.db", KEY)
    store.generation = GEN
    cid = str(uuid.uuid4())
    capid = str(uuid.uuid4())
    with transaction(factory) as db:
        db.add_all([
            Credential(id=cid, tenant_id=None, label="bmc", username_cipher=b"u",
                       password_cipher=b"p", key_version=1, revision=1, created=STAMP),
            Capability(id=capid, vendor="Supermicro", model="X10", firmware="1.0",
                       adapter="rfb-vnc", status="verified", evidence="measured",
                       approver="operator", expires=STAMP + 86400, revision=1,
                       created=STAMP),
        ])
        db.flush()
        db.add(Asset(id=ASSET, tenant_id=None, name="node", address="192.0.2.20",
                     credential_id=cid, capability_id=capid, created=STAMP, updated=STAMP))
        db.add_all([
            AssetConnection(id=str(uuid.uuid4()), asset_id=ASSET, revision=1,
                            endpoint_json='[{"host":"192.0.2.20","port":5900}]',
                            adapter="rfb-vnc", identity_policy="{}",
                            source_versions_json="{}", secret_ref=cid,
                            secret_source="vnc_hidden", secret_revision=1,
                            schema="v2", digest=DIGEST, created=STAMP),
            PlaneProjection(id=str(uuid.uuid4()), asset_id=ASSET, domain_id=DOMAIN,
                            desired_revision=1, desired_digest=DIGEST,
                            generation=GEN, policy_fingerprint=POLICY,
                            status="pending", error="", ack_at=0.0),
            ExecutionDomain(domain_id=DOMAIN, store_id="store-1",
                            endpoint="https://internal.invalid",
                            supported_schema='["v2"]', policy_fingerprint=POLICY,
                            generation=GEN, health="healthy"),
            PlaneOutbox(event_id=str(uuid.uuid4()), asset_id=ASSET, revision=1,
                        event_type="test_change", created=STAMP, next_attempt=STAMP),
        ])
    yield SimpleNamespace(factory=factory, store=store, engine=engine)
    store.close()
    engine.dispose()


def _body():
    return {
        "snapshot": {
            "endpoint_json": '[{"host":"192.0.2.20","port":5900}]',
            "adapter": "rfb-vnc",
            "identity_policy": "{}",
            "source_versions_json": "{}",
            "secret_ref": "cred-1",
            "secret_source": "vnc_hidden",
            "secret_revision": 1,
            "schema": "v2",
        },
        "secret": {"username": "vnc", "password": SECRET_PASSWORD},
        "digest": DIGEST,
        "domain_id": DOMAIN,
        "generation": GEN,
        "policy_fingerprint": POLICY,
    }




def test_worker_certificate_cannot_write_projection():
    cfg = {"worker_cert_cn": "w1-worker", "projector_cert_cn": "kvmhub-projector"}
    with pytest.raises(Problem) as exc:
        check_projector_credentials({}, FakeTransport(FakeSSL("w1-worker")), cfg)
    assert exc.value.code == "projector_certificate_mismatch"


def test_projector_certificate_cannot_exchange_session():
    cfg = {"worker_cert_cn": "w1-worker", "projector_cert_cn": "kvmhub-projector",
           "worker_proof_hash": hash_digest("proof")}
    with pytest.raises(Problem) as exc:
        check_worker_credentials({"x-worker-proof": "proof"},
                                 FakeTransport(FakeSSL("kvmhub-projector")), cfg)
    assert exc.value.code == "worker_certificate_mismatch"




def _listener(tmp_path, store, cfg):
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    app = create_app(cfg, store, expected_host=f"127.0.0.1:{port}")
    return TestClient(TestServer(app, port=port)), f"127.0.0.1:{port}"


async def test_projection_route_accepts_projector_role_and_never_logs_secret(
        tmp_path, rig, monkeypatch):
    identity = generate(tmp_path / "identity")
    cfg = json.loads((identity / "manager.json").read_text())
    cfg["projector_cert_cn"] = "kvmhub-projector"
    cfg["database"] = str(tmp_path / "manager.sqlite")
    client, host = _listener(tmp_path, rig.store, cfg)
    monkeypatch.setattr(internal_api, "peer_certificate", lambda _transport: _cert_cn("kvmhub-projector"))
    async with client:
        response = await client.put(
            f"/internal/v2/projections/{ASSET}/1", json=_body(),
            headers={"Host": host, "X-Trace-ID": "trace-projection-1"})
        assert response.status == 200
        payload = await response.json()
        assert payload["ok"] is True
        assert payload["asset_id"] == ASSET
        assert SECRET_PASSWORD not in json.dumps(payload)
    state = rig.store.projection_state(ASSET)
    assert state["current_revision"] == 1
    assert state["status"] == "ready"
    assert SECRET_PASSWORD not in repr(list(rig.store.db.execute("SELECT * FROM audit")))


async def test_worker_role_is_refused_on_the_projection_route(tmp_path, rig, monkeypatch):
    identity = generate(tmp_path / "identity")
    cfg = json.loads((identity / "manager.json").read_text())
    cfg["projector_cert_cn"] = "kvmhub-projector"
    monkeypatch.setattr(internal_api, "peer_certificate", lambda _transport: _cert_cn("w1-worker"))
    client, host = _listener(tmp_path, rig.store, cfg)
    async with client:
        response = await client.put(
            f"/internal/v2/projections/{ASSET}/1", json=_body(), headers={"Host": host})
        assert response.status == 403
        assert (await response.json())["error"] == "projector_certificate_mismatch"




def _http_stub(rig):
    async def put(url, body, headers, tls):
        rig.store.put_connection_snapshot(
            body["snapshot"]["asset_id"] if "asset_id" in body["snapshot"] else ASSET, 1,
            body["snapshot"], digest=body["digest"], domain_id=body["domain_id"],
            generation=body["generation"], policy_fingerprint=body["policy_fingerprint"])
        rig.store.ack_projection(ASSET, 1, digest=body["digest"])
        return {"ok": True, "asset_id": ASSET, "revision": 1, "digest": body["digest"]}
    return put


async def test_projector_ack_matches_store_and_replay_is_idempotent(rig):
    put = _http_stub(rig)
    kwargs = dict(now=STAMP + 1, http_put=put, secret_provider=_secret_provider,
                  endpoint="https://internal.invalid", headers={}, tls=False)
    first = await run_projector_once(rig.factory, None, **kwargs)
    assert first["delivered"] == 1
    assert first["acknowledged"] == 1
    assert SECRET_PASSWORD not in json.dumps(first)
    with rig.factory() as db:
        row = db.scalar(select(PlaneProjection).where(PlaneProjection.asset_id == ASSET))
        assert row.applied_revision == 1
        assert row.applied_digest == DIGEST
    second = await run_projector_once(rig.factory, None, **kwargs)
    assert second["claimed"] == 0
    with rig.factory() as db:
        row = db.scalar(select(PlaneProjection).where(PlaneProjection.asset_id == ASSET))
        assert row.applied_revision == 1
        assert row.ack_at > 0


async def test_projector_does_not_put_the_secret_on_the_wire(rig):
    captured = {}

    async def put(url, body, headers, tls):
        captured.update(body)
        return await _http_stub(rig)(url, body, headers, tls)

    await run_projector_once(
        rig.factory, None, now=STAMP + 1, http_put=put,
        secret_provider=_secret_provider, endpoint="https://internal.invalid",
        headers={}, tls=False)
    assert "secret" not in captured
    assert SECRET_PASSWORD not in json.dumps(captured)


def test_only_client_rejections_are_permanent_projection_failures():
    assert _permanent_failure(RuntimeError("projection_http_403")) is True
    assert _permanent_failure(RuntimeError("projection_http_409")) is True
    assert _permanent_failure(RuntimeError("projection_http_500")) is False
    assert _permanent_failure(RuntimeError("projection_http_408")) is False
    assert _permanent_failure(RuntimeError("projection_http_429")) is False
    assert _permanent_failure(asyncio.TimeoutError()) is False


async def test_crash_before_ack_replays_the_same_event(rig):
    calls = [0]
    good_put = _http_stub(rig)

    async def flaky_put(url, body, headers, tls):
        calls[0] += 1
        if calls[0] == 1:
            raise RuntimeError("injected crash before ACK")
        return await good_put(url, body, headers, tls)

    first = await run_projector_once(
        rig.factory, None, now=STAMP + 1, http_put=flaky_put,
        secret_provider=_secret_provider, endpoint="https://internal.invalid",
        headers={}, tls=False)
    assert first["delivered"] == 0
    assert first["failed"] == 1
    with rig.factory() as db:
        row = db.scalar(select(PlaneProjection).where(PlaneProjection.asset_id == ASSET))
        assert row.applied_revision == 0

    second = await run_projector_once(
        rig.factory, None, now=STAMP + 40, http_put=flaky_put,
        secret_provider=_secret_provider, endpoint="https://internal.invalid",
        headers={}, tls=False)
    assert second["acknowledged"] == 1
    assert calls[0] == 2
    with rig.factory() as db:
        row = db.scalar(select(PlaneProjection).where(PlaneProjection.asset_id == ASSET))
        assert row.applied_revision == 1
        assert row.applied_digest == DIGEST


def test_projector_builds_per_asset_url_from_base_endpoint(rig):
    from kvmhub.projector import run_projector_once
    from kvmhub.platform.connection_config import ack_projection

    second = "asset-projector-2"
    with transaction(rig.factory) as db:
        cid = db.execute(select(Credential.id).limit(1)).scalar_one()
        capid = db.execute(select(Capability.id).limit(1)).scalar_one()
        db.add(Asset(id=second, tenant_id=None, name="node2", address="192.0.2.21",
                     credential_id=cid, capability_id=capid, created=STAMP, updated=STAMP))
        db.add_all([
            AssetConnection(id=str(uuid.uuid4()), asset_id=second, revision=1,
                            endpoint_json='[{"host":"192.0.2.21","port":5900}]',
                            adapter="rfb-vnc", identity_policy="{}",
                            source_versions_json="{}", secret_ref=cid,
                            secret_source="vnc_hidden", secret_revision=1,
                            schema="v2", digest="b" * 64, created=STAMP),
            PlaneProjection(id=str(uuid.uuid4()), asset_id=second, domain_id=DOMAIN,
                            desired_revision=1, desired_digest="b" * 64,
                            generation=GEN, policy_fingerprint=POLICY,
                            status="pending", error="", ack_at=0.0),
            PlaneOutbox(event_id=str(uuid.uuid4()), asset_id=second, revision=1,
                        event_type="test_change", created=STAMP, next_attempt=STAMP),
        ])
        db.flush()

    put_urls = []

    async def capture_put(url, body, headers, tls):
        put_urls.append(url)
        return {"ok": True}

    result = asyncio.run(run_projector_once(
        rig.factory, None, http_put=capture_put,
        endpoint="https://internal.invalid", headers={}, tls=False))

    assert result["claimed"] == 2
    assert set(put_urls) == {
        f"https://internal.invalid/internal/v2/projections/{ASSET}/1",
        f"https://internal.invalid/internal/v2/projections/{second}/1",
    }


def test_acked_outbox_row_does_not_starve_pending_assets(rig):
    from kvmhub.platform.connection_config import ack_projection

    second = "asset-projector-2"
    with transaction(rig.factory) as db:
        cid = db.execute(select(Credential.id).limit(1)).scalar_one()
        capid = db.execute(select(Capability.id).limit(1)).scalar_one()
        db.add(Asset(id=second, tenant_id=None, name="node2", address="192.0.2.21",
                     credential_id=cid, capability_id=capid, created=STAMP, updated=STAMP))
        db.add_all([
            AssetConnection(id=str(uuid.uuid4()), asset_id=second, revision=1,
                            endpoint_json='[]', adapter="rfb-vnc", identity_policy="{}",
                            source_versions_json="{}", secret_ref=cid,
                            secret_source="vnc_hidden", secret_revision=1,
                            schema="v2", digest="b" * 64, created=STAMP),
            PlaneProjection(id=str(uuid.uuid4()), asset_id=second, domain_id=DOMAIN,
                            desired_revision=1, desired_digest="b" * 64,
                            generation=GEN, policy_fingerprint=POLICY,
                            status="pending", error="", ack_at=0.0),
            PlaneOutbox(event_id=str(uuid.uuid4()), asset_id=second, revision=1,
                        event_type="test_change", created=STAMP + 1, next_attempt=STAMP),
        ])
        db.flush()
        first_proj = db.scalar(select(PlaneProjection).where(
            PlaneProjection.asset_id == ASSET))
        first_proj.applied_revision = 1
        first_proj.applied_digest = DIGEST
        first_proj.status = "ready"

    put_urls = []

    async def capture_put(url, body, headers, tls):
        put_urls.append(url)
        return {"ok": True}

    async def two_passes():
        r1 = await run_projector_once(rig.factory, None, http_put=capture_put,
                                      endpoint="https://internal.invalid",
                                      headers={}, tls=False, limit=1)
        r2 = await run_projector_once(rig.factory, None, http_put=capture_put,
                                      endpoint="https://internal.invalid",
                                      headers={}, tls=False, limit=1)
        return r1, r2

    r1, r2 = asyncio.run(two_passes())
    assert any(url.endswith(f"/projections/{second}/1") for url in put_urls), (
        "an already-ACKed head row starved the pending asset")
    with rig.factory() as db:
        acked_event = db.scalar(select(PlaneOutbox).where(PlaneOutbox.asset_id == ASSET))
        assert acked_event.attempts >= 8, "ACKed event must be retired from the queue"


def test_projector_url_keeps_full_canary_style_endpoint():
    from kvmhub.projector import projection_url

    full = f"https://internal.invalid/internal/v2/projections/{ASSET}/1"
    assert projection_url(full, ASSET, 1) == full


def test_projector_url_strips_trailing_slash_on_base():
    from kvmhub.projector import projection_url

    assert projection_url("https://internal.invalid/", ASSET, 3) == \
        f"https://internal.invalid/internal/v2/projections/{ASSET}/3"
