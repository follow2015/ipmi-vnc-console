"""G1 managed operation chain: binding, one-shot consumption and deadlines."""
import asyncio
import json
import socket
import time
from pathlib import Path

import pytest
from aiohttp.test_utils import TestClient, TestServer
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from kvmhub import admission_runtime, internal_api
from kvmhub.admission_runtime import (AuthorityClient, authority_request, binding_digest,
                                      binding_payload)
from kvmhub.common import BMC_BASE_URL, Problem, issue, verify
from kvmhub.operation_permit import (OPERATION_AUDIENCE, issue_operation_permit,
                                     verify_operation_permit)
from kvmhub.store import Store
from tools.bootstrap import generate

KEY = Ed25519PrivateKey.generate()
NOW = [time.time()]
DIGEST = "e" * 64
DOMAIN = "admission-canary"
GEN = "gen-g1"
TENANT = "tenant-g1"
USER = "local-admin"
ASSET = "mock-1"
WORKER, INSTANCE = "w1", "i1"
BINDING = binding_digest(binding_payload(
    sid="x" * 32, asset_id=ASSET, tenant_id=TENANT, user_id=USER,
    domain_id=DOMAIN, worker_id=WORKER, instance_id=INSTANCE,
    connection_revision=3, admission_revision=2, digest=DIGEST, generation=GEN))


def _fields(sid):
    return dict(sid=sid, asset_id=ASSET, tenant_id=TENANT, user_id=USER,
                domain_id=DOMAIN, worker_id=WORKER, instance_id=INSTANCE,
                connection_revision=3, admission_revision=2,
                digest=DIGEST, generation=GEN)


def _permit(operation, sid, *, lease_not_after=None, now=None):
    return issue_operation_permit(
        KEY, operation=operation, **_fields(sid),
        lease_not_after=NOW[0] + 30 if lease_not_after is None else lease_not_after,
        now=NOW[0] if now is None else now)


def _expected(sid):
    return {"aid": ASSET, "usr": USER, "dom": DOMAIN, "wid": WORKER, "iid": INSTANCE,
            "cr": 3, "ar": 2, "dgs": DIGEST, "gen": GEN, "tid": TENANT, "sid": sid}


@pytest.fixture(autouse=True)
def _fresh_clock():
    NOW[0] = time.time()


@pytest.fixture
def store(tmp_path):
    opened = Store(tmp_path / "g1.sqlite", b"k" * 32, clock=lambda: NOW[0])
    opened.seed_mock(BMC_BASE_URL, "aa" * 32, "fixture-user", "fixture-password")
    yield opened
    opened.close()


def _allocate(opened, sid, *, permit=None, binding=BINDING, lease_not_after=None):
    return opened.allocate(
        ASSET, USER, WORKER, INSTANCE, "g1-trace", sid=sid,
        permit=permit or _permit("allocate", sid, lease_not_after=lease_not_after),
        public_key=KEY.public_key(), binding=binding, expected=_expected(sid))


def _ticket(row, sid):
    return issue(KEY, row, NOW[0], tenant_id=TENANT, binding=BINDING)


def _ticket_claims(row, sid):
    claims = verify(KEY.public_key(), _ticket(row, sid), WORKER, INSTANCE)
    assert claims["sid"] == sid and claims["bdg"] == BINDING
    return claims


def test_allocate_consumes_one_permit_and_replay_is_refused(store):
    sid = "a" * 32
    permit = _permit("allocate", sid)
    row = _allocate(store, sid, permit=permit)
    assert row["binding_digest"] == BINDING
    assert row["snapshot_digest"] == DIGEST
    with store.tx():
        with pytest.raises(Problem) as exc:
            store.consume_operation(permit, public_key=KEY.public_key(),
                                    operation="allocate", sid=sid, binding=BINDING,
                                    expected=_expected(sid))
    assert exc.value.code == "operation_permit_replayed"
    assert store.get(sid)["status"] == "pending"


def test_exchange_needs_matching_assembly_ticket_and_session_binding(store):
    sid = "b" * 32
    row = _allocate(store, sid)
    claims = _ticket_claims(row, sid)
    with pytest.raises(Problem) as exc:
        store.exchange(claims, "g1-trace", permit=_permit("exchange", sid),
                       public_key=KEY.public_key(), binding=BINDING,
                       assembly_binding="f" * 64)
    assert exc.value.code == "connection_revision_mismatch"
    assert store.get(sid)["consumed"] == 0

    result = store.exchange(claims, "g1-trace", permit=_permit("exchange", sid),
                            public_key=KEY.public_key(), binding=BINDING,
                            assembly_binding=BINDING)
    assert result["password"] == "fixture-password"
    assert result["lease_seconds"] <= 30
    with pytest.raises(Problem) as exc:
        store.exchange(claims, "g1-trace", permit=_permit("exchange", sid),
                       public_key=KEY.public_key(), binding=BINDING,
                       assembly_binding=BINDING)
    assert exc.value.code == "ticket_consumed_or_expired"


def test_renew_cannot_extend_past_the_authority_ceiling(store):
    sid = "c" * 32
    store.lease_seconds = 60
    row = _allocate(store, sid, lease_not_after=NOW[0] + 300)
    claims = _ticket_claims(row, sid)
    store.exchange(claims, "g1-trace", permit=_permit("exchange", sid),
                   public_key=KEY.public_key(), binding=BINDING, assembly_binding=BINDING)
    fresh = _permit("activate", sid, lease_not_after=NOW[0] + 300)
    result = store.renew(sid, WORKER, INSTANCE, activate=True, permit=fresh,
                         public_key=KEY.public_key(), binding=BINDING)
    assert 0 < result["lease_seconds"] <= 60
    NOW[0] += 32
    fresh_renew = _permit("renew", sid, lease_not_after=NOW[0] + 8, now=NOW[0])
    renewed = store.renew(sid, WORKER, INSTANCE, permit=fresh_renew,
                          public_key=KEY.public_key(), binding=BINDING)
    assert 0 < renewed["lease_seconds"] <= 8
    assert store.get(sid)["lease_until"] <= NOW[0] + 8


def test_allocate_absolute_ceiling_lets_the_lease_roll(store):
    sid = "e" * 32
    store.lease_seconds = 60
    ceiling = NOW[0] + 4 * 3600
    row = _allocate(store, sid, lease_not_after=ceiling)
    assert row["hard_until"] == ceiling
    assert row["lease_not_after"] == ceiling

    claims = _ticket_claims(row, sid)
    store.exchange(claims, "g1-trace", permit=_permit("exchange", sid),
                   public_key=KEY.public_key(), binding=BINDING, assembly_binding=BINDING)
    store.renew(sid, WORKER, INSTANCE, activate=True,
                permit=_permit("activate", sid),
                public_key=KEY.public_key(), binding=BINDING)
    first_until = store.get(sid)["lease_until"]

    NOW[0] += 22
    renewed = store.renew(
        sid, WORKER, INSTANCE,
        permit=_permit("renew", sid, lease_not_after=NOW[0] + 30, now=NOW[0]),
        public_key=KEY.public_key(), binding=BINDING)
    assert store.get(sid)["lease_until"] > first_until
    assert 0 < renewed["lease_seconds"] <= 30


def test_every_recover_attempt_gets_a_new_permit(store):
    sid = "d" * 32
    row = _allocate(store, sid)
    claims = _ticket_claims(row, sid)
    store.exchange(claims, "g1-trace", permit=_permit("exchange", sid),
                   public_key=KEY.public_key(), binding=BINDING, assembly_binding=BINDING)
    store.renew(sid, WORKER, INSTANCE, activate=True, permit=_permit("activate", sid),
                public_key=KEY.public_key(), binding=BINDING)
    first = _permit("recover", sid)
    decision = store.start_operation(sid, WORKER, INSTANCE, "recover", permit=first,
                                     public_key=KEY.public_key(), binding=BINDING)
    assert decision["start_deadline"] > NOW[0]
    with pytest.raises(Problem) as exc:
        store.start_operation(sid, WORKER, INSTANCE, "recover", permit=first,
                              public_key=KEY.public_key(), binding=BINDING)
    assert exc.value.code == "operation_permit_replayed"
    second = store.start_operation(sid, WORKER, INSTANCE, "recover",
                                   permit=_permit("recover", sid),
                                   public_key=KEY.public_key(), binding=BINDING)
    assert second["start_deadline"] > NOW[0]


def test_browser_ticket_never_carries_an_operation_permit():
    row = {"id": "e" * 32, "jti": "j" * 32, "user_id": USER, "asset_id": ASSET,
           "worker_id": WORKER, "instance_id": INSTANCE, "hard_until": NOW[0] + 60}
    token = _ticket(row, row["id"])
    claims = verify(KEY.public_key(), token, WORKER, INSTANCE)
    assert claims["aud"] != OPERATION_AUDIENCE
    assert not any(key in claims for key in ("jti2", "permit", "cr", "ar", "lna"))
    assert claims["bdg"] == BINDING


async def test_authority_client_maps_only_trusted_codes_and_never_retries():
    calls = []

    async def answer(body, host):
        calls.append((body, host))
        return {"error": "unexpected_authority_failure"}

    client = AuthorityClient("https://authority.invalid", ca="unused", cert="unused",
                             key="unused", public_key=KEY.public_key(), post=answer)
    request = authority_request(
        operation="exchange", sid="f" * 32, asset_id=ASSET, user_id=USER,
        tenant_id=TENANT, domain_id=DOMAIN, worker_id=WORKER, instance_id=INSTANCE,
        connection_revision=3, admission_revision=2, digest=DIGEST, generation=GEN,
        session_started_at=NOW[0], hard_until=NOW[0] + 60)
    with pytest.raises(Problem) as exc:
        await client.authorize(host="authority.invalid", **request)
    assert exc.value.code == "admission_service_unavailable"
    assert len(calls) == 1

    async def trusted(body, host):
        raise Problem("device_not_admitted", 403)

    client._post = trusted
    with pytest.raises(Problem) as exc:
        await client.authorize(host="authority.invalid", **request)
    assert exc.value.code == "device_not_admitted"


async def test_authority_client_binds_compact_permit_claims():
    sid = "g" * 32
    request = authority_request(
        operation="exchange", sid=sid, asset_id=ASSET, user_id=USER,
        tenant_id=TENANT, domain_id=DOMAIN, worker_id=WORKER,
        instance_id=INSTANCE, connection_revision=3, admission_revision=2,
        digest=DIGEST, generation=GEN, session_started_at=NOW[0],
        hard_until=NOW[0] + 30)

    async def answer(body, _host):
        return {"permit": issue_operation_permit(
            KEY, operation=body["operation"], sid=body["sid"],
            asset_id=body["asset_id"], tenant_id=body["tenant_id"],
            user_id=body["user_id"], domain_id=body["domain_id"],
            worker_id=body["worker_id"], instance_id=body["instance_id"],
            connection_revision=body["connection_revision"],
            admission_revision=body["admission_revision"],
            digest=body["digest"], generation=body["generation"],
            lease_not_after=body["hard_until"], now=NOW[0])}

    client = AuthorityClient("https://authority.invalid", ca="unused", cert="unused",
                             key="unused", public_key=KEY.public_key(), post=answer)
    result = await client.authorize(host="authority.invalid", **request)
    assert result["claims"]["aid"] == ASSET
    assert result["claims"]["usr"] == USER
    assert result["claims"]["dgs"] == DIGEST


class _Authority:
    def __init__(self):
        self.calls = []

    async def authorize(self, *, operation, host, **fields):
        self.calls.append((operation, fields))
        token = issue_operation_permit(
            KEY, operation=operation, sid=fields["sid"], asset_id=fields["asset_id"],
            tenant_id=fields["tenant_id"], user_id=fields["user_id"],
            domain_id=fields["domain_id"], worker_id=fields["worker_id"],
            instance_id=fields["instance_id"],
            connection_revision=fields["connection_revision"],
            admission_revision=fields["admission_revision"], digest=fields["digest"],
            generation=fields["generation"],
            lease_not_after=NOW[0] + 30, now=NOW[0])
        return {"permit": token,
                "claims": verify_operation_permit(KEY.public_key(), token, now=NOW[0])}


async def test_internal_api_exchange_asks_authority_and_keeps_binding(tmp_path, store, monkeypatch):
    identity = generate(tmp_path / "identity")
    cfg = json.loads((identity / "manager.json").read_text())
    cfg["instance_id"] = INSTANCE
    cfg["worker_cert_cn"] = f"{WORKER}-{INSTANCE}"
    sid = "f" * 32
    row = _allocate(store, sid)
    ticket_key = load_pem_private_key(Path(cfg["signing_key"]).read_bytes(), password=None)
    token = issue(ticket_key, row, NOW[0], tenant_id=TENANT, binding=BINDING)
    proof = (identity / "worker-proof").read_text().strip()
    authority = _Authority()

    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    host = f"127.0.0.1:{port}"
    app = internal_api.create_app(
        cfg, store, expected_host=host, authority=authority,
        managed_domains=(DOMAIN,), authority_host="authority.internal",
        permit_public_key=KEY.public_key())
    monkeypatch.setattr(internal_api, "peer_certificate",
                        lambda _transport: {"subject": (((("commonName", cfg["worker_cert_cn"]),),))})
    headers = {"Host": host, "X-Worker-Proof": proof, "X-Trace-ID": "a" * 32}
    async with TestClient(TestServer(app, port=port)) as client:
        response = await client.post(
            f"/internal/v1/sessions/{sid}/exchange",
            json={"ticket": token, "binding": "f" * 64}, headers=headers)
        assert response.status == 409
        assert (await response.json())["error"] == "connection_revision_mismatch"

        response = await client.post(
            f"/internal/v1/sessions/{sid}/exchange",
            json={"ticket": token, "binding": BINDING}, headers=headers)
        assert response.status == 200, await response.text()
        result = await response.json()
        assert result["password"] == "fixture-password"
        assert authority.calls[0][0] == "exchange"
    assert store.get(sid)["consumed"] == 1


async def test_internal_api_exchange_without_authority_fails_closed(tmp_path, store, monkeypatch):
    identity = generate(tmp_path / "identity")
    cfg = json.loads((identity / "manager.json").read_text())
    cfg["instance_id"] = INSTANCE
    cfg["worker_cert_cn"] = f"{WORKER}-{INSTANCE}"
    sid = "d" * 32
    row = _allocate(store, sid)
    ticket_key = load_pem_private_key(Path(cfg["signing_key"]).read_bytes(), password=None)
    token = issue(ticket_key, row, NOW[0], tenant_id=TENANT, binding=BINDING)
    proof = (identity / "worker-proof").read_text().strip()

    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    host = f"127.0.0.1:{port}"
    app = internal_api.create_app(
        cfg, store, expected_host=host, authority=None,
        managed_domains=(DOMAIN,), authority_host="authority.internal",
        permit_public_key=KEY.public_key())
    monkeypatch.setattr(internal_api, "peer_certificate",
                        lambda _transport: {"subject": (((("commonName", cfg["worker_cert_cn"]),),))})
    headers = {"Host": host, "X-Worker-Proof": proof, "X-Trace-ID": "a" * 32}
    async with TestClient(TestServer(app, port=port)) as client:
        response = await client.post(
            f"/internal/v1/sessions/{sid}/exchange",
            json={"ticket": token, "binding": BINDING}, headers=headers)
        assert response.status == 503, await response.text()
        assert (await response.json())["error"] == "admission_service_unavailable"
    assert store.get(sid)["consumed"] == 0


async def test_authority_client_creates_one_session_under_concurrency(monkeypatch):
    sessions = []

    class FakeResponse:
        status = 200

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return False

        async def json(self, content_type=None):
            return {"permit": "unused"}

    class FakeSession:
        def __init__(self, connector, timeout):
            sessions.append(self)

        def post(self, *args, **kwargs):
            return FakeResponse()

        async def close(self):
            return None

    monkeypatch.setattr(admission_runtime, "client_tls", lambda *_a: object())
    monkeypatch.setattr(admission_runtime.aiohttp, "TCPConnector", lambda ssl: object())
    monkeypatch.setattr(admission_runtime.aiohttp, "ClientSession", FakeSession)
    client = AuthorityClient("https://authority.invalid", ca="unused", cert="unused",
                             key="unused", public_key=KEY.public_key())
    await asyncio.gather(*(client._post({"trace_id": "x"}, "authority.invalid")
                           for _ in range(4)))
    assert len(sessions) == 1
    await client.close()
