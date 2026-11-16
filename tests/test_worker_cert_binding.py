"""H2: the Manager accepts one worker identity, not merely any certificate we signed."""
import base64
import json
import socket
import sqlite3
from pathlib import Path

import pytest
from aiohttp.test_utils import TestClient, TestServer

from kvmhub.common import (certificate_common_name, expected_worker_cert_cn,
                           peer_certificate)
from kvmhub.internal_api import check_worker_credentials, create_app
from kvmhub.store import Store
from tools.bootstrap import generate


class FakeSSL:

    def __init__(self, cn=None, raw=None):
        self.cn = cn
        self.raw = raw

    def getpeercert(self):
        if self.raw is not None:
            return self.raw
        if not self.cn:
            return {}
        return {"subject": ((("commonName", self.cn),),)}


class FakeTransport:
    def __init__(self, ssl_object):
        self._ssl = ssl_object

    def get_extra_info(self, name, default=None):
        return self._ssl if name == "ssl_object" else default


@pytest.fixture
def manager(tmp_path):
    directory = generate(tmp_path / "identity")
    cfg = json.loads((directory / "manager.json").read_text())
    cfg["database"] = str(tmp_path / "h2.sqlite3")
    store = Store(cfg["database"], base64.b64decode(Path(cfg["encryption_key"]).read_bytes()))
    store.db.close()
    store.db = sqlite3.connect(cfg["database"], isolation_level=None, timeout=5,
                               check_same_thread=False)
    store.db.row_factory = sqlite3.Row
    proof = Path(json.loads((directory / "worker.json").read_text())["worker_proof"]).read_text().strip()
    yield cfg, store, proof
    store.close()




def test_a_connection_without_a_certificate_has_no_identity():
    assert peer_certificate(None) is None
    assert peer_certificate(FakeTransport(None)) is None


def test_an_empty_certificate_is_not_an_identity():
    assert peer_certificate(FakeTransport(FakeSSL(raw={}))) is None


def test_a_presented_certificate_yields_its_common_name():
    assert certificate_common_name(peer_certificate(FakeTransport(FakeSSL("w1-" + "a" * 32)))) == "w1-" + "a" * 32


def test_a_subject_without_a_common_name_has_none():
    assert certificate_common_name({"subject": ((("organizationName", "ops"),),)}) is None


def test_the_expected_name_is_declared_or_derived_from_the_instance():
    assert expected_worker_cert_cn({"worker_cert_cn": "lab-worker"}) == "lab-worker"
    assert expected_worker_cert_cn({"worker_id": "w1", "instance_id": "ab" * 16}) == "w1-" + "ab" * 16
    assert expected_worker_cert_cn({"worker_id": "w1", "instance_id": "ab" * 16,
                                    "worker_cert_cn": "  "}) == "w1-" + "ab" * 16




def test_the_right_worker_name_passes_both_halves(manager):
    cfg, _store, proof = manager
    check_worker_credentials({"x-worker-proof": proof},
                             FakeTransport(FakeSSL(cfg["worker_cert_cn"])), cfg)


def test_another_workers_certificate_is_refused_by_name(manager):
    cfg, _store, proof = manager
    with pytest.raises(Exception) as caught:
        check_worker_credentials({"x-worker-proof": proof},
                                 FakeTransport(FakeSSL("w1-" + "f" * 32)), cfg)
    assert getattr(caught.value, "code", None) == "worker_certificate_mismatch"


def test_a_missing_client_certificate_is_refused_not_tolerated(manager):
    cfg, _store, proof = manager
    for transport in (None, FakeTransport(None), FakeTransport(FakeSSL(raw={}))):
        with pytest.raises(Exception) as caught:
            check_worker_credentials({"x-worker-proof": proof}, transport, cfg)
        assert getattr(caught.value, "code", None) == "worker_certificate_missing"


def test_the_shared_proof_is_still_required_on_top_of_the_certificate(manager):
    cfg, _store, _proof = manager
    with pytest.raises(Exception) as caught:
        check_worker_credentials({"x-worker-proof": "not-the-proof"},
                                 FakeTransport(FakeSSL(cfg["worker_cert_cn"])), cfg)
    assert getattr(caught.value, "code", None) == "worker_authentication_failed"




def _listener(cfg, store):
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    app = create_app(cfg, store, expected_host=f"127.0.0.1:{port}")
    return TestClient(TestServer(app, port=port))


async def test_a_plain_request_never_reaches_the_store(manager):
    cfg, store, proof = manager
    async with _listener(cfg, store) as client:
        response = await client.post("/internal/v1/sessions/x/active", json={},
                                     headers={"X-Worker-Proof": proof})
        assert response.status == 403
        assert (await response.json())["error"] == "worker_certificate_missing"


async def test_an_unknown_endpoint_answers_json_not_html(manager):
    cfg, store, _proof = manager
    async with _listener(cfg, store) as client:
        response = await client.get("/internal/v1/nope")
        assert response.status == 404
        assert (await response.json())["error"] == "unknown_operation"
        assert response.headers["Cache-Control"] == "no-store"


async def test_a_foreign_host_header_is_refused(manager):
    cfg, store, _proof = manager
    async with _listener(cfg, store) as client:
        response = await client.post("/internal/v1/sessions/x/active", json={},
                                     headers={"Host": "evil.example"})
        assert response.status == 421
        assert (await response.json())["error"] == "invalid_host"
