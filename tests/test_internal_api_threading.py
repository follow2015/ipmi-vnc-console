"""Blocking Store calls must not run on the event loop thread."""
import asyncio
import socket
import threading

import pytest
from aiohttp.test_utils import TestClient, TestServer

from kvmhub import internal_api


@pytest.fixture
def cfg(tmp_path):
    from cryptography.hazmat.primitives.asymmetric import ed25519

    key = ed25519.Ed25519PrivateKey.generate()
    private = tmp_path / "signing.pem"
    from cryptography.hazmat.primitives import serialization
    private.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    return {"signing_key": str(private), "worker_id": "w1", "instance_id": "i1"}


class ThreadRecordingStore:
    def __init__(self):
        self.threads = []

    def renew(self, sid, worker, instance, activate, trace=None, **_kwargs):
        self.threads.append(threading.current_thread().name)
        return {"lease_seconds": 30}


async def test_renew_runs_off_the_event_loop_thread(cfg, monkeypatch):
    store = ThreadRecordingStore()
    monkeypatch.setattr(internal_api, "check_worker_credentials", lambda *a, **k: None)
    monkeypatch.setattr(internal_api, "verify", lambda *a, **k: {"sid": "x"})
    app = internal_api.create_app(cfg, store, expected_host="localhost:1")
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    async with TestClient(TestServer(app, port=port)) as client:
        resp = await client.post("/internal/v1/sessions/x/renew", json={},
                                 headers={"Host": "localhost:1"})
        assert resp.status == 200, await resp.text()
    loop_thread = threading.current_thread().name
    assert store.threads
    assert all(name != loop_thread for name in store.threads)
