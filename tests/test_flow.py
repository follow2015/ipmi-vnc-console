"""End-to-end TLS/mTLS Manager -> Worker -> synthetic BMC verification."""
import asyncio
import json
import os
import signal
import socket
import subprocess
import sys
import time
from contextlib import asynccontextmanager
from pathlib import Path

import aiohttp
import httpx
import pytest
from aiohttp.abc import AbstractResolver

from kvmhub.common import (BMC_PORT, INTERNAL_ORIGIN, INTERNAL_PORT, UI_ORIGIN,
                           WORKER_PORT, client_tls)

ROOT = Path(__file__).resolve().parents[1]


class LoopbackResolver(AbstractResolver):
    async def resolve(self, host, port=0, family=socket.AF_INET):
        return [{"hostname": host, "host": "127.0.0.1", "port": port,
                 "family": socket.AF_INET, "proto": 0, "flags": 0}]

    async def close(self):
        pass


@pytest.fixture(scope="module")
def services(tmp_path_factory):
    folder = tmp_path_factory.mktemp("flow") / "local"
    subprocess.run([sys.executable, str(ROOT/"tools/bootstrap.py"), "--directory", str(folder)],
                   cwd=ROOT, check=True, capture_output=True)
    log = (folder/"services.log").open("w+")
    popen_kwargs = {"start_new_session": True} if os.name == "posix" else {}
    proc = subprocess.Popen([sys.executable, "-m", "kvmhub.run", "--directory", str(folder)],
                            cwd=ROOT, stdout=log, stderr=log, **popen_kwargs)
    try:
        deadline = time.monotonic()+15
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                log.seek(0)
                pytest.fail(log.read())
            try:
                with httpx.Client(verify=client_tls(str(folder/"ca.pem")), trust_env=False, timeout=0.3) as client:
                    if client.get(f"{UI_ORIGIN}/").status_code == 200:
                        for port in (INTERNAL_PORT, WORKER_PORT, BMC_PORT):
                            with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                                pass
                        break
            except (httpx.HTTPError, OSError):
                pass
            time.sleep(0.1)
        else:
            log.seek(0)
            pytest.fail("services startup timeout\n"+log.read())
        yield folder, proc
    finally:
        if proc.poll() is None:
            if os.name == "nt":
                subprocess.run(["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                               capture_output=True, check=False)
            else:
                os.killpg(proc.pid, signal.SIGINT)
            try:
                proc.wait(timeout=12)
            except subprocess.TimeoutExpired:
                if os.name == "nt":
                    proc.kill()
                else:
                    os.killpg(proc.pid, signal.SIGKILL)
                proc.wait()
        log.close()


@asynccontextmanager
async def manager_client(folder):
    client = httpx.AsyncClient(base_url=UI_ORIGIN, verify=client_tls(str(folder/"ca.pem")), trust_env=False)
    response = await client.post("/api/login", headers={"Origin": UI_ORIGIN},
                                 json={"token": (folder/"login-token").read_text().strip()})
    assert response.status_code == 200
    assert "Domain=" not in response.headers["set-cookie"]
    me = (await client.get("/api/me")).json()
    client.headers.update({"Origin": UI_ORIGIN, "X-CSRF-Token": me["csrf"]})
    try:
        yield client
    finally:
        await client.aclose()


async def status_until(client, sid, status="closed", cleanup="confirmed"):
    async with asyncio.timeout(10):
        while True:
            body = (await client.get(f"/api/sessions/{sid}")).json()
            if body["status"] == status and body["cleanup"] == cleanup:
                return body
            await asyncio.sleep(0.1)


async def test_tls_mtls_browser_console_replay_and_revoke(services):
    folder, _ = services
    ctx = client_tls(str(folder/"ca.pem"))
    async with manager_client(folder) as manager:
        async with httpx.AsyncClient(verify=ctx, trust_env=False) as anonymous:
            assert (await anonymous.get(f"{UI_ORIGIN}/api/me")).status_code == 401
        bad = await manager.post("/api/assets/mock-1/sessions", headers={"Origin": "https://evil.example"})
        assert bad.status_code == 403
        assert (await manager.post("/api/assets/unknown/sessions")).status_code == 403
        a = (await manager.post("/api/assets/mock-1/sessions")).json()
        b = (await manager.post("/api/assets/mock-2/sessions")).json()
        assert (await manager.post("/api/assets/mock-1/sessions")).status_code == 409

        connector = aiohttp.TCPConnector(ssl=ctx, resolver=LoopbackResolver())
        async with aiohttp.ClientSession(connector=connector, trust_env=False) as browser:
            async with browser.post(b["accept_url"], data={"ticket": a["ticket"]},
                                    headers={"Origin": UI_ORIGIN}, allow_redirects=False) as r:
                assert r.status == 403
            for item in (a, b):
                async with browser.post(item["accept_url"], data={"ticket": item["ticket"]},
                                        headers={"Origin": UI_ORIGIN}, allow_redirects=False) as r:
                    assert r.status == 200, await r.text()
                    assert '/_platform/continue.js' in await r.text()
                    assert "UPSTREAM_SECRET" not in str(r.headers)
                    cookie = r.headers["Set-Cookie"]
                    assert "__Host-kvm_sid=" in cookie and "HttpOnly" in cookie and "Secure" in cookie
                    assert "Domain=" not in cookie
            async with browser.post(a["accept_url"], data={"ticket": a["ticket"]},
                                    headers={"Origin": UI_ORIGIN}, allow_redirects=False) as r:
                assert r.status == 409
            state = (await manager.get(f'/api/sessions/{a["id"]}')).json()
            assert state["status"] == "active" and state["cleanup"] == "pending"
            assert (await manager.post("/api/assets/mock-1/sessions")).status_code == 409

            origin = a["accept_url"].split("/_platform")[0]
            async with browser.get(origin+"/") as r:
                assert r.status == 200
                page = await r.text()
                assert "192.0.2.11" not in page and str(BMC_PORT) not in page
            async with browser.get(origin+"/redfish/v1/Systems") as r:
                assert r.status == 403
            with pytest.raises(aiohttp.WSServerHandshakeError) as error:
                await browser.ws_connect(origin+"/console", protocols=("binary",), origin="https://evil.example")
            assert error.value.status == 403
            with pytest.raises(aiohttp.WSServerHandshakeError) as error:
                await browser.ws_connect(origin+"/console", protocols=("wrong",), origin=origin)
            assert error.value.status == 400
            ws = await browser.ws_connect(origin+"/console", protocols=("binary",), origin=origin)
            assert ws.protocol == "binary"
            message = await ws.receive(timeout=3)
            assert message.type == aiohttp.WSMsgType.BINARY and b"SYNTHETIC" in message.data
            await ws.send_bytes(b"A")
            for _ in range(5):
                message = await ws.receive(timeout=3)
                if b"INPUT ACK" in message.data:
                    break
            else:
                pytest.fail("binary keyboard input was not acknowledged")
            assert (await manager.post(f'/api/sessions/{a["id"]}/close')).status_code == 200
            async with asyncio.timeout(6):
                while not ws.closed:
                    await ws.receive()
            await status_until(manager, a["id"])
            origin_b = b["accept_url"].split("/_platform")[0]
            async with browser.get(origin_b+"/") as r:
                assert r.status == 200
            assert (await manager.post(f'/api/sessions/{b["id"]}/close')).status_code == 200
            await status_until(manager, b["id"])
        audit = (await manager.get("/api/audit")).text
        assert "credential_access_succeeded" in audit
        assert a["ticket"] not in audit and "synthetic-user" not in audit


async def test_internal_socket_requires_client_certificate(services):
    folder, _ = services
    async with httpx.AsyncClient(verify=client_tls(str(folder/"ca.pem")), trust_env=False) as client:
        with pytest.raises(httpx.HTTPError):
            await client.post(f"{INTERNAL_ORIGIN}/internal/v1/sessions/nope/exchange", json={})


async def test_mtls_identity_also_requires_instance_proof(services):
    folder, _ = services
    cfg = json.loads((folder/"worker.json").read_text())
    ctx = client_tls(cfg["ca"], cfg["client_cert"], cfg["client_key"])
    async with httpx.AsyncClient(verify=ctx, trust_env=False) as client:
        r = await client.post(f"{INTERNAL_ORIGIN}/internal/v1/sessions/nope/exchange", json={})
        assert r.status_code == 403


async def test_trace_id_spans_ui_ticket_exchange_and_audit(services):
    folder, _ = services
    ctx = client_tls(str(folder/"ca.pem"))
    async with manager_client(folder) as manager:
        response = await manager.post("/api/assets/mock-2/sessions")
        assert response.status_code == 200, response.text
        trace = response.headers.get("X-Trace-ID")
        assert trace and len(trace) == 32
        a = response.json()
        connector = aiohttp.TCPConnector(ssl=ctx, resolver=LoopbackResolver())
        async with aiohttp.ClientSession(connector=connector, trust_env=False) as browser:
            async with browser.post(a["accept_url"], data={"ticket": a["ticket"]},
                                    headers={"Origin": UI_ORIGIN}, allow_redirects=False) as r:
                assert r.status == 200, await r.text()
                assert r.headers.get("X-Trace-ID") == trace
        audit = (await manager.get("/api/audit")).json()
        linked = [e for e in audit if e["session_id"] == a["id"]]
        consumed = [e for e in linked if e["action"] == "ticket_consumed"]
        assert consumed and consumed[0]["trace_id"] == trace
        active = [e for e in linked if e["action"] == "session_active"]
        assert active and active[0]["trace_id"] == trace
        assert (await manager.post(f'/api/sessions/{a["id"]}/close')).status_code == 200
        await status_until(manager, a["id"])
