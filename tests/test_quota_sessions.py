"""P2 second batch: tenant quotas and live-session governance."""
from __future__ import annotations

import asyncio
import json
import os
import time
import uuid
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
from sqlalchemy import select

from kvmhub.common import PASSTHROUGH_ADAPTER_ID
from kvmhub.platform import services, vendor_registry
from kvmhub.platform.api import create_app
from kvmhub.platform.bus import AssemblyBus
from kvmhub.platform.config import Settings
from kvmhub.platform.console import ConsolePlane
from kvmhub.platform.db import (bootstrap_platform_admin, init_schema, seed_roles,
                                transaction)
from kvmhub.platform.models import (DEFAULT_TENANT_ID, Capability, Tenant,
                                    VendorProfile, json_field)
from kvmhub.platform.redis_state import MemoryState, RedisState, quota_key
from kvmhub.store import TENANT_GRANT, Store
from kvmhub.worker import Gateway
from tools.bootstrap import generate

KEY = b"0123456789abcdef0123456789abcdef"
ADMIN_PASSWORD = "synthetic-password"
PLATFORM_PASSWORD = "synthetic-password"
BMC_PASSWORD = "synthetic-password"
ORIGIN = "http://testserver"
PROFILE_CODE = "smci-x10-ast2100-rfb003008"
MANUFACTURER = "Supermicro (Inspur OEM)"
TARGET = "https://192.0.2.11"
FINGERPRINT = "ab1eed64" * 8


def cfg_for(db_url: str) -> Settings:
    return Settings(env="test", db_url=db_url, redis_url="", credential_key=KEY,
                    session_ttl=3600, lease_seconds=30, bootstrap_admin=None,
                    bootstrap_password=None, strict_prod=False)


@pytest.fixture
def rig(tmp_path):
    cfg = cfg_for(f"sqlite:///{tmp_path}/control.db")
    state = MemoryState()
    bus = AssemblyBus(state)
    private = Ed25519PrivateKey.generate()
    data_db = tmp_path / "data-plane.db"

    def connect() -> Store:
        return Store(str(data_db), KEY, passthrough_targets=(TARGET,))

    plane = ConsolePlane(store_factory=connect, private_key=private, bus=bus,
                         accept_template="https://{worker_id}-{sid}.kvm.localhost:9443/_platform/accept")
    app = create_app(cfg, state=state, plane=plane)
    platform = app.state.platform
    store = connect()
    with transaction(platform.factory) as db:
        init_schema(platform.engine)
        seed_roles(db)
        vendor_registry.seed_builtin_profiles(db)
        admin = services.create_user(db, "admin", ADMIN_PASSWORD, "admin", actor="test")
        globex = services.create_tenant(db, code="globex", name="Globex", actor="test")
        services.create_user(db, "globex-admin", ADMIN_PASSWORD, "admin", actor="test",
                             tenant_id=globex.id)
        bootstrap_platform_admin(db, "platform", PLATFORM_PASSWORD)
        profile = db.scalar(select(VendorProfile).where(VendorProfile.code == PROFILE_CODE))
        profile.status = "approved"
        cred = services.save_credential(db, platform.cipher, label="bmc-01",
                                        username="ADMIN", password=BMC_PASSWORD, actor="test")
        cap = Capability(id=str(uuid.uuid4()), vendor=MANUFACTURER, model="X10DRT-PS",
                         firmware="8.78", adapter="passthrough", profile_id=profile.id,
                         status="verified", expires=time.time() + 86400 * 30,
                         evidence="synthetic fixture", approver="operator",
                         console_impl="AST2100 / iKVM HTML5", licence="synthetic",
                         created=time.time())
        db.add(cap)
        db.flush()
        assets = [services.upsert_asset(
            db, name=f"node-{index}", address=f"192.0.2.1{index}", vendor=MANUFACTURER,
            model="X10DRT-PS", firmware="8.78", fingerprint=FINGERPRINT,
            credential_id=cred.id, profile_id=profile.id, capability_id=cap.id,
            actor="test") for index in (1, 2)]
        for asset in assets:
            services.grant_asset(db, user_id=admin.id, asset_id=asset.id, actor="test")
        ids = {"admin": admin.id, "globex": globex.id,
               "assets": [asset.id for asset in assets], "capability": cap.id}
    capability = store.register_capability({
        "id": "auto-quota-fixture", "vendor": MANUFACTURER, "model": "X10DRT-PS",
        "firmware": "8.78", "adapter": PASSTHROUGH_ADAPTER_ID,
        "models": ["X10DRT-PS"],
        "firmware_min": "", "firmware_max": "", "protocol_versions": ["RFB 003.008"],
        "input_shaping": {}, "logout_path": "", "console_impl": "AST2100 / iKVM HTML5",
        "licence": "synthetic", "concurrency_limit": 1,
        "evidence": "synthetic fixture"}, "operator")
    store.approve_capability(capability["id"], actor="operator", approver="operator",
                             evidence="synthetic fixture", licence="synthetic",
                             console_impl="AST2100 / iKVM HTML5",
                             expires=time.time() + 86400 * 30,
                             review_due=time.time() + 86400 * 30)
    for index, asset_id in enumerate(ids["assets"], start=1):
        store.register_asset(asset_id=asset_id, name=f"node-{index}",
                             vendor=MANUFACTURER, model="X10DRT-PS", firmware="8.78",
                             capability_id=capability["id"], target=TARGET,
                             fingerprint=FINGERPRINT, username="ADMIN",
                             password=BMC_PASSWORD, user_id=ids["admin"], actor="test")
        with store.tx():
            store.db.execute("INSERT OR REPLACE INTO access_grant VALUES(?,?,?)",
                             (TENANT_GRANT, asset_id, time.time() + 86400 * 30))
    asyncio.run(bus.register_worker("w1", instance_id="i1", capacity=4))
    store.close()
    with TestClient(app, base_url=ORIGIN, client=("127.0.0.1", 54321)) as client:
        yield SimpleNamespace(client=client, platform=platform, state=state, bus=bus,
                              plane=plane, ids=ids)
        platform.engine.dispose()


def login(client: TestClient, username: str = "admin",
          password: str = ADMIN_PASSWORD) -> str:
    path = "/api/v2/platform/login" if username == "platform" else "/api/v2/login"
    response = client.post(path, json={"username": username, "password": password})
    assert response.status_code == 200, response.text
    return response.json()["csrf"]


def headers(csrf: str) -> dict:
    return {"Origin": ORIGIN, "X-CSRF-Token": csrf}


def set_quotas(rig, quotas: dict, *, tenant_id: str = DEFAULT_TENANT_ID) -> None:
    with transaction(rig.platform.factory) as db:
        db.get(Tenant, tenant_id).quotas_json = json_field(quotas)


def open_console(rig, csrf: str, asset_id: str):
    return rig.client.post("/api/v2/consoles/open", json={"asset_id": asset_id},
                           headers=headers(csrf))


def test_quota_gate_refuses_the_second_console_and_returns_the_slot_on_close(rig):
    set_quotas(rig, {"max_concurrent_sessions": 1})
    csrf = login(rig.client)
    first = open_console(rig, csrf, rig.ids["assets"][0])
    assert first.status_code == 200, first.text

    refused = open_console(rig, csrf, rig.ids["assets"][1])
    assert refused.status_code == 429, refused.text
    assert refused.json()["error"] == "quota_exceeded"
    again = open_console(rig, csrf, rig.ids["assets"][1])
    assert again.status_code == 429

    closed = rig.client.post(f"/api/v2/consoles/{first.json()['sid']}/close",
                             headers=headers(csrf))
    assert closed.status_code == 200, closed.text
    retried = open_console(rig, csrf, rig.ids["assets"][1])
    assert retried.status_code == 200, retried.text


def test_a_session_the_worker_reaper_ended_stops_counting_against_the_quota(rig):
    set_quotas(rig, {"max_concurrent_sessions": 1})
    csrf = login(rig.client)
    first = open_console(rig, csrf, rig.ids["assets"][0])
    assert first.status_code == 200, first.text
    sid = first.json()["sid"]

    store, dispose = rig.plane._connect()
    try:
        store.db.execute("UPDATE session SET status='closed', reason='deadline' WHERE id=?",
                         (sid,))
        store.db.commit()
    finally:
        if dispose:
            store.close()
    assert asyncio.run(rig.bus.tenant_quota_usage(DEFAULT_TENANT_ID)) == 1
    assert asyncio.run(rig.bus.quota_members(DEFAULT_TENANT_ID)) == [sid]

    second = open_console(rig, csrf, rig.ids["assets"][1])
    assert second.status_code == 200, second.text
    members = asyncio.run(rig.bus.quota_members(DEFAULT_TENANT_ID))
    assert sid not in members and second.json()["sid"] in members


def test_absent_quota_means_unlimited(rig):
    csrf = login(rig.client)
    first = open_console(rig, csrf, rig.ids["assets"][0])
    assert first.status_code == 200, first.text
    second = open_console(rig, csrf, rig.ids["assets"][1])
    assert second.status_code == 200, second.text


def test_session_minutes_narrows_the_ticket_and_leaves_live_sessions_alone(rig):
    set_quotas(rig, {"max_session_minutes": 2})
    csrf = login(rig.client)
    opened = open_console(rig, csrf, rig.ids["assets"][0])
    assert opened.status_code == 200, opened.text
    body = opened.json()
    now = time.time()
    assert body["session_limit_minutes"] == 2
    assert now + 110 <= body["hard_until"] <= now + 121
    store, dispose = rig.plane._connect()
    try:
        original = store.get(body["sid"])["hard_until"]
        assert original == body["hard_until"]
    finally:
        if dispose:
            store.close()

    set_quotas(rig, {"max_session_minutes": 1})
    store, dispose = rig.plane._connect()
    try:
        assert store.get(body["sid"])["hard_until"] == original
    finally:
        if dispose:
            store.close()
    second = open_console(rig, csrf, rig.ids["assets"][1])
    assert second.status_code == 200, second.text
    now = time.time()
    assert now + 50 <= second.json()["hard_until"] <= now + 61


def test_suspended_tenant_is_refused_and_says_so(rig):
    with transaction(rig.platform.factory) as db:
        db.get(Tenant, DEFAULT_TENANT_ID).status = "suspended"
    csrf = login(rig.client)
    refused = open_console(rig, csrf, rig.ids["assets"][0])
    assert refused.status_code == 403, refused.text
    assert refused.json()["error"] == "tenant_suspended"


def test_asset_quota_blocks_creation_but_not_edits(rig):
    set_quotas(rig, {"max_assets": 2})
    csrf = login(rig.client)
    payload = {"name": "node-3", "address": "192.0.2.13"}
    refused = rig.client.post("/api/v2/assets", json=payload, headers=headers(csrf))
    assert refused.status_code == 429, refused.text
    assert refused.json()["error"] == "quota_exceeded"
    edit = rig.client.post("/api/v2/assets",
                           json={"name": "node-1-renamed", "address": "192.0.2.11"},
                           headers=headers(csrf))
    assert edit.status_code == 200, edit.text


def test_session_list_is_tenant_scoped_and_names_the_asset(rig):
    csrf = login(rig.client)
    opened = open_console(rig, csrf, rig.ids["assets"][0])
    assert opened.status_code == 200, opened.text

    rows = rig.client.get("/api/v2/sessions").json()
    assert [row["sid"] for row in rows] == [opened.json()["sid"]]
    assert rows[0]["asset_name"] == "node-1"
    assert rows[0]["username"] == "admin"
    assert rows[0]["tenant_id"] == DEFAULT_TENANT_ID


def test_revoke_publishes_revoke_clears_route_and_frees_quota(rig):
    set_quotas(rig, {"max_concurrent_sessions": 1})
    csrf = login(rig.client)
    opened = open_console(rig, csrf, rig.ids["assets"][0])
    assert opened.status_code == 200, opened.text
    sid = opened.json()["sid"]
    assert asyncio.run(rig.state.drain_revocations()) == []

    revoked = rig.client.post(f"/api/v2/sessions/{sid}/revoke", headers=headers(csrf))
    assert revoked.status_code == 200, revoked.text
    body = revoked.json()
    assert body["was_live"] is True and body["tenant_id"] == DEFAULT_TENANT_ID
    assert asyncio.run(rig.state.drain_revocations()) == [sid], "the Worker never learns to stop"
    assert asyncio.run(rig.bus.tenant_quota_usage(DEFAULT_TENANT_ID)) == 0
    assert open_console(rig, csrf, rig.ids["assets"][1]).status_code == 200


def test_tenant_cannot_revoke_another_tenants_session(rig):
    csrf = login(rig.client)
    opened = open_console(rig, csrf, rig.ids["assets"][0])
    sid = opened.json()["sid"]

    globex = rig.client.post("/api/v2/login",
                             json={"username": "globex-admin", "password": ADMIN_PASSWORD,
                                   "tenant_code": "globex"})
    assert globex.status_code == 200, globex.text
    globex_csrf = globex.json()["csrf"]
    refused = rig.client.post(f"/api/v2/sessions/{sid}/revoke",
                              headers=headers(globex_csrf))
    assert refused.status_code == 404, refused.text
    assert refused.json()["error"] == "session_not_found"
    assert asyncio.run(rig.state.drain_revocations()) == [], "a refused revoke must not signal"


def test_cleanup_confirmation_cannot_release_another_tenants_slot(rig):
    csrf = login(rig.client)
    sid = open_console(rig, csrf, rig.ids["assets"][0]).json()["sid"]
    store, dispose = rig.plane._connect()
    try:
        store.db.execute("UPDATE session SET status='lost',cleanup='pending' WHERE id=?", (sid,))
    finally:
        if dispose:
            store.close()

    foreign_csrf = login(rig.client, "globex-admin")
    foreign = rig.client.post(f"/api/v2/consoles/{sid}/cleanup", headers=headers(foreign_csrf))
    missing = rig.client.post(f"/api/v2/consoles/{'0' * 32}/cleanup", headers=headers(foreign_csrf))
    assert foreign.status_code == missing.status_code == 404
    assert foreign.json()["error"] == missing.json()["error"] == "session_not_found"
    store, dispose = rig.plane._connect()
    try:
        assert store.get(sid)["cleanup"] == "pending"
        assert store.db.execute("SELECT 1 FROM asset_slot WHERE session_id=?", (sid,)).fetchone()
    finally:
        if dispose:
            store.close()
    csrf = login(rig.client)
    own = rig.client.post(f"/api/v2/consoles/{sid}/cleanup", headers=headers(csrf))
    assert own.status_code == 200, own.text


def test_platform_channel_sees_all_tenants_and_revokes_with_an_audit_row(rig):
    csrf = login(rig.client)
    opened = open_console(rig, csrf, rig.ids["assets"][0])
    sid = opened.json()["sid"]

    tenant_view = rig.client.get("/api/v2/platform/sessions")
    assert tenant_view.status_code == 403
    assert tenant_view.json()["error"] == "platform_access_denied"

    platform_csrf = login(rig.client, "platform", PLATFORM_PASSWORD)
    listing = rig.client.get("/api/v2/platform/sessions")
    assert listing.status_code == 200, listing.text
    assert [row["sid"] for row in listing.json()] == [sid]

    revoked = rig.client.post(f"/api/v2/platform/sessions/{sid}/revoke",
                              headers=headers(platform_csrf))
    assert revoked.status_code == 200, revoked.text
    with transaction(rig.platform.factory) as db:
        rows = services.recent_audit(db, tenant_id=None)
        force = [row for row in rows if row["action"] == "session.force_revoked"]
        assert force and force[0]["tenant_id"] == DEFAULT_TENANT_ID
        assert force[0]["actor_type"] == "platform"


def test_memory_quota_prunes_on_expiry_instead_of_counting_forever():
    clock = [1_000.0]
    state = MemoryState(clock=lambda: clock[0])
    key = quota_key("t1")

    async def run():
        assert await state.reserve_quota(key, "s1", 1, 30)
        assert not await state.reserve_quota(key, "s2", 1, 30)
        clock[0] += 31
        assert await state.quota_usage(key) == 1
        assert not await state.reserve_quota(key, "s2", 1, 30)
        clock[0] += 5
        assert await state.quota_usage(key) == 0
        assert await state.reserve_quota(key, "s2", 1, 30)
        await state.release_quota(key, "s2")
        assert await state.quota_usage(key) == 0
    asyncio.run(run())


def test_memory_quota_key_is_visible_to_reconciliation():
    async def run():
        state = MemoryState()
        key = quota_key("t1")
        await state.reserve_quota(key, "s1", 5, 60)
        assert key in await state.keys("kvmhub:quota:")
        assert await state.keys("kvmhub:quota:") != []
    asyncio.run(run())


@pytest.mark.skipif(not os.environ.get("KVMHUB_TEST_REDIS_URL"),
                    reason="set KVMHUB_TEST_REDIS_URL to run the real Redis quota check")
def test_real_redis_quota_reservation_is_atomic_and_uses_server_time():
    async def run():
        state = RedisState(os.environ["KVMHUB_TEST_REDIS_URL"])
        key = quota_key("test-" + uuid.uuid4().hex[:12])
        members = [f"s{index}" for index in range(20)]
        try:
            grants = await asyncio.gather(*(
                state.reserve_quota(key, member, 3, 30) for member in members))
            assert sum(grants) == 3, grants
            assert await state.quota_usage(key) == 3
            assert not await state.reserve_quota(key, "late", 3, 30)
            for member, granted in zip(members, grants):
                if granted:
                    await state.release_quota(key, member)
            assert await state.quota_usage(key) == 0
            assert await state.reserve_quota(key, "after-release", 3, 30)
        finally:
            for member in members + ["late", "after-release"]:
                await state.release_quota(key, member)
            await state.close()
    asyncio.run(run())


def test_memory_quota_ttl_tracks_the_latest_live_reservation():
    clock = [1_000.0]
    state = MemoryState(clock=lambda: clock[0])
    key = quota_key("ttl-check")

    async def run():
        assert await state.reserve_quota(key, "short", 4, 10)
        clock[0] += 8
        assert await state.reserve_quota(key, "long", 4, 100)
        clock[0] += 10
        assert await state.quota_usage(key) == 1
        assert await state.reserve_quota(key, "next", 4, 10)
    asyncio.run(run())


@pytest.mark.skipif(not os.environ.get("KVMHUB_TEST_REDIS_URL"),
                    reason="set KVMHUB_TEST_REDIS_URL to run the real Redis quota check")
def test_real_redis_quota_short_reservation_preserves_long_one_and_usage_prunes():
    async def run():
        state = RedisState(os.environ["KVMHUB_TEST_REDIS_URL"])
        key = quota_key("test-" + uuid.uuid4().hex[:12])
        try:
            assert await state.reserve_quota(key, "long", 2, 120)
            assert await state.reserve_quota(key, "short", 2, 1)
            assert await state._client.pttl(key) > 120_000
            now = await state._client.time()
            now_ms = now[0] * 1000 + now[1] // 1000
            await state._client.zadd(key, {"short": now_ms - 6000})
            assert await state.quota_usage(key) == 1
            assert await state.reserve_quota(key, "replacement", 2, 1)
            assert not await state.reserve_quota(key, "excess", 2, 1)
            assert await state._client.pttl(key) > 120_000
        finally:
            await state._client.delete(key)
            await state.close()
    asyncio.run(run())


def test_worker_revoke_watcher_ends_only_the_matching_session(tmp_path):
    bus = AssemblyBus(MemoryState())
    cfg = json.loads((generate(tmp_path / "identity") / "worker.json").read_text())
    cfg["reconnect_grace_seconds"] = 0.5
    gateway = Gateway(cfg, assembly_bus=bus)
    finished: list[tuple[str, str]] = []

    class FakeSession:
        def __init__(self, sid: str):
            self.sid = sid

    async def fake_finish(session, reason):
        finished.append((session.sid, reason))

    gateway.finish = fake_finish
    gateway.sessions["s1"] = FakeSession("s1")
    gateway.sessions["s2"] = FakeSession("s2")

    async def run():
        watcher = asyncio.create_task(gateway.watch_revocations())
        try:
            await bus.publish_revoke("s1")
            for _ in range(50):
                if finished:
                    break
                await asyncio.sleep(0.02)
            await bus.publish_revoke("unknown-sid")
            await asyncio.sleep(0.1)
        finally:
            watcher.cancel()
            try:
                await watcher
            except asyncio.CancelledError:
                pass

    asyncio.run(run())
    assert finished == [("s1", "revoked")]


def test_the_revoke_watcher_exits_quietly_on_shutdown(monkeypatch, caplog):
    class Bus:
        async def revocations(self):
            try:
                await asyncio.sleep(3600)
            except asyncio.CancelledError:
                raise TimeoutError("Timeout reading from 127.0.0.1:6379") from None
            yield ""  # pragma: no cover - unreachable, makes this a generator

    bus = Bus()
    finished = asyncio.Event()

    async def run():
        gateway = Gateway.__new__(Gateway)
        gateway.assembly_bus = bus
        gateway.sessions = {}
        gateway.watchdogs = set()
        gateway.revoke_task = asyncio.current_task()
        try:
            await gateway.watch_revocations()
        finally:
            finished.set()

    async def scenario():
        task = asyncio.create_task(run())
        await asyncio.sleep(0.05)
        task.cancel()
        await task

    with caplog.at_level("WARNING"):
        asyncio.run(scenario())
    assert finished.is_set(), "the watcher must not retry forever after a cancel"
    assert not [record for record in caplog.records if record.levelname == "ERROR"]


def test_the_revocation_subscription_has_no_read_timeout():
    from kvmhub.platform.redis_state import RedisState

    state = RedisState("redis://127.0.0.1:6379/0")
    command = state._client.connection_pool.connection_kwargs
    subscription = state._subscription_client().connection_pool.connection_kwargs
    assert command["socket_timeout"] == 3
    assert subscription.get("socket_timeout") is None
    assert subscription["socket_connect_timeout"] == 3
