"""Stage 30 step 2: control plane -> ticket -> Worker assembly, end to end."""
from __future__ import annotations

import asyncio
import time
import uuid
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (Encoding, NoEncryption,
                                                          PrivateFormat, PublicFormat)
from fastapi.testclient import TestClient
from sqlalchemy import select

from kvmhub import common as common_module
from kvmhub.adapters.passthrough import PassthroughAdapter
from kvmhub.common import PASSTHROUGH_ADAPTER_ID, Problem, verify
from kvmhub.platform import connection, data_plane, services, vendor_registry
from kvmhub.platform.api import create_app
from kvmhub.platform.bus import AssemblyBus, BusError
from kvmhub.platform.config import Settings
from kvmhub.platform.console import ConsolePlane
from kvmhub.platform.db import init_schema, seed_roles, session_factory, transaction
from kvmhub.platform.models import DEFAULT_TENANT_ID, Capability, Tenant, VendorProfile
from kvmhub.platform.redis_state import MemoryState
from kvmhub.platform.security import CredentialCipher
from kvmhub.store import Store
from kvmhub.worker import Gateway

KEY = b"0123456789abcdef0123456789abcdef"
ADMIN_PASSWORD = "synthetic-password"
VIEWER_PASSWORD = "unit-test-password"
BMC_PASSWORD = "local-admin"
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
    public_pem = private.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    signing_key = tmp_path / "signing.pem"
    signing_key.write_bytes(private.private_bytes(Encoding.PEM, PrivateFormat.PKCS8,
                                                  NoEncryption()))
    data_db = tmp_path / "data-plane.db"

    def connect() -> Store:
        return Store(str(data_db), KEY, passthrough_targets=(TARGET,))

    store = connect()
    plane = ConsolePlane(store_factory=connect, private_key=private, bus=bus,
                         accept_template="https://{worker_id}-{sid}.kvm.localhost:9443/_platform/accept")
    app = create_app(cfg, state=state, plane=plane)
    platform = app.state.platform
    with transaction(platform.factory) as db:
        init_schema(platform.engine)
        seed_roles(db)
        vendor_registry.seed_builtin_profiles(db)
        admin = services.create_user(db, "admin", ADMIN_PASSWORD, "admin", actor="test")
        viewer = services.create_user(db, "viewer", VIEWER_PASSWORD, "viewer", actor="test")
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
        asset = services.upsert_asset(
            db, name="node-1", address="192.0.2.11", vendor=MANUFACTURER,
            model="X10DRT-PS", firmware="8.78", fingerprint=FINGERPRINT,
            credential_id=cred.id, profile_id=profile.id, capability_id=cap.id,
            actor="test")
        services.grant_asset(db, user_id=admin.id, asset_id=asset.id, actor="test")
        assembly = connection.assembly(db, asset_id=asset.id, user_id=admin.id, actor="admin")
        ids = {"admin": admin.id, "viewer": viewer.id, "asset": asset.id,
               "credential": cred.id, "capability": cap.id}
    entry = assembly["data_plane"]["capability_entry"]
    store.register_capability(entry, "operator")
    store.approve_capability(entry["id"], actor="operator", approver="operator",
                             evidence="synthetic fixture", licence="synthetic",
                             console_impl="AST2100 / iKVM HTML5",
                             expires=time.time() + 86400 * 30,
                             review_due=time.time() + 86400 * 30)
    store.register_asset(asset_id=asset.id, name="node-1", vendor=MANUFACTURER,
                         model="X10DRT-PS", firmware="8.78",
                         capability_id=entry["id"], target=TARGET,
                         fingerprint=FINGERPRINT, username="ADMIN",
                         password=BMC_PASSWORD, user_id=admin.id, actor="test")
    asyncio.run(bus.register_worker("w1", instance_id="i1", capacity=2))
    store.close()
    yield SimpleNamespace(cfg=cfg, app=app, platform=platform, state=state, bus=bus,
                          plane=plane, connect=connect, private=private,
                          public_pem=public_pem, signing_key=signing_key,
                          assembly=assembly, entry=entry, ids=ids)
    platform.engine.dispose()


def login(c: TestClient, username="admin", password=ADMIN_PASSWORD):
    r = c.post("/api/v2/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return r.json()["csrf"]


def headers(csrf):
    return {"Origin": ORIGIN, "X-CSRF-Token": csrf}



def test_default_asset_templates_match_the_measured_whitelist():
    pattern = data_plane.compile_asset_paths(None)
    assert pattern.fullmatch("/novnc/include/rfb.js")
    assert pattern.fullmatch("/js/util.js")
    assert pattern.fullmatch("/images/a/b/logo.png")
    assert pattern.fullmatch("/favicon.ico")
    assert pattern.fullmatch("/cgi/login.cgi") is None
    assert pattern.fullmatch("/novnc/include/../secret.js") is None
    assert pattern.fullmatch("/novnc/include/%2e%2e/x.js") is None


def test_a_profile_cannot_widen_the_whitelist_into_a_control_endpoint():
    for bad in (["/cgi/*.cgi"], ["/_platform/*"], ["/images/../../x.png"],
                ["/js/.*"], ["//js/*.js"], ["/js/*.js?x=1"]):
        with pytest.raises(Problem, match="invalid_target_policy"):
            data_plane.compile_asset_paths(bad)


def test_brand_plan_becomes_worker_settings(rig):
    info = {"target": TARGET, "fingerprint": FINGERPRINT,
            "adapter": PASSTHROUGH_ADAPTER_ID, "protocol_versions": (),
            "input_shaping": None, "logout_path": None}
    result = data_plane.assembled_info(info, rig.assembly)
    assert result["protocol_versions"] == ("RFB 003.008",)
    assert result["login_path"] == "/cgi/login.cgi"
    assert result["logout_path"] == "/cgi/logout.cgi"
    assert result["message_profile"] == "insyde"
    assert result["asset_pattern"].fullmatch("/novnc/include/rfb.js")
    assert result["asset_pattern"].fullmatch("/cgi/login.cgi") is None
    assert info["protocol_versions"] == (), "原 info 不能被就地改写"


def test_a_mismatched_message_profile_is_refused_before_a_frame_is_sent(rig):
    broken = dict(rig.assembly)
    broken["plan"] = {**rig.assembly["plan"], "message_profile": "smc"}
    with pytest.raises(Problem, match="invalid_target_policy"):
        data_plane.assembled_info({"target": TARGET}, broken)


def test_no_assembly_keeps_the_measured_poc_defaults():
    info = {"target": TARGET, "protocol_versions": (), "logout_path": None}
    assert data_plane.assembled_info(info, None) is info


def test_real_adapter_consumes_the_assembled_paths(rig):
    info = data_plane.assembled_info(
        {"target": TARGET, "fingerprint": FINGERPRINT,
         "adapter": PASSTHROUGH_ADAPTER_ID, "protocol_versions": (),
         "input_shaping": None, "logout_path": None}, rig.assembly)
    adapter = PassthroughAdapter(info)
    assert adapter.cfg.login_path == "/cgi/login.cgi"
    assert adapter.cfg.logout_path == "/cgi/logout.cgi"
    assert adapter.cfg.protocol_versions == ("RFB 003.008",)
    assert adapter.asset_pattern.fullmatch("/js/rfb.js")
    assert adapter.asset_pattern.fullmatch("/cgi/login.cgi") is None



def test_assembly_is_one_shot_and_never_carries_a_password(rig):
    document = {"plan": rig.assembly["plan"], "password": "synthetic-password",
                "username": "ADMIN", "ticket": "secret"}
    assembly_id = asyncio.run(rig.bus.put_assembly("sid-1", document))
    value = asyncio.run(rig.bus.peek_assembly("sid-1"))
    assert value["assembly_id"] == assembly_id
    assert "password" not in value and "username" not in value and "ticket" not in value
    assert asyncio.run(rig.bus.take_assembly("sid-1")) is not None
    assert asyncio.run(rig.bus.take_assembly("sid-1")) is None


def test_least_loaded_routing_and_capacity_exhaustion(rig):
    async def scenario():
        await rig.bus.register_worker("w2", instance_id="i2", capacity=1)
        assert await rig.bus.claim_session("w1", "s0", 60)
        assert (await rig.bus.choose_worker())["worker_id"] == "w2"
        assert await rig.bus.claim_session("w1", "s1", 60)
        assert await rig.bus.claim_session("w2", "s2", 60)
        with pytest.raises(BusError, match="worker_capacity_exhausted"):
            await rig.bus.choose_worker()
        await rig.bus.release_session("w2", "s2")
        assert (await rig.bus.choose_worker())["worker_id"] == "w2"
    asyncio.run(scenario())


def test_no_registered_worker_refuses_to_issue_a_ticket():
    bus = AssemblyBus(MemoryState())
    with pytest.raises(BusError, match="no_worker_available"):
        asyncio.run(bus.choose_worker())


def test_worker_registration_expires_with_its_ttl():
    clock = {"now": 1000.0}
    state = MemoryState(clock=lambda: clock["now"])
    bus = AssemblyBus(state, clock=lambda: clock["now"])
    asyncio.run(bus.register_worker("w1", instance_id="i1", capacity=2, ttl=10))
    assert asyncio.run(bus.workers())
    clock["now"] = 1011.0
    assert asyncio.run(bus.workers()) == {}



def test_console_open_signs_a_verifiable_ticket(rig):
    with TestClient(rig.app, base_url=ORIGIN) as c:
        csrf = login(c)
        r = c.post("/api/v2/consoles/open", json={"asset_id": rig.ids["asset"]},
                   headers=headers(csrf))
        assert r.status_code == 200, r.text
        out = r.json()
        assert out["delivery"] == "worker_bridge" and out["worker_id"] == "w1"
        assert out["assembly_id"] and out["sid"] in out["accept_url"]
        assert BMC_PASSWORD not in r.text and "ADMIN" not in r.text
        claims = verify(rig.private.public_key(), out["ticket"], "w1", "i1")
        assert claims["sid"] == out["sid"] and claims["aid"] == rig.ids["asset"]
        assert claims["wid"] == "w1" and claims["iid"] == "i1"
        delivered = asyncio.run(rig.bus.take_assembly(out["sid"]))
        assert delivered is not None and delivered["plan"]["rfb_version"] == "RFB 003.008"
        assert "password" not in str(delivered)
        assert asyncio.run(rig.bus.take_assembly(out["sid"])) is None
        status = c.get(f"/api/v2/consoles/{out['sid']}").json()
        assert status["status"] == "pending"


def test_second_console_on_one_asset_is_refused_with_asset_busy(rig):
    with TestClient(rig.app, base_url=ORIGIN) as c:
        csrf = login(c)
        first = c.post("/api/v2/consoles/open", json={"asset_id": rig.ids["asset"]},
                       headers=headers(csrf))
        assert first.status_code == 200, first.text
        second = c.post("/api/v2/consoles/open", json={"asset_id": rig.ids["asset"]},
                        headers=headers(csrf))
        assert second.status_code == 409 and second.json()["error"] == "asset_busy"


def test_proxy_route_follows_ticket_worker_and_keeps_draining_sessions_routable(rig):
    async def run():
        await rig.bus.register_worker('w1', instance_id='i1', capacity=2,
                                      metadata={'address': '192.0.2.7', 'port': 9443})
        out = await rig.plane.open(rig.assembly, user_id=rig.ids['admin'])
        host = f"w1-{out['sid']}.kvm.example.test"
        assert await rig.plane.route(host) == '192.0.2.7:9443'
        await rig.bus.set_draining('w1', True, actor='operator')
        assert await rig.plane.route(host) == '192.0.2.7:9443'
        with pytest.raises(services.PlatformError):
            await rig.plane.route(f"w2-{out['sid']}.kvm.example.test")
        await rig.bus.register_worker('w1', instance_id='replacement', capacity=2,
                                      metadata={'address': '192.0.2.8', 'port': 9443})
        with pytest.raises(services.PlatformError):
            await rig.plane.route(host)
    asyncio.run(run())


def test_path_mode_publishes_and_clears_entry_route(rig, monkeypatch):
    monkeypatch.setattr(common_module, "SESSION_MODE", "path", raising=True)

    async def run():
        await rig.bus.register_worker('w1', instance_id='i1', capacity=2,
                                      metadata={'address': '192.0.2.7', 'port': 9443})
        out = await rig.plane.open(rig.assembly, user_id=rig.ids['admin'])
        assert await rig.bus.get_route(out['sid']) == {
            'worker_id': 'w1', 'instance_id': 'i1',
            'upstream': '192.0.2.7:9443', 'asset_id': rig.ids['asset'],
            'tenant_id': DEFAULT_TENANT_ID}
        await rig.plane.close_session(out['sid'], user_id=rig.ids['admin'])
        assert await rig.bus.get_route(out['sid']) is None

    asyncio.run(run())


@pytest.mark.parametrize('status', ['closing', 'closed', 'failed', 'lost'])
def test_proxy_route_rejects_sessions_that_are_ending_or_ended(rig, status):
    async def run():
        await rig.bus.register_worker('w1', instance_id='i1', capacity=2,
                                      metadata={'address': '192.0.2.7', 'port': 9443})
        out = await rig.plane.open(rig.assembly, user_id=rig.ids['admin'])
        store = rig.connect()
        try:
            store.db.execute('UPDATE session SET status=? WHERE id=?', (status, out['sid']))
            store.db.commit()
        finally:
            store.close()
        with pytest.raises(services.PlatformError) as caught:
            await rig.plane.route(f"w1-{out['sid']}.kvm.example.test")
        assert caught.value.code == 'invalid_session'
    asyncio.run(run())


def test_proxy_route_rejects_a_session_past_its_hard_deadline(rig):
    async def run():
        await rig.bus.register_worker('w1', instance_id='i1', capacity=2,
                                      metadata={'address': '192.0.2.7', 'port': 9443})
        out = await rig.plane.open(rig.assembly, user_id=rig.ids['admin'])
        store = rig.connect()
        try:
            store.db.execute('UPDATE session SET hard_until=? WHERE id=?', (time.time() - 1, out['sid']))
            store.db.commit()
        finally:
            store.close()
        with pytest.raises(services.PlatformError) as caught:
            await rig.plane.route(f"w1-{out['sid']}.kvm.example.test")
        assert caught.value.code == 'invalid_session'
    asyncio.run(run())


def test_proxy_route_rejects_public_or_malformed_upstream(rig):
    async def run():
        out = await rig.plane.open(rig.assembly, user_id=rig.ids['admin'])
        for address in ('8.8.8.8', 'example.com/path', 'http://127.0.0.1'):
            await rig.bus.register_worker('w1', instance_id='i1', capacity=2,
                                          metadata={'address': address, 'port': 9443})
            with pytest.raises(services.PlatformError):
                await rig.plane.route(f"w1-{out['sid']}.example.test")
    asyncio.run(run())


def test_asset_list_reads_occupancy_from_the_slot_including_cleanup_pending(rig):
    with TestClient(rig.app, base_url=ORIGIN) as c:
        csrf = login(c)
        assert c.get('/api/v2/assets').json()[0]['occupancy'] is None
        out = c.post('/api/v2/consoles/open', headers=headers(csrf),
                     json={'asset_id': rig.ids['asset']}).json()
        occupancy = c.get('/api/v2/assets').json()[0]['occupancy']
        assert occupancy['owned'] and occupancy['username'] == 'admin'
        assert occupancy['session_id'] == out['sid'] and occupancy['remaining_seconds'] > 0
        assert occupancy['queue'] == 'not_supported'
        store = rig.connect()
        try:
            store.db.execute("UPDATE session SET status='failed',cleanup='pending' WHERE id=?", (out['sid'],))
            store.db.commit()
        finally:
            store.close()
        occupancy = c.get('/api/v2/assets').json()[0]['occupancy']
        assert occupancy['busy'] and occupancy['cleanup'] == 'pending'


def test_other_users_cannot_read_occupant_identity_or_session_id(rig):
    with TestClient(rig.app, base_url=ORIGIN) as c:
        csrf = login(c)
        out = c.post('/api/v2/consoles/open', headers=headers(csrf),
                     json={'asset_id': rig.ids['asset']}).json()
        with transaction(rig.platform.factory) as db:
            services.grant_asset(db, user_id=rig.ids['viewer'], asset_id=rig.ids['asset'], actor='test')
        login(c, 'viewer', VIEWER_PASSWORD)
        occupancy = c.get('/api/v2/assets').json()[0]['occupancy']
        assert occupancy['busy'] and not occupancy['owned']
        assert occupancy['username'] is None and occupancy['user_id'] is None and occupancy['session_id'] is None
        assert out['sid'] not in str(occupancy)


def test_console_close_revokes_ticket_and_drops_the_assembly(rig):
    with TestClient(rig.app, base_url=ORIGIN) as c:
        csrf = login(c)
        out = c.post("/api/v2/consoles/open", json={"asset_id": rig.ids["asset"]},
                     headers=headers(csrf)).json()
        closed = c.post(f"/api/v2/consoles/{out['sid']}/close", headers=headers(csrf))
        assert closed.status_code == 200, closed.text
        assert asyncio.run(rig.bus.peek_assembly(out["sid"])) is None
        assert c.get(f"/api/v2/consoles/{out['sid']}").json()["status"] == "closed"


def _pending_session(c, csrf, rig):
    out = c.post("/api/v2/consoles/open", json={"asset_id": rig.ids["asset"]},
                 headers=headers(csrf)).json()
    store = rig.connect()
    try:
        store.db.execute("UPDATE session SET status='failed',cleanup='pending' WHERE id=?",
                         (out["sid"],))
        store.db.commit()
    finally:
        store.close()
    return out["sid"]


def test_a_pending_cleanup_blocks_the_asset_until_an_operator_confirms_it(rig):
    with TestClient(rig.app, base_url=ORIGIN) as c:
        csrf = login(c)
        sid = _pending_session(c, csrf, rig)
        blocked = c.post("/api/v2/consoles/open", json={"asset_id": rig.ids["asset"]},
                         headers=headers(csrf))
        assert blocked.status_code == 409 and blocked.json()["error"] == "asset_busy"

        released = c.post(f"/api/v2/consoles/{sid}/cleanup", headers=headers(csrf))
        assert released.status_code == 200, released.text
        assert released.json() == {"ok": True, "sid": sid, "cleanup": "confirmed"}

        again = c.post("/api/v2/consoles/open", json={"asset_id": rig.ids["asset"]},
                       headers=headers(csrf))
        assert again.status_code == 200, again.text
        actions = [row["action"] for row in c.get("/api/v2/audit").json()]
        assert "console_slot_released" in actions


def test_cleanup_is_refused_for_a_session_that_is_not_pending(rig):
    with TestClient(rig.app, base_url=ORIGIN) as c:
        csrf = login(c)
        out = c.post("/api/v2/consoles/open", json={"asset_id": rig.ids["asset"]},
                     headers=headers(csrf)).json()
        r = c.post(f"/api/v2/consoles/{out['sid']}/cleanup", headers=headers(csrf))
        assert r.status_code == 409 and r.json()["error"] == "cleanup_not_pending"


def test_viewer_cannot_confirm_a_cleanup(rig):
    with TestClient(rig.app, base_url=ORIGIN) as c:
        csrf = login(c)
        sid = _pending_session(c, csrf, rig)
        viewer_csrf = login(c, "viewer", VIEWER_PASSWORD)
        r = c.post(f"/api/v2/consoles/{sid}/cleanup", headers=headers(viewer_csrf))
        assert r.status_code == 403 and r.json()["error"] == "permission_denied"
        store = rig.connect()
        try:
            row = store.get(sid)
        finally:
            store.close()
        assert row["cleanup"] == "pending", "a refused caller must change nothing"


def test_the_management_view_exposes_the_session_it_has_to_release(rig):
    with TestClient(rig.app, base_url=ORIGIN) as c:
        csrf = login(c)
        with transaction(rig.platform.factory) as db:
            services.create_user(db, "ops2", VIEWER_PASSWORD, "operator", actor="test")
            ops_id = db.scalar(select(services.User.id).where(services.User.username == "ops2"))
            services.grant_asset(db, user_id=ops_id, asset_id=rig.ids["asset"], actor="test")
        store = rig.connect()
        try:
            store.db.execute("INSERT INTO access_grant(user_id,asset_id,expires) VALUES(?,?,?)",
                             (ops_id, rig.ids["asset"], time.time() + 3600))
            store.db.commit()
        finally:
            store.close()
        ops_csrf = login(c, "ops2", VIEWER_PASSWORD)
        sid = _pending_session(c, ops_csrf, rig)
        admin_csrf = login(c)
        occupancy = c.get("/api/v2/assets?scope=all", headers=headers(admin_csrf)).json()[0]["occupancy"]
        assert occupancy["busy"] and occupancy["cleanup"] == "pending"
        assert occupancy["session_id"] == sid and occupancy["username"] == "ops2"
        released = c.post(f"/api/v2/consoles/{sid}/cleanup", headers=headers(admin_csrf))
        assert released.status_code == 200, released.text


def test_consumer_tenant_admin_cannot_confirm_another_users_cleanup(rig):
    with TestClient(rig.app, base_url=ORIGIN) as c:
        csrf = login(c)
        with transaction(rig.platform.factory) as db:
            services.create_user(db, "ops3", VIEWER_PASSWORD, "operator", actor="test")
            ops_id = db.scalar(select(services.User.id).where(services.User.username == "ops3"))
            services.grant_asset(db, user_id=ops_id, asset_id=rig.ids["asset"], actor="test")
        store = rig.connect()
        try:
            store.db.execute("INSERT INTO access_grant(user_id,asset_id,expires) VALUES(?,?,?)",
                             (ops_id, rig.ids["asset"], time.time() + 3600))
            store.db.commit()
        finally:
            store.close()
        ops_csrf = login(c, "ops3", VIEWER_PASSWORD)
        sid = _pending_session(c, ops_csrf, rig)
        with transaction(rig.platform.factory) as db:
            db.get(Tenant, DEFAULT_TENANT_ID).mode = "consumer"
        admin_csrf = login(c)
        r = c.post(f"/api/v2/consoles/{sid}/cleanup", headers=headers(admin_csrf))
        assert r.status_code == 403 and r.json()["error"] == "permission_denied", r.text
        store = rig.connect()
        try:
            assert store.get(sid)["cleanup"] == "pending", "a refused caller must change nothing"
        finally:
            store.close()


def test_viewer_cannot_open_a_console(rig):
    with TestClient(rig.app, base_url=ORIGIN) as c:
        csrf = login(c, "viewer", VIEWER_PASSWORD)
        r = c.post("/api/v2/consoles/open", json={"asset_id": rig.ids["asset"]},
                   headers=headers(csrf))
        assert r.status_code == 403 and r.json()["error"] == "permission_denied"


def test_control_plane_without_a_data_plane_is_honest_about_it(tmp_path):
    cfg = cfg_for(f"sqlite:///{tmp_path}/readonly.db")
    state = MemoryState()
    app = create_app(cfg, state=state)
    with transaction(app.state.platform.factory) as db:
        init_schema(app.state.platform.engine)
        seed_roles(db)
        services.create_user(db, "admin", ADMIN_PASSWORD, "admin", actor="test")
    with TestClient(app, base_url=ORIGIN) as c:
        csrf = login(c)
        r = c.post("/api/v2/consoles/open", json={"asset_id": "whatever"},
                   headers=headers(csrf))
        assert r.status_code == 503 and r.json()["error"] == "data_plane_not_configured"
    app.state.platform.engine.dispose()


def test_worker_refuses_a_ticket_with_its_brand_assembly(rig):
    gateway = object.__new__(Gateway)
    gateway.assembly_bus = rig.bus
    with pytest.raises(Problem) as caught:
        asyncio.run(gateway.apply_assembly("never-issued", {"target": TARGET}))
    assert caught.value.code == "assembly_missing"

    gateway.assembly_bus = None
    info = {"target": TARGET}
    assert asyncio.run(gateway.apply_assembly("sid", info)) is info




def test_a_claim_without_a_live_session_is_released_before_routing(rig):
    orphan = "0" * 32
    asyncio.run(rig.bus.claim_session("w1", orphan, 3600))
    assert asyncio.run(rig.bus.worker_load("w1")) == 1

    out = asyncio.run(rig.plane.open(rig.assembly, user_id=rig.ids["admin"]))

    assert asyncio.run(rig.bus.worker_load("w1")) == 1
    assert asyncio.run(rig.bus.claims("w1")) == [out["sid"]]


def test_a_live_session_keeps_its_claim_when_the_plane_reconciles(rig):
    out = asyncio.run(rig.plane.open(rig.assembly, user_id=rig.ids["admin"]))
    assert asyncio.run(rig.plane.reconcile_claims()) == 0
    assert out["sid"] in asyncio.run(rig.bus.claims("w1"))


def test_a_session_the_worker_ended_frees_its_slot(rig):
    out = asyncio.run(rig.plane.open(rig.assembly, user_id=rig.ids["admin"]))
    store = rig.connect()
    try:
        store.finish(out["sid"], "w1", "i1", "confirmed", "client_closed")
    finally:
        store.close()
    assert asyncio.run(rig.plane.reconcile_claims()) == 1
    assert asyncio.run(rig.bus.worker_load("w1")) == 0


def test_brand_plan_protocol_reaches_worker_settings(rig):
    assembly = dict(rig.assembly)
    assembly["plan"] = {**rig.assembly["plan"], "protocol": "supermicro-ikvm-html5"}
    info = data_plane.assembled_info(
        {"target": TARGET, "fingerprint": FINGERPRINT,
         "adapter": PASSTHROUGH_ADAPTER_ID, "protocol_versions": (),
         "input_shaping": None, "logout_path": None}, assembly)
    assert info["protocol"] == "supermicro-ikvm-html5"


def test_unknown_brand_protocol_fails_the_exchange(rig):
    assembly = dict(rig.assembly)
    assembly["plan"] = {**rig.assembly["plan"], "protocol": "dell-idrac8-unregistered"}
    with pytest.raises(Problem, match="invalid_target_policy"):
        data_plane.assembled_info({"target": TARGET}, assembly)


def test_absent_protocol_keeps_the_measured_default(rig):
    info = data_plane.assembled_info(
        {"target": TARGET, "fingerprint": FINGERPRINT,
         "adapter": PASSTHROUGH_ADAPTER_ID, "protocol_versions": (),
         "input_shaping": None, "logout_path": None}, rig.assembly)
    assert info["protocol"] == ""
