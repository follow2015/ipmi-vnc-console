"""Brand auto-match -> approved profile -> PoC data-plane assembly."""
from __future__ import annotations

import time
import uuid
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from kvmhub import capability as poc_capability
from kvmhub.common import PASSTHROUGH_ADAPTER_ID
from kvmhub.platform import connection, services, vendor_registry
from kvmhub.platform.api import create_app
from kvmhub.platform.config import Settings
from kvmhub.platform.db import (init_schema, make_engine, seed_roles,
                                session_factory, transaction)
from kvmhub.platform.models import Asset, Capability, VendorProfile
from kvmhub.platform.redis_state import MemoryState
from kvmhub.platform.security import CredentialCipher
from kvmhub.store import Store

KEY = b"0123456789abcdef0123456789abcdef"
ADMIN_PASSWORD = "synthetic-password"
VIEWER_PASSWORD = "unit-test-password"
BMC_PASSWORD = "local-admin"
ORIGIN = "http://testserver"
PROFILE_CODE = "smci-x10-ast2100-rfb003008"
MANUFACTURER = "Supermicro (Inspur OEM)"


def make_cfg(db_url: str) -> Settings:
    return Settings(env="test", db_url=db_url, redis_url="", credential_key=KEY,
                    session_ttl=3600, lease_seconds=30, bootstrap_admin=None,
                    bootstrap_password=None, strict_prod=False)


@pytest.fixture
def world(tmp_path):
    cfg = make_cfg(f"sqlite:///{tmp_path}/control.db")
    engine = make_engine(cfg.db_url)
    init_schema(engine)
    factory = session_factory(engine)
    cipher = CredentialCipher(KEY)
    with transaction(factory) as db:
        seed_roles(db)
        vendor_registry.seed_builtin_profiles(db)
        admin = services.create_user(db, "admin", ADMIN_PASSWORD, "admin", actor="test")
        viewer = services.create_user(db, "viewer", VIEWER_PASSWORD, "viewer", actor="test")
        profile = connection.approved_profile(db, PROFILE_CODE)
        profile.status = "approved"
        cred = services.save_credential(db, cipher, label="bmc-01", username="ADMIN",
                                        password=BMC_PASSWORD, actor="test")
        cap = Capability(id=str(uuid.uuid4()), vendor=MANUFACTURER, model="X10DRT-PS",
                         firmware="8.78", adapter="passthrough", profile_id=profile.id,
                         status="verified", expires=time.time() + 86400 * 365,
                         evidence="docs/implementation/evidence/real-bmc-passthrough-e2e-20261112.json",
                         approver="operator", console_impl="AST2100 / iKVM HTML5",
                         licence="同源代理转发", created=time.time())
        db.add(cap)
        db.flush()
        asset = services.upsert_asset(
            db, name="node-1", address="192.0.2.11", vendor=MANUFACTURER,
            model="X10DRT-PS", firmware="8.78", credential_id=cred.id,
            profile_id=profile.id, capability_id=cap.id, actor="test")
        services.grant_asset(db, user_id=admin.id, asset_id=asset.id, actor="test")
        ids = {"admin": admin.id, "viewer": viewer.id, "asset": asset.id,
               "profile": profile.id, "capability": cap.id, "credential": cred.id}
    yield SimpleNamespace(cfg=cfg, engine=engine, factory=factory, cipher=cipher, ids=ids)
    engine.dispose()


def _entry(world, *, session=None):
    def build(db):
        profile = connection.approved_profile(db, PROFILE_CODE)
        asset = db.get(Asset, world.ids["asset"])
        return connection.capability_entry(
            profile, asset=asset,
            detection={"model": asset.model, "firmware": asset.firmware,
                       "raw": {"Manufacturer": MANUFACTURER}})
    if session is not None:
        return build(session)
    with transaction(world.factory) as db:
        return build(db)


def _refused(fn, code: str):
    with pytest.raises(connection.ConnectionRefused) as caught:
        fn()
    assert caught.value.code == code



def test_draft_profile_never_produces_an_entry(world):
    with transaction(world.factory) as db:
        profile = connection.approved_profile(db, PROFILE_CODE)
        profile.status = "draft"
        db.flush()
        _refused(lambda: connection.capability_entry(profile, asset=db.get(Asset, world.ids["asset"])),
                 "profile_not_approved")


def test_an_unimplemented_adapter_is_refused_not_silently_rerouted(world):
    with transaction(world.factory) as db:
        profile = connection.approved_profile(db, PROFILE_CODE)
        profile.console_impl = "some-future-adapter"
        db.flush()
        _refused(lambda: connection.capability_entry(profile, asset=db.get(Asset, world.ids["asset"])),
                 "adapter_unavailable")


def test_entry_carries_the_measured_protocol_and_logout_path(world):
    entry = _entry(world)
    assert entry["adapter"] == PASSTHROUGH_ADAPTER_ID
    assert entry["protocol_versions"] == ["RFB 003.008"]
    assert entry["logout_path"] == "/cgi/logout.cgi"
    assert entry["model"] == "X10DRT-PS" and entry["firmware"] == "8.78"
    assert entry["id"].startswith("auto-")
    assert _entry(world)["id"] == entry["id"]
    assert poc_capability.window_parses(entry)


def test_entry_is_accepted_and_approved_by_the_real_poc_store(world):
    entry = _entry(world)
    store = Store(":memory:")
    try:
        row = store.register_capability(entry, "control-plane")
        assert row["status"] == "draft"
        assert row["adapter"] == PASSTHROUGH_ADAPTER_ID
        assert row["model"] == "X10DRT-PS"
        assert row["logout_path"] == "/cgi/logout.cgi"
        assert poc_capability.parse_protocol_versions(row["protocol_versions"]) == ("RFB 003.008",)
        approved = store.approve_capability(
            entry["id"], actor="operator", approver="operator",
            evidence="docs/implementation/evidence/real-bmc-passthrough-e2e-20261112.json",
            licence="同源代理转发", console_impl="AST2100 / iKVM HTML5",
            expires=time.time() + 86400, review_due=time.time() + 86400)
        assert approved["status"] == "verified"
    finally:
        store.close()



def test_assembly_is_ready_and_never_exposes_the_credential(world):
    with transaction(world.factory) as db:
        result = connection.assembly(db, asset_id=world.ids["asset"],
                                     user_id=world.ids["admin"], actor="admin")
    assert result["ready"] is True and result["delivery"] == "worker_bridge"
    assert result["plan"]["rfb_version"] == "RFB 003.008"
    assert result["plan"]["message_profile"] == "insyde"
    assert result["data_plane"]["capability_entry"]["logout_path"] == "/cgi/logout.cgi"
    assert result["checks"] == {"profile": "approved", "capability": "verified",
                                "credential": "by_id_only"}
    assert result["credential_id"] == world.ids["credential"]
    assert BMC_PASSWORD not in str(result) and "ADMIN" not in str(result)


def test_viewer_without_a_grant_cannot_assemble(world):
    with transaction(world.factory) as db:
        _refused(lambda: connection.assembly(db, asset_id=world.ids["asset"],
                                             user_id=world.ids["viewer"], actor="viewer"),
                 "asset_not_granted")


@pytest.mark.parametrize("gate,expected", [
    ("profile_missing", "profile_missing"),
    ("profile_draft", "profile_not_approved"),
    ("profile_overdue", "profile_review_overdue"),
    ("capability_missing", "capability_not_verified"),
    ("capability_draft", "capability_not_verified"),
    ("capability_expired", "capability_expired"),
    ("capability_mismatch", "profile_capability_mismatch"),
    ("credential_missing", "credential_missing"),
])
def test_each_gate_closes_the_assembly(world, gate, expected):
    with transaction(world.factory) as db:
        asset = db.get(Asset, world.ids["asset"])
        profile = connection.approved_profile(db, PROFILE_CODE)
        cap = db.get(Capability, world.ids["capability"])
        if gate == "profile_missing":
            asset.profile_id = None
        elif gate == "profile_draft":
            profile.status = "draft"
        elif gate == "profile_overdue":
            profile.review_due = time.time() - 1
        elif gate == "capability_missing":
            asset.capability_id = None
        elif gate == "capability_draft":
            cap.status = "draft"
        elif gate == "capability_expired":
            cap.expires = time.time() - 1
        elif gate == "capability_mismatch":
            other = db.scalar(select(VendorProfile).where(VendorProfile.code != PROFILE_CODE))
            cap.profile_id = other.id
        elif gate == "credential_missing":
            asset.credential_id = None
        db.flush()
        _refused(lambda: connection.assembly(db, asset_id=asset.id,
                                             user_id=world.ids["admin"], actor="admin"),
                 expected)



def login(c: TestClient, password=ADMIN_PASSWORD):
    r = c.post("/api/v2/login", json={"username": "admin", "password": password})
    assert r.status_code == 200, r.text
    return {"Origin": ORIGIN, "X-CSRF-Token": r.json()["csrf"]}


def test_http_assembly_returns_the_plan_without_secrets(world):
    with TestClient(create_app(world.cfg, state=MemoryState()), base_url=ORIGIN) as c:
        headers = login(c)
        r = c.post("/api/v2/consoles/assembly", headers=headers,
                   json={"asset_id": world.ids["asset"]})
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["ready"] is True
        assert body["plan"]["rfb_version"] == "RFB 003.008"
        assert body["data_plane"]["capability_entry"]["logout_path"] == "/cgi/logout.cgi"
        assert BMC_PASSWORD not in r.text and "username_cipher" not in r.text


def test_http_asset_rename_preserves_bindings_and_remains_assemblable(world):
    with TestClient(create_app(world.cfg, state=MemoryState()), base_url=ORIGIN) as c:
        headers = login(c)
        r = c.post("/api/v2/assets", headers=headers,
                   json={"name": "renamed", "address": "192.0.2.11"})
        assert r.status_code == 200, r.text
        with transaction(world.factory) as db:
            asset = db.get(Asset, world.ids["asset"])
            assert asset.capability_id == world.ids["capability"]
            assert asset.profile_id == world.ids["profile"]
            assert asset.credential_id == world.ids["credential"]
            assert asset.vendor == MANUFACTURER and asset.model == "X10DRT-PS"
        r = c.post("/api/v2/consoles/assembly", headers=headers,
                   json={"asset_id": world.ids["asset"]})
        assert r.status_code == 200 and r.json()["ready"] is True


@pytest.mark.parametrize("change", [
    {"capability_id": None}, {"model": "different-model"},
    {"firmware": "9.00"}, {"vendor": "different-vendor"}, {"profile_id": None},
])
def test_http_asset_identity_change_or_explicit_clear_requires_reverification(world, change):
    with TestClient(create_app(world.cfg, state=MemoryState()), base_url=ORIGIN) as c:
        headers = login(c)
        r = c.post("/api/v2/assets", headers=headers,
                   json={"name": "node-1", "address": "192.0.2.11", **change})
        assert r.status_code == 200, r.text
        with transaction(world.factory) as db:
            assert db.get(Asset, world.ids["asset"]).capability_id is None
        r = c.post("/api/v2/consoles/assembly", headers=headers,
                   json={"asset_id": world.ids["asset"]})
        assert r.status_code == 409


def test_http_assembly_refuses_an_unknown_asset(world):
    with TestClient(create_app(world.cfg, state=MemoryState()), base_url=ORIGIN) as c:
        r = c.post("/api/v2/consoles/assembly", headers=login(c),
                   json={"asset_id": str(uuid.uuid4())})
        assert r.status_code == 409 and r.json()["error"] == "asset_not_granted"


def test_viewer_cannot_call_the_assembly_endpoint(world):
    with TestClient(create_app(world.cfg, state=MemoryState()), base_url=ORIGIN) as c:
        r = c.post("/api/v2/login", json={"username": "viewer", "password": VIEWER_PASSWORD})
        headers = {"Origin": ORIGIN, "X-CSRF-Token": r.json()["csrf"]}
        r = c.post("/api/v2/consoles/assembly", headers=headers,
                   json={"asset_id": world.ids["asset"]})
        assert r.status_code == 403 and r.json()["error"] == "permission_denied"
