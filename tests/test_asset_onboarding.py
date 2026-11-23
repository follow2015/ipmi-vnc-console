"""Brand-driven asset entry: one approved source, auto-fill, no self-approval."""
from __future__ import annotations

import time
import uuid

import pytest
from fastapi.testclient import TestClient

from kvmhub.platform import services, vendor_registry
from kvmhub.platform.api import create_app
from kvmhub.platform.config import Settings
from kvmhub.platform.db import init_schema, seed_roles, session_factory, transaction
from kvmhub.platform.models import Capability, VendorProfile
from kvmhub.platform.redis_state import MemoryState

KEY = b"0123456789abcdef0123456789abcdef"
ORIGIN = "http://testserver"
ADMIN_PASSWORD = "synthetic-password"
APPROVED_CODE = "smci-x10-ast2100-rfb003008"


@pytest.fixture
def world(tmp_path):
    cfg = Settings(env="test", db_url=f"sqlite:///{tmp_path}/control.db", redis_url="",
                   credential_key=KEY, session_ttl=3600, lease_seconds=30,
                   bootstrap_admin=None, bootstrap_password=None, strict_prod=False)
    app = create_app(cfg, state=MemoryState())
    platform = app.state.platform
    with transaction(platform.factory) as db:
        init_schema(platform.engine)
        seed_roles(db)
        vendor_registry.seed_builtin_profiles(db)
        services.create_user(db, "admin", ADMIN_PASSWORD, "admin", actor="test")
        approved = db.query(VendorProfile).filter(VendorProfile.code == APPROVED_CODE).one()
        approved.status = "approved"
        approved.review_due = time.time() + 86400 * 365
        approved.licence = "授权许可：内置 VNC"
        profile_id = approved.id
        cap = Capability(id=str(uuid.uuid4()), vendor=approved.vendor, model="X10DRT-PS",
                         firmware="8.78", adapter="passthrough", profile_id=profile_id,
                         status="verified", expires=time.time() + 86400 * 365,
                         evidence="evidence.json", approver="test", console_impl="passthrough",
                         licence="授权许可：内置 VNC", created=time.time())
        db.add(cap)
        db.flush()
        cap_id = cap.id
    with TestClient(app, base_url=ORIGIN) as c:
        r = c.post("/api/v2/login", json={"username": "admin", "password": ADMIN_PASSWORD})
        assert r.status_code == 200, r.text
        csrf = r.json()["csrf"]
        yield c, {"csrf": csrf, "profile_id": profile_id, "cap_id": cap_id}, platform
    platform.engine.dispose()


def _headers(world):
    c, ids, _ = world
    return {"Origin": ORIGIN, "X-CSRF-Token": ids["csrf"]}


def test_onboarding_lists_only_approved_profiles(world):
    c, ids, platform = world
    body = c.get("/api/v2/asset-onboarding").json()
    codes = {b["code"] for b in body["brands"]}
    assert APPROVED_CODE in codes
    assert len(body["brands"]) == 1, body["brands"]
    assert body["note"]


def test_onboarding_carries_autofill_defaults(world):
    c, ids, platform = world
    brand = c.get("/api/v2/asset-onboarding").json()["brands"][0]
    assert brand["profile_id"] == ids["profile_id"]
    assert brand["licence"] == "授权许可：内置 VNC"
    assert brand["default_capability_id"] == ids["cap_id"]
    assert brand["capabilities"][0]["id"] == ids["cap_id"]
    assert brand["capabilities"][0]["status"] == "verified"
    assert brand["certificate_mode"] in ("env_pin", "asset_fingerprint")


def test_asset_post_autofills_from_brand(world):
    c, ids, _ = world
    r = c.post("/api/v2/assets", headers=_headers(world),
               json={"name": "node-1", "address": "192.0.2.31",
                     "profile_id": ids["profile_id"]})
    assert r.status_code == 200, r.text
    asset = r.json()
    assert asset["licence"] == "授权许可：内置 VNC"
    assert asset["capability_id"] == ids["cap_id"]
    assert asset["vendor"]


def test_asset_post_rejects_draft_profile(world):
    c, ids, platform = world
    with transaction(platform.factory) as db:
        draft = db.query(VendorProfile).filter(VendorProfile.status == "draft").first()
        draft_id = draft.id
    r = c.post("/api/v2/assets", headers=_headers(world),
               json={"name": "bad", "address": "192.0.2.32", "profile_id": draft_id})
    assert r.status_code == 400
    assert r.json()["error"] == "profile_not_approved"


def test_asset_post_rejects_unknown_profile(world):
    c, ids, _ = world
    r = c.post("/api/v2/assets", headers=_headers(world),
               json={"name": "bad", "address": "192.0.2.33", "profile_id": str(uuid.uuid4())})
    assert r.status_code == 400
    assert r.json()["error"] == "profile_not_found"


def test_overdue_profile_is_not_offered_nor_bindable(world):
    c, ids, platform = world
    with transaction(platform.factory) as db:
        profile = db.query(VendorProfile).filter(VendorProfile.id == ids["profile_id"]).one()
        profile.review_due = time.time() - 1
    body = c.get("/api/v2/asset-onboarding").json()
    assert body["brands"] == []
    r = c.post("/api/v2/assets", headers=_headers(world),
               json={"name": "bad", "address": "192.0.2.34", "profile_id": ids["profile_id"]})
    assert r.status_code == 400
    assert r.json()["error"] == "profile_review_overdue"


def test_legacy_asset_without_profile_still_works(world):
    c, ids, _ = world
    r = c.post("/api/v2/assets", headers=_headers(world),
               json={"name": "bare", "address": "192.0.2.35", "vendor": "acme"})
    assert r.status_code == 200, r.text
    assert r.json()["name"] == "bare"


def test_edit_changing_identity_clears_capability_even_if_posted(world):
    c, ids, _ = world
    asset = c.post("/api/v2/assets", headers=_headers(world),
                   json={"name": "node-1", "address": "192.0.2.36",
                         "profile_id": ids["profile_id"]}).json()
    assert asset["capability_id"] == ids["cap_id"]
    edit = c.post("/api/v2/assets", headers=_headers(world), json={
        "id": asset["id"], "name": asset["name"], "address": asset["address"],
        "profile_id": ids["profile_id"],
        "vendor": asset["vendor"], "model": "CHANGED-MODEL",
        "firmware": asset["firmware"],
        "capability_id": ids["cap_id"],
    })
    assert edit.status_code == 200, edit.text
    assert edit.json()["capability_id"] is None
