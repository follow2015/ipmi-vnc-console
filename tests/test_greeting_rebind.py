"""Measured RFB greeting decides which profile a device belongs to."""
from __future__ import annotations

import base64
import json
import time
import uuid
from types import SimpleNamespace

import pytest
from sqlalchemy import select

from kvmhub.platform import connection, data_plane, services, vendor_registry
from kvmhub.platform.db import (init_schema, make_engine, seed_roles,
                                session_factory, transaction)
from kvmhub.platform.models import Asset, AuditLog, Capability, User, VendorProfile
from kvmhub.platform.security import CredentialCipher
from tools import platform_admin

KEY = b"0123456789abcdef0123456789abcdef"
PROFILE_003 = "smci-x10-ast2100-rfb003008"
PROFILE_055 = "smci-x10-ast2100-rfb055008"
DETECTION = {"vendor": "Supermicro (Inspur OEM)", "model": "SA5248M4", "firmware": "ASPEED 8.78"}


@pytest.fixture
def world(tmp_path):
    engine = make_engine(f"sqlite:///{tmp_path}/control.db")
    init_schema(engine)
    factory = session_factory(engine)
    with transaction(factory) as db:
        seed_roles(db)
        vendor_registry.seed_builtin_profiles(db)
        services.create_user(db, "admin", "synthetic-password", "admin", actor="test")
    yield SimpleNamespace(engine=engine, factory=factory, tmp=tmp_path)
    engine.dispose()


def test_both_greetings_are_builtin_and_the_x10_default_is_unchanged(world):
    with transaction(world.factory) as db:
        codes = {p.code: p for p in db.scalars(select(VendorProfile)).all()}
        assert PROFILE_003 in codes and PROFILE_055 in codes
        assert codes[PROFILE_055].rfb_version == "RFB 055.008"
        assert codes[PROFILE_055].message_profile == "smc"
        plain = vendor_registry.identify(db, DETECTION)
        assert plain.profile is not None and plain.profile.code == PROFILE_003


def test_measured_greeting_selects_the_matching_profile(world):
    with transaction(world.factory) as db:
        measured = vendor_registry.identify(db, DETECTION, greeting="RFB 055.008")
        assert measured.profile is not None and measured.profile.code == PROFILE_055
        assert measured.usable is False
        assert measured.reason == "matched_but_not_approved"

        same = vendor_registry.identify(db, DETECTION, greeting="RFB 003.008")
        assert same.profile is not None and same.profile.code == PROFILE_003


def test_rebind_mints_a_draft_that_cannot_open_until_approved(world, monkeypatch):
    with transaction(world.factory) as db:
        profile_055 = connection.approved_profile(db, PROFILE_055)
        profile_003 = connection.approved_profile(db, PROFILE_003)
        profile_003.status = "approved"
        profile_055.status = "approved"
        cred = services.save_credential(db, CredentialCipher(KEY), label="bmc-1", username="ADMIN",
                                        password="synthetic-password", actor="test")
        cap = Capability(id=str(uuid.uuid4()), vendor="Inspur", model="SA5248M4",
                         firmware="ASPEED 8.78", adapter="passthrough",
                         profile_id=profile_003.id, status="verified",
                         expires=time.time() + 86400, evidence="evidence.json",
                         approver="lab", protocol_versions='["RFB 003.008"]',
                         created=time.time())
        db.add(cap)
        db.flush()
        asset = services.upsert_asset(db, name="bmc-055", address="192.0.2.55",
                                      vendor="Inspur", model="SA5248M4",
                                      firmware="ASPEED 8.78", credential_id=cred.id,
                                      profile_id=profile_003.id, capability_id=cap.id,
                                      actor="test")
        asset_id = asset.id
        user_id = db.scalar(select(User.id).order_by(User.created))
        services.grant_asset(db, user_id=user_id, asset_id=asset_id, actor="test")

    monkeypatch.setenv("KVMHUB_DB_URL", f"sqlite:///{world.tmp}/control.db")
    monkeypatch.setenv("KVMHUB_CREDENTIAL_KEY", base64.b64encode(KEY).decode())
    args = SimpleNamespace(id=asset_id, profile=PROFILE_055, actor="lab-admin",
                           env_file=str(world.tmp / "absent.env"))
    platform_admin.cmd_rebind_asset(args)

    with transaction(world.factory) as db:
        asset = db.get(Asset, asset_id)
        profile = db.get(VendorProfile, asset.profile_id)
        draft = db.get(Capability, asset.capability_id)
        assert profile.code == PROFILE_055
        assert draft.status == "draft" and draft.profile_id == profile.id
        audit = [row for row in db.scalars(select(AuditLog).order_by(
            AuditLog.ts.desc())).all() if row.action == "asset_rebound"]
        assert audit and json.loads(audit[0].detail)["capability_id"] == draft.id

        with pytest.raises(connection.ConnectionRefused) as refused:
            connection.assembly(db, asset_id=asset_id, user_id=user_id, actor="test")
        assert refused.value.code == "capability_not_verified"

        draft.status = "verified"
        draft.expires = time.time() + 86400 * 30
        result = connection.assembly(db, asset_id=asset_id, user_id=user_id, actor="test")

    assert result["plan"]["rfb_version"] == "RFB 055.008"
    assert result["plan"]["message_profile"] == "smc"
    entry = result["data_plane"]["capability_entry"]
    assert entry["protocol_versions"] == ["RFB 055.008"]
    info = data_plane.assembled_info({}, result)
    assert info["rfb_version"] == "RFB 055.008" and info["message_profile"] == "smc"
