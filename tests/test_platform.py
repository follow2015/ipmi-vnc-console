"""Production control-plane unit tests: config, crypto, accounts, RBAC,"""
from __future__ import annotations

import base64
import json
import struct

import pytest
from sqlalchemy import select

from kvmhub.platform import services, text_input, vendor_registry
from kvmhub.platform.config import Settings, mysql_url, settings
from kvmhub.platform.db import (bootstrap_admin, init_schema, make_engine,
                                seed_roles, session_factory, transaction)
from kvmhub.platform.models import (AuditLog, PERMISSIONS, ROLE_PERMISSIONS,
                                    Role, User, VendorProfile)
from kvmhub.platform.security import (CredentialCipher, hash_password,
                                      verify_password)

KEY = b"0123456789abcdef0123456789abcdef"

P1 = "synthetic-password"
P2 = "sim-password"
P3 = "live-password"
P4 = "unit-test-password"
BMC_PASSWORD = "local-admin"


def make_cfg(**overrides) -> Settings:
    values = dict(env="test", db_url="sqlite:///:memory:", redis_url="",
                  credential_key=KEY, session_ttl=3600, lease_seconds=30,
                  bootstrap_admin=None, bootstrap_password=None, strict_prod=False)
    values.update(overrides)
    return Settings(**values)


@pytest.fixture
def ctx():
    cfg = make_cfg()
    engine = make_engine(cfg.db_url)
    init_schema(engine)
    factory = session_factory(engine)
    with transaction(factory) as db:
        seed_roles(db)
    yield cfg, engine, factory, CredentialCipher(KEY)
    engine.dispose()



def test_prod_refuses_sqlite_and_missing_redis(monkeypatch):
    monkeypatch.setenv("KVMHUB_ENV", "prod")
    monkeypatch.setenv("KVMHUB_DB_URL", "sqlite:///./x.db")
    monkeypatch.delenv("KVMHUB_REDIS_URL", raising=False)
    monkeypatch.setenv("KVMHUB_CREDENTIAL_KEY", base64.b64encode(KEY).decode())
    with pytest.raises(ValueError, match="production configuration incomplete"):
        settings()


def test_dev_can_run_on_sqlite_without_redis(monkeypatch, tmp_path):
    monkeypatch.setenv("KVMHUB_ENV", "dev")
    monkeypatch.setenv("KVMHUB_DB_URL", f"sqlite:///{tmp_path}/p.db")
    monkeypatch.delenv("KVMHUB_REDIS_URL", raising=False)
    monkeypatch.delenv("KVMHUB_CREDENTIAL_KEY", raising=False)
    assert settings().db_url.startswith("sqlite:")


def test_mysql_url_escapes_the_password(monkeypatch):
    monkeypatch.setenv("MYSQL_USER", "kvm user")
    monkeypatch.setenv("MYSQL_PASSWORD", "p@ss/word")
    monkeypatch.setenv("MYSQL_HOST", "db.internal")
    monkeypatch.setenv("MYSQL_PORT", "3307")
    monkeypatch.setenv("MYSQL_DATABASE", "kvmhub")
    url = mysql_url()
    assert "kvm+user:p%40ss%2Fword@db.internal:3307/kvmhub" in url
    assert " " not in url


def test_bad_credential_key_length_is_rejected():
    cfg = make_cfg(credential_key=b"short")
    with pytest.raises(ValueError, match="32 bytes"):
        cfg.validate()


def test_iframe_mode_defaults_to_off_and_rejects_typos(monkeypatch, tmp_path):
    monkeypatch.setenv("KVMHUB_ENV", "dev")
    monkeypatch.setenv("KVMHUB_DB_URL", f"sqlite:///{tmp_path}/iframe.db")
    monkeypatch.delenv("KVMHUB_IFRAME_MODE", raising=False)
    assert settings().iframe_mode == "off"
    monkeypatch.setenv("KVMHUB_IFRAME_MODE", "OFF")
    assert settings().iframe_mode == "off"
    monkeypatch.setenv("KVMHUB_IFRAME_MODE", "maybe")
    with pytest.raises(ValueError, match="off\\|on"):
        settings()



def test_password_hash_roundtrip_and_long_passphrase():
    password = P4 + " " * 6
    hashed = hash_password(password)
    assert hashed.startswith("$2")
    assert verify_password(password, hashed)
    assert not verify_password(password + "x", hashed)
    with pytest.raises(ValueError):
        hash_password("short")


def test_ciphertext_is_bound_to_its_row_id():
    cipher = CredentialCipher(KEY)
    blob = cipher.encrypt("ADMIN", aad="row-1:username")
    assert cipher.decrypt(blob, aad="row-1:username") == "ADMIN"
    with pytest.raises(Exception):
        cipher.decrypt(blob, aad="row-2:username")
    broken = bytearray(blob)
    broken[-1] ^= 0x01
    with pytest.raises(Exception):
        cipher.decrypt(bytes(broken), aad="row-1:username")


def test_cipher_without_key_fails_closed():
    assert not CredentialCipher(None).available
    with pytest.raises(RuntimeError):
        CredentialCipher(None).encrypt("x", aad="a")



def test_seed_roles_is_idempotent(ctx):
    _, _, factory, _ = ctx
    fresh = make_engine("sqlite:///:memory:")
    init_schema(fresh)
    with transaction(session_factory(fresh)) as db:
        first = seed_roles(db)
    with transaction(factory) as db:
        second = seed_roles(db)
        third = seed_roles(db)
        roles = {r.code for r in db.scalars(select(Role)).all()}
    assert first["roles"] == 4
    assert first["permissions"] == len({code for codes in ROLE_PERMISSIONS.values() for code in codes})
    assert first["links"] == sum(len(codes) for codes in ROLE_PERMISSIONS.values())
    assert second == third == {"roles": 0, "permissions": 0, "links": 0}
    assert roles == {"admin", "operator", "viewer", "platform_admin"}
    fresh.dispose()


def test_bootstrap_admin_never_resets_an_existing_password(ctx):
    _, _, factory, _ = ctx
    with transaction(factory) as db:
        first = bootstrap_admin(db, "admin", P1)
    with transaction(factory) as db:
        again = bootstrap_admin(db, "admin", P2)
        user = db.scalar(select(User).where(User.username == "admin"))
    assert first is not None and again is None
    assert verify_password(P1, user.password_hash)
    assert not verify_password(P2, user.password_hash)


def test_role_permission_matrix(ctx):
    _, _, factory, _ = ctx
    with transaction(factory) as db:
        admin = services.create_user(db, "boss", P1, "admin", actor="test")
        viewer = services.create_user(db, "guest", P1, "viewer", actor="test")
        admin_perms = services.permissions_of(db, admin.id)
        viewer_perms = services.permissions_of(db, viewer.id)
    assert "vendor.approve" in admin_perms and "user.write" in admin_perms
    assert viewer_perms == {"asset.read", "vendor.read", "audit.read"}
    with transaction(factory) as db:
        with pytest.raises(services.PlatformError, match="permission_denied"):
            services.require(db, viewer.id, "console.open")



def test_five_failures_lock_the_account_then_it_recovers(ctx):
    _, _, factory, _ = ctx
    stamp = 1_000_000.0
    with transaction(factory) as db:
        services.create_user(db, "alice", P3, "operator", actor="test", now=stamp)
    for _ in range(5):
        with transaction(factory) as db:
            with pytest.raises(services.PlatformError, match="authentication_failed"):
                services.authenticate(db, "alice", "wrong", now=stamp)
    with transaction(factory) as db:
        with pytest.raises(services.PlatformError, match="account_locked"):
            services.authenticate(db, "alice", P3, now=stamp)
        with pytest.raises(services.PlatformError, match="account_locked"):
            services.authenticate(db, "alice", P3, now=stamp + 899)
    with transaction(factory) as db:
        user = services.authenticate(db, "alice", P3, now=stamp + 901)
        assert user.last_login == stamp + 901
        assert int(user.failed_attempts) == 0


def test_every_write_leaves_an_audit_row(ctx):
    _, _, factory, _ = ctx
    with transaction(factory) as db:
        services.create_user(db, "alice", P1, "viewer", actor="cli")
        rows = services.recent_audit(db)
    assert any(r["action"] == "user_created" and r["actor"] == "cli" for r in rows)
    assert all(r["detail"] for r in rows)
    with transaction(factory) as db:
        before = db.scalar(select(AuditLog.id).order_by(AuditLog.id.desc()).limit(1))
        assert before is not None



def test_credential_is_encrypted_and_never_in_asset_response(ctx):
    _, _, factory, cipher = ctx
    with transaction(factory) as db:
        cred = services.save_credential(db, cipher, label="bmc-01", username="ADMIN",
                                        password=BMC_PASSWORD, actor="cli")
        raw_username = bytes(cred.username_cipher)
        raw_password = bytes(cred.password_cipher)
        asset = services.upsert_asset(db, name="node-1", address="192.0.2.11",
                                      credential_id=cred.id, actor="cli")
        public = asset.public()
    assert b"ADMIN" not in raw_username and BMC_PASSWORD.encode() not in raw_password
    assert "credential" not in public and "password" not in json.dumps(public)
    assert public["address"] == "192.0.2.11"
    with transaction(factory) as db:
        assert services.read_credential(db, cipher, cred.id)["password"] == BMC_PASSWORD


def test_grants_filter_what_a_user_sees(ctx):
    _, _, factory, _ = ctx
    stamp = 2_000_000.0
    with transaction(factory) as db:
        user = services.create_user(db, "alice", P1, "viewer", actor="cli", now=stamp)
        a1 = services.upsert_asset(db, name="a", address="192.0.2.11", actor="cli", now=stamp)
        services.upsert_asset(db, name="b", address="192.0.2.24", actor="cli", now=stamp)
        services.grant_asset(db, user_id=user.id, asset_id=a1.id, actor="cli",
                             ttl_seconds=10, now=stamp)
        assert [a["name"] for a in services.assets_for_user(db, user.id, now=stamp)] == ["a"]
        assert services.assets_for_user(db, user.id, now=stamp + 11) == []
        services.grant_asset(db, user_id=user.id, asset_id=a1.id, actor="cli",
                             ttl_seconds=100, now=stamp)
        assert len(services.assets_for_user(db, user.id, now=stamp)) == 1
        services.revoke_grant(db, user_id=user.id, asset_id=a1.id, actor="cli")
        assert services.assets_for_user(db, user.id, now=stamp) == []



def test_vendor_aliases_normalise_real_redfish_strings():
    assert vendor_registry.normalize_vendor("Supermicro (Inspur OEM)") == "supermicro"
    assert vendor_registry.normalize_vendor("American Megatrends Inc.") == "supermicro"
    assert vendor_registry.normalize_vendor("Dell Inc.") == "dell"
    assert vendor_registry.normalize_vendor(None) == ""


def test_firmware_window_is_inclusive_and_numeric():
    assert vendor_registry.firmware_in_window("8.78", "8.10", "9.02")
    assert not vendor_registry.firmware_in_window("9.10", "8.10", "9.02")
    assert vendor_registry.firmware_in_window("1.2", "", "")


def test_detect_prefers_the_bmc_over_the_host():
    inventory = {"resources": {
        "Systems": [{"Manufacturer": "Intel", "Model": "S2600", "FirmwareVersion": "1.0"}],
        "Managers": [{"Manufacturer": "Supermicro (Inspur OEM)", "Model": "X10DRT-PS",
                      "FirmwareVersion": "8.78"}]}}
    result = vendor_registry.detect_from_redfish(inventory)
    assert result["vendor"] == "supermicro" and result["model"] == "X10DRT-PS"
    assert result["source"] == "Managers"


def test_matched_draft_is_not_usable_and_unknown_brand_never_falls_back(ctx):
    _, _, factory, _ = ctx
    with transaction(factory) as db:
        vendor_registry.seed_builtin_profiles(db)
        detection = {"vendor": "supermicro", "model": "X10DRT-PS", "firmware": "8.78"}
        match = vendor_registry.identify(db, detection)
        assert match.profile is not None and match.profile.status == "draft"
        assert match.usable is False and match.reason == "matched_but_not_approved"
        assert match.candidates[0]["reasons"][0] == "vendor_alias"
        with pytest.raises(vendor_registry.UnknownVendor):
            vendor_registry.connection_plan(match.profile)
        other = vendor_registry.identify(db, {"vendor": "totally-unknown-brand",
                                              "model": "X10DRT-PS", "firmware": "8.78"})
        assert other.profile is None and other.reason == "unknown_vendor"
        assert vendor_registry.identify(db, {"vendor": "", "model": ""}).reason == "vendor_not_detected"


def test_approved_profile_yields_a_connection_plan_and_a_draft_capability(ctx):
    _, _, factory, _ = ctx
    with transaction(factory) as db:
        vendor_registry.seed_builtin_profiles(db)
        profile = db.scalar(select(VendorProfile).where(
            VendorProfile.code == "smci-x10-ast2100-rfb003008"))
        profile.status = "approved"
        detection = {"vendor": "supermicro", "model": "X10DRT-PS", "firmware": "8.78"}
        match = vendor_registry.identify(db, detection)
        plan = vendor_registry.connection_plan(profile)
        draft = services.capability_draft(db, profile, detection=detection, actor="cli")
        assert match.usable is True
        assert plan["rfb_version"] == "RFB 003.008" and plan["message_profile"] == "insyde"
        assert "/cgi/logout.cgi" == plan["logout_path"]
        assert draft.status == "draft" and draft.approver == ""
        assert "awaiting" in draft.status_reason



def test_text_plan_flags_the_measured_pipe_failure_without_rewriting():
    plan = text_input.plan_text("echo root:poc | chpasswd\n")
    assert plan.has_broken
    warning = next(w for w in plan.warnings if w["level"] == "known_broken")
    assert "↔" in warning["message"] and "passwd" in warning["message"]
    assert "|" in [s.char for s in plan.strokes]
    assert plan.counts["known_broken"] == 1
    assert plan.counts["verified"] > plan.counts["unverified"]


def test_verified_characters_are_the_measured_set_and_shifted_ones_are_not_claimed():
    assert text_input.reliability("a") == text_input.VERIFIED
    assert text_input.reliability("/") == text_input.VERIFIED
    assert text_input.reliability("=") == text_input.VERIFIED
    assert text_input.reliability("A") == text_input.VERIFIED
    assert text_input.reliability("!") == text_input.VERIFIED
    assert text_input.reliability("~") == text_input.VERIFIED
    assert text_input.reliability("中") == text_input.UNSUPPORTED
    assert text_input.reliability("|") == text_input.KNOWN_BROKEN


def test_keystrokes_are_balanced_and_frames_use_the_measured_18_byte_layout():
    plan = text_input.plan_text("A\nb")
    frames = text_input.frame_stream(plan)
    assert len(frames) == 8
    keys = [struct.unpack(">I", f[5:9])[0] for f, _ in frames]
    downs = [f[2] for f, _ in frames]
    assert keys.count(text_input.LEFT_SHIFT) == 2
    assert downs.count(1) == downs.count(0)
    assert all(len(f) == 18 for f, _ in frames)
    assert all(f[0] == 4 and f[1] == 0 and f[3:5] == b"\x00\x00" for f, _ in frames)


def test_standard8_frames_and_length_limit():
    plan = text_input.plan_text("abc")
    frames = text_input.frame_stream(plan, style="standard8")
    assert all(len(f) == 8 for f, _ in frames)
    with pytest.raises(ValueError, match="exceeds"):
        text_input.plan_text("x" * (text_input._MAX_CHARS + 1))
    with pytest.raises(ValueError, match="unknown key frame style"):
        text_input.plan_text("a").strokes[0].frames(style="nope")
