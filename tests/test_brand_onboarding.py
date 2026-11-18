"""New-brand onboarding stays a draft-only, evidence-bound workflow."""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy import select

from kvmhub.platform import brand_onboarding, services
from kvmhub.platform.db import init_schema, make_engine, seed_roles, session_factory, transaction
from kvmhub.platform.models import PROFILE_DRAFT, AuditLog, Capability, VendorProfile
from tools import platform_admin

KEY = b"0123456789abcdef0123456789abcdef"


@pytest.fixture
def factory(tmp_path):
    engine = make_engine(f"sqlite:///{tmp_path / 'brand.sqlite3'}")
    init_schema(engine)
    result = session_factory(engine)
    with transaction(result) as db:
        seed_roles(db)
    return result


def measured(tmp_path: Path, *, code: str = "acme-x9-rfb003008") -> tuple[dict, Path]:
    evidence = tmp_path / "acme-measured.json"
    evidence.write_text('{"measurements": ["rfb", "input"]}', encoding="utf-8")
    spec = {
        "code": code, "vendor": "ACME", "vendor_aliases": ["ACME Corp"],
        "model_pattern": r"(?i)X9", "firmware_min": "1.0", "firmware_max": "2.9",
        "rfb_version": "RFB 003.008", "message_profile": "standard",
        "asset_paths": ["/novnc/*.js"], "login_path": "/cgi/login.cgi",
        "logout_path": "/cgi/logout.cgi", "console_impl": "passthrough",
        "licence": "measured KVM", "concurrency_limit": 1, "priority": 120,
    }
    return spec, evidence


def inventory() -> dict:
    return {"inventory": {"resources": {"Managers": [{
        "Id": "1", "Manufacturer": "ACME Corp", "Model": "X9-BMC",
        "FirmwareVersion": "2.1"}]}}}


def args_for(tmp_path: Path, spec: Path, evidence: Path, inv: Path, **extra):
    values = {"spec": str(spec), "inventory": str(inv), "evidence": str(evidence),
              "greeting": "", "actor": "ops", "env_file": None}
    values.update(extra)
    return SimpleNamespace(**values)


def test_validate_spec_rejects_typos_and_missing_evidence(tmp_path):
    spec, evidence = measured(tmp_path)
    assert brand_onboarding.validate_spec(spec, evidence=str(evidence))["vendor_aliases"] == [
        "ACME", "ACME Corp"]

    bad = dict(spec, message_profile="insyd")
    with pytest.raises(brand_onboarding.SpecError, match="message_profile"):
        brand_onboarding.validate_spec(bad, evidence=str(evidence))
    bad = dict(spec, model_pattern="[")
    with pytest.raises(brand_onboarding.SpecError, match="model_pattern"):
        brand_onboarding.validate_spec(bad, evidence=str(evidence))
    bad = dict(spec, console_impl="executable-adapter")
    with pytest.raises(brand_onboarding.SpecError, match="console_impl"):
        brand_onboarding.validate_spec(bad, evidence=str(evidence))
    with pytest.raises(brand_onboarding.SpecError, match="evidence"):
        brand_onboarding.validate_spec(spec, evidence=str(tmp_path / "absent.json"))


def test_create_profile_only_creates_a_draft_and_audits_it(factory, tmp_path, capsys):
    spec_data, evidence = measured(tmp_path)
    spec = tmp_path / "spec.json"
    spec.write_text(json.dumps(spec_data), encoding="utf-8")
    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(platform_admin, "_context",
                        lambda args: (None, None, factory, None))
    try:
        platform_admin.cmd_create_profile(args_for(
            tmp_path, spec, evidence, tmp_path / "unused.json", actor="ops"))
    finally:
        monkeypatch.undo()
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == PROFILE_DRAFT and result["approver"] == ""
    assert "approve-profile" in result["approve_command"]

    with transaction(factory) as db:
        row = db.scalar(select(VendorProfile).where(VendorProfile.code == spec_data["code"]))
        assert row is not None and row.status == PROFILE_DRAFT
        assert row.evidence == str(evidence)
        actions = [r.action for r in db.scalars(select(AuditLog)).all()]
        assert "vendor_profile_draft_created" in actions

        with pytest.raises(brand_onboarding.SpecError, match="exists"):
            brand_onboarding.create_draft_profile(
                db, spec=spec_data, evidence=str(evidence), actor="ops")


def test_brand_onboard_prepares_drafts_and_hands_out_commands(factory, tmp_path, capsys):
    spec_data, evidence = measured(tmp_path)
    spec = tmp_path / "spec.json"
    spec.write_text(json.dumps(spec_data), encoding="utf-8")
    inv = tmp_path / "inventory.json"
    inv.write_text(json.dumps(inventory()), encoding="utf-8")

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(platform_admin, "_context",
                        lambda args: (None, None, factory, None))
    try:
        platform_admin.cmd_brand_onboard(args_for(tmp_path, spec, evidence, inv))
    finally:
        monkeypatch.undo()
    result = json.loads(capsys.readouterr().out)
    assert result["profile_created"] is True
    assert result["profile"]["status"] == PROFILE_DRAFT
    assert result["capability"]["status"] == "draft"
    assert result["match"]["matched"] is True
    commands = "\n".join(result["commands"])
    assert "approve-profile" in commands and "approve-capability" in commands
    assert "sync-data-plane" in commands

    with transaction(factory) as db:
        assert db.scalar(select(Capability)) is not None
        actions = [r.action for r in db.scalars(select(AuditLog)).all()]
        assert {"vendor_profile_draft_created", "capability_draft_created",
                "brand_onboard_prepared"}.issubset(actions)

    monkeypatch.setattr(platform_admin, "_context",
                        lambda args: (None, None, factory, None))
    try:
        platform_admin.cmd_brand_onboard(args_for(tmp_path, spec, evidence, inv))
    finally:
        monkeypatch.undo()
    second = json.loads(capsys.readouterr().out)
    assert second["profile_created"] is False
    assert second["capability"]["id"] != result["capability"]["id"]
    with transaction(factory) as db:
        assert len(db.scalars(select(VendorProfile).where(
            VendorProfile.code == spec_data["code"])).all()) == 1


def test_brand_onboard_refuses_wrong_inventory_without_leaving_a_profile(factory, tmp_path):
    spec_data, evidence = measured(tmp_path)
    spec = tmp_path / "spec.json"
    spec.write_text(json.dumps(spec_data), encoding="utf-8")
    inv = tmp_path / "inventory.json"
    inv.write_text(json.dumps({"inventory": {"resources": {"Managers": [{
        "Id": "1", "Manufacturer": "Other Corp", "Model": "Z1",
        "FirmwareVersion": "2.1"}]}}}), encoding="utf-8")

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(platform_admin, "_context",
                        lambda args: (None, None, factory, None))
    try:
        with pytest.raises(SystemExit, match="did not match"):
            platform_admin.cmd_brand_onboard(args_for(tmp_path, spec, evidence, inv))
    finally:
        monkeypatch.undo()

    with transaction(factory) as db:
        assert db.scalar(select(VendorProfile)) is None
        assert db.scalar(select(Capability)) is None
        assert db.scalar(select(AuditLog)) is None


def test_profile_matches_spec_blocks_silent_code_reuse(factory, tmp_path):
    spec_data, evidence = measured(tmp_path)
    with transaction(factory) as db:
        profile = brand_onboarding.create_draft_profile(
            db, spec=spec_data, evidence=str(evidence), actor="ops")
        assert brand_onboarding.profile_matches_spec(profile, spec_data, evidence=str(evidence))
        drifted = dict(spec_data, rfb_version="RFB 055.008")
        assert not brand_onboarding.profile_matches_spec(profile, drifted, evidence=str(evidence))
