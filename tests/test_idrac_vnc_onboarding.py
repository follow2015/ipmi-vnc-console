"""Onboarding automation for the iDRAC built-in VNC path."""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest
from sqlalchemy import select

from kvmhub.common import IDRAC_VNC_ADAPTER_ID
from kvmhub.platform import vendor_registry
from kvmhub.platform.db import init_schema, make_engine, session_factory
from kvmhub.platform.models import VendorProfile

KEY = b"0123456789abcdef0123456789abcdef"
TOOL_PATH = Path(__file__).resolve().parents[1] / "tools" / "idrac8_vnc_setup.py"


@pytest.fixture
def db_session(tmp_path):
    engine = make_engine(f"sqlite:///{tmp_path}/control.db")
    init_schema(engine)
    factory = session_factory(engine)
    session = factory()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


def _builtin(code: str) -> dict:
    for item in vendor_registry.BUILTIN_PROFILES:
        if item["code"] == code:
            return item
    raise AssertionError(f"{code} missing from BUILTIN_PROFILES")


def test_vnc_profile_is_builtin_and_well_formed():
    p = _builtin("dell-idrac-vnc-tcp")
    assert p["console_impl"] == IDRAC_VNC_ADAPTER_ID
    assert p["message_profile"] == "standard"
    assert p["rfb_version"] == "RFB 003.008"
    assert p["vendor"] == "dell"
    assert "iDRAC8" in p["model_pattern"]
    assert p["priority"] < 90


EVIDENCE = Path("docs/implementation/evidence/idrac8-vnc-tcp-20261120.json")
needs_evidence = pytest.mark.skipif(
    not EVIDENCE.is_file(), reason="private iDRAC real-device evidence is unpublished")


@needs_evidence
def test_vnc_profile_has_private_real_device_evidence():
    assert EVIDENCE.is_file()


def test_seed_installs_vnc_profile_as_draft(db_session):
    vendor_registry.seed_builtin_profiles(db_session)
    row = db_session.scalar(select(VendorProfile).where(VendorProfile.code == "dell-idrac-vnc-tcp"))
    assert row is not None
    assert row.status == "draft"


def test_identify_selects_vnc_profile_for_dell_idrac8(db_session):
    vendor_registry.seed_builtin_profiles(db_session)
    detection = {"vendor": "Dell Inc.", "model": "iDRAC8", "firmware": "3.89"}
    match = vendor_registry.identify(db_session, detection, greeting="RFB 003.008")
    assert match.profile is not None
    assert match.profile.code == "dell-idrac-vnc-tcp"
    assert not match.usable
    assert match.reason == "matched_but_not_approved"


def test_approved_vnc_profile_yields_plan_with_new_adapter(db_session):
    vendor_registry.seed_builtin_profiles(db_session)
    row = db_session.scalar(select(VendorProfile).where(VendorProfile.code == "dell-idrac-vnc-tcp"))
    row.status = "approved"
    db_session.flush()
    plan = vendor_registry.connection_plan(row)
    assert plan["console_impl"] == IDRAC_VNC_ADAPTER_ID
    assert plan["message_profile"] == "standard"
    assert plan["rfb_version"] == "RFB 003.008"



@pytest.fixture(scope="module")
def tool():
    if not TOOL_PATH.is_file():
        pytest.skip("internal RACADM tool is not published in the public repo")
    spec = importlib.util.spec_from_file_location("idrac8_vnc_setup", TOOL_PATH)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["idrac8_vnc_setup"] = mod
    spec.loader.exec_module(mod)
    return mod


def test_parse_vnc_config_masks_write_only_password(tool):
    text = ("[Key=idrac.Embedded.1#VNCServer.1]\r\n"
            "Enable=Enabled\r\n"
            "!!Password=******** (Write-Only)\r\n"
            "Port=5901\r\n"
            "Timeout=300\r\n")
    parsed = tool.parse_vnc_config(text)
    assert parsed["Enable"] == "Enabled"
    assert parsed["Port"] == "5901"
    assert parsed["Timeout"] == "300"
    assert parsed["Password"] == "<write-only>"


def test_parse_vnc_config_ignores_banners(tool):
    parsed = tool.parse_vnc_config("cmdstat\r\n  status : 0\r\nPort=5901\r\n")
    assert parsed == {"Port": "5901"}


def test_validate_host(tool):
    assert tool.validate_host("192.0.2.84") == "192.0.2.84"
    assert tool.validate_host("example.local") == "example.local"
    with pytest.raises(SystemExit):
        tool.validate_host("https://192.0.2.84")
    with pytest.raises(SystemExit):
        tool.validate_host("")
