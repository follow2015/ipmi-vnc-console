"""One-shot real-BMC onboarding: pure planning logic, no network."""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from tools import onboard_probe as op


def probe_result(*, vendor="Supermicro (Inspur OEM)", model="X10DRT-PS",
                 firmware="8.78", greeting="RFB 055.008",
                 fingerprint="ab" * 32, host="192.0.2.11") -> dict:
    return {
        "inventory": {"resources": {
            "Managers": [{"Id": "1", "Manufacturer": vendor, "Model": model,
                          "FirmwareVersion": firmware}],
        }, "truncated": False},
        "greeting": greeting,
        "fingerprint": fingerprint,
        "host": host,
    }


def test_build_spec_maps_greeting_to_message_profile():
    spec, measured = op.build_spec(probe_result(greeting="RFB 055.008"), actor="auto-onboard")
    assert measured is True
    assert spec["rfb_version"] == "RFB 055.008"
    assert spec["message_profile"] == "smc"
    assert spec["code"] == "smci-x10-ast2100-rfb055008"
    assert spec["console_impl"] == "passthrough"
    assert spec["vendor"] == "supermicro"


def test_measured_spec_matches_builtin_wire_fields_for_idempotent_reuse():
    from kvmhub.platform import vendor_registry as v
    template = {p["rfb_version"]: p for p in v.BUILTIN_PROFILES}["RFB 055.008"]
    spec, measured = op.build_spec(probe_result(greeting="RFB 055.008"), actor="auto-onboard")
    assert measured is True
    wire = ("code", "vendor", "model_pattern", "rfb_version", "message_profile",
            "asset_paths", "login_path", "logout_path", "console_impl", "licence",
            "concurrency_limit", "priority")
    for field in wire:
        assert spec[field] == template[field], f"{field} drifted from builtin"
    assert spec["vendor_aliases"] == template["vendor_aliases"]


def test_build_spec_handles_the_other_measured_greeting():
    spec, _ = op.build_spec(probe_result(greeting="RFB 003.008"), actor="auto-onboard")
    assert spec["message_profile"] == "insyde"
    assert spec["code"] == "smci-x10-ast2100-rfb003008"


def test_build_spec_accepts_validate_spec_fields_only(tmp_path):
    from kvmhub.platform.brand_onboarding import validate_spec
    evidence = tmp_path / "measured.json"
    evidence.write_text("{}", encoding="utf-8")
    spec, _ = op.build_spec(probe_result(), actor="auto-onboard")
    fields = validate_spec(spec, evidence=str(evidence))
    assert fields["code"] == spec["code"]
    assert fields["message_profile"] == "smc"


def test_build_spec_marks_unknown_vendor_as_unmeasured():
    spec, measured = op.build_spec(
        probe_result(vendor="ACME", model="M1", firmware="1.0", greeting="RFB 099.099"),
        actor="auto-onboard")
    assert measured is False
    assert spec["vendor"] == "acme"
    assert spec["code"].startswith("acme-")
    assert "_measured" not in spec


def test_evidence_is_json_serialisable_and_carries_no_secret():
    evidence = op.build_evidence(probe_result(), actor="auto-onboard")
    assert "BMC_USER" not in json.dumps(evidence)
    assert "password" not in json.dumps(evidence).lower()
    assert evidence["fingerprint"].startswith("ab")
    assert evidence["recorded_by"] == "auto-onboard"


def test_plan_has_approval_after_draft_and_sync_last():
    steps = op.plan_steps(asset_id="a1", profile_id="p1", capability_id="c1",
                          credential_id="k1", approver="auto-onboard")
    verbs = [s["verb"] for s in steps]
    assert verbs.index("approve-profile") > verbs.index("brand-onboard")
    assert verbs.index("approve-capability") > verbs.index("brand-onboard")
    assert verbs[-1] == "sync-data-plane"
    assert all(s["actor"] == "auto-onboard" for s in steps)


def test_read_inventory_prefers_basic_auth_when_sessions_are_rejected(monkeypatch):
    from demos import redfish_probe as rp

    calls = []

    class FakeBasicClient:
        def __init__(self, *a, **k):
            calls.append(("init_basic", k.get("basic_auth")))
        def json(self, path):
            calls.append(("json", path))
            return {"RedfishVersion": "test"}
        def login(self, *a):
            calls.append(("login", a))
            raise AssertionError("must not create a session in basic mode")
        def logout(self):
            calls.append(("logout",))

    def fake_inventory(client, root, n):
        calls.append(("inventory", n))
        return {"resources": {"Managers": [{"Model": "iDRAC"}]}}

    monkeypatch.setattr(rp, "Redfish", lambda *a, **k: FakeBasicClient(*a, **k))
    monkeypatch.setattr(rp, "inventory", fake_inventory)
    monkeypatch.setenv("BMC_USER", "root")
    monkeypatch.setenv("BMC_PASSWORD", "calvin")
    args = SimpleNamespace(host="192.0.2.84", port=443, timeout=5)
    inv, mode, _ = op._read_inventory(args, "ab" * 32)
    assert mode == "basic" and inv["resources"]["Managers"][0]["Model"] == "iDRAC"
    assert calls[0] == ("init_basic", ("root", "calvin"))
    assert not any(c[0] in ("login", "logout") for c in calls)
    assert "calvin" not in json.dumps(inv)


def test_measure_greeting_degrades_to_unmeasured_without_leaking_session(monkeypatch):
    events = []

    class FakeUpstream:
        def __init__(self, cfg):
            self.cfg = cfg
        async def login(self, u, p):
            events.append("login")
            raise type("Problem", (Exception,), {"code": "bmc_auth_failed"})()
        async def open(self):
            events.append("open")
        async def close(self):
            events.append("close")

    args = SimpleNamespace(host="192.0.2.84", port=443, timeout=5)
    monkeypatch.setenv("BMC_USER", "root")
    monkeypatch.setenv("BMC_PASSWORD", "calvin")
    greeting, error = op._measure_greeting(args, "ab" * 32, make_upstream=lambda cfg: FakeUpstream(cfg))
    assert greeting == ""
    assert error == "bmc_auth_failed"
    assert events == ["login", "close"]


def test_measure_greeting_returns_version_and_closes(monkeypatch):
    events = []

    class FakeUpstream:
        def __init__(self, cfg):
            self.cfg = cfg
            self.protocol_version = "RFB 055.008"
        async def login(self, u, p):
            events.append("login")
        async def open(self):
            events.append("open")
        async def close(self):
            events.append("close")

    args = SimpleNamespace(host="x", port=443, timeout=5)
    monkeypatch.setenv("BMC_USER", "root")
    monkeypatch.setenv("BMC_PASSWORD", "calvin")
    greeting, error = op._measure_greeting(args, "ab" * 32, make_upstream=lambda cfg: FakeUpstream(cfg))
    assert greeting == "RFB 055.008" and error == ""
    assert events == ["login", "open", "close"]


def test_read_inventory_uses_session_when_basic_rejected(monkeypatch):
    from demos import redfish_probe as rp

    calls = []

    class FakeBasicClient:
        def __init__(self, *a, **k):
            calls.append(("init_basic", k.get("basic_auth")))
        def json(self, path):
            raise rp.RedfishError("http_401")

    class FakeSessionClient:
        def __init__(self, *a, **k):
            calls.append(("init_session",))
        def json(self, path):
            return {"RedfishVersion": "test"}
        def login(self, *a):
            calls.append(("login", a))
        def logout(self):
            calls.append(("logout",))

    def fake_inventory(client, root, n):
        calls.append(("inventory",))
        return {"resources": {"Managers": []}}

    monkeypatch.setattr(rp, "Redfish", lambda *a, **k: FakeBasicClient(*a, **k) if k.get("basic_auth") else FakeSessionClient(*a, **k))
    monkeypatch.setattr(rp, "inventory", fake_inventory)
    monkeypatch.setenv("BMC_USER", "root")
    monkeypatch.setenv("BMC_PASSWORD", "calvin")
    args = SimpleNamespace(host="192.0.2.84", port=443, timeout=5)
    inv, mode, _ = op._read_inventory(args, "ab" * 32)
    assert mode == "session" and inv["resources"]["Managers"] == []
    assert ("login", ("root", "calvin")) in calls
    assert ("logout",) in calls
