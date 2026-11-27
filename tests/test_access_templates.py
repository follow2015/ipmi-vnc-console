"""Access model invariants: a brand is data, a template is code."""
from __future__ import annotations

import json

import pytest

from kvmhub.adapters.huawei_ibmc_vnc import HuaweiIbmcVncAdapter
from kvmhub.adapters.idrac_vnc import IdracVncAdapter
from kvmhub.adapters.rfb_relay import RfbRelayAdapter
from kvmhub.common import (HUAWEI_IBMC_VNC_ADAPTER_ID, IDRAC_VNC_ADAPTER_ID,
                           RFB_RELAY_ADAPTER_ID, Problem)
from kvmhub.driver_factory import FACTORIES, make_adapter
from kvmhub.driver_specs import (DRIVERS, LEGACY_RELAY_PROFILES, DriverSpec,
                                 freeze_specs, parse_access_params,
                                 resolve_adapter)
from kvmhub.platform import connection
from kvmhub.platform.models import PROFILE_APPROVED, VendorProfile

NETWORKS = ["192.0.2.0/16"]


def _profile(**overrides) -> VendorProfile:
    fields = dict(
        code="acme-bmc-v5", vendor="Acme", model_pattern=r"^Acme BMC.*$",
        firmware_min="", firmware_max="", rfb_version="RFB 003.008",
        message_profile="standard", console_impl=RFB_RELAY_ADAPTER_ID,
        access_params=json.dumps({"port": 5911, "tls": "pinned",
                                  "pin_source": "asset_then_env",
                                  "encodings": [0]}),
        protocol="", licence="", concurrency_limit=1,
        input_shaping="{}", status=PROFILE_APPROVED, evidence="synthetic",
    )
    fields.update(overrides)
    return VendorProfile(**fields)



def test_registry_is_keyed_by_template_not_by_brand():
    for brand in LEGACY_RELAY_PROFILES:
        assert brand not in DRIVERS
        assert resolve_adapter(brand) == RFB_RELAY_ADAPTER_ID
    assert FACTORIES[RFB_RELAY_ADAPTER_ID] is RfbRelayAdapter
    for cls in (IdracVncAdapter, HuaweiIbmcVncAdapter):
        assert issubclass(cls, RfbRelayAdapter)
        for method in ("login", "connect", "close", "fetch_asset"):
            assert method not in cls.__dict__, f"{cls.__name__} re-implements {method}"


def test_relay_brands_share_one_lifecycle():
    for cls in (IdracVncAdapter, HuaweiIbmcVncAdapter, RfbRelayAdapter):
        assert cls.login is RfbRelayAdapter.login
        assert cls.connect is RfbRelayAdapter.connect
        assert cls.close is RfbRelayAdapter.close


def test_legacy_brand_rows_keep_their_measured_parameters(monkeypatch):
    monkeypatch.setenv("KVMHUB_BMC_ALLOWED_NETWORKS", NETWORKS[0])
    dell = make_adapter({"adapter": IDRAC_VNC_ADAPTER_ID,
                         "target": "https://192.0.2.84"})
    assert type(dell) is RfbRelayAdapter
    assert (dell.port, dell.tls, dell.client_encodings) == (5901, "none", (0, 1))

    huawei = HuaweiIbmcVncAdapter(
        {"adapter": HUAWEI_IBMC_VNC_ADAPTER_ID, "target": "https://192.0.2.234",
         "fingerprint": "ab" * 32}, networks=NETWORKS)
    assert (huawei.port, huawei.tls, huawei.pin) == (5900, "pinned", "ab" * 32)


def test_idrac_adapter_keeps_raw_first_and_plaintext():
    adapter = IdracVncAdapter(
        {"adapter": IDRAC_VNC_ADAPTER_ID, "target": "https://192.0.2.84"},
        networks=NETWORKS)
    assert (adapter.port, adapter.tls, adapter.pin) == (5901, "none", "")
    assert adapter.client_encodings == (0, 1)



def test_a_new_relay_brand_needs_only_profile_data():
    entry = connection.capability_entry(
        _profile(), detection={"model": "Acme BMC 9000",
                               "raw": {"Manufacturer": "Acme"}})
    assert entry["adapter"] == RFB_RELAY_ADAPTER_ID
    assert entry["console_impl"] == RFB_RELAY_ADAPTER_ID

    adapter = RfbRelayAdapter(
        {"adapter": entry["adapter"], "target": "https://192.0.2.9",
         "fingerprint": "ab" * 32,
         "access_params": {"port": 5911, "tls": "pinned",
                           "pin_source": "asset_then_env", "encodings": [0]}},
        networks=NETWORKS)
    assert (adapter.port, adapter.tls, adapter.client_encodings) == (5911, "pinned", (0,))
    assert adapter.pin == "ab" * 32


def test_relay_profile_without_a_port_is_refused():
    with pytest.raises(connection.ConnectionRefused) as exc:
        connection.capability_entry(
            _profile(access_params="{}"),
            detection={"model": "Acme BMC 9000", "raw": {"Manufacturer": "Acme"}})
    assert exc.value.code == "access_params_missing"


def test_relay_without_any_port_fails_closed_at_construction():
    with pytest.raises(Problem) as exc:
        RfbRelayAdapter({"adapter": RFB_RELAY_ADAPTER_ID,
                         "target": "https://192.0.2.9"}, networks=NETWORKS)
    assert exc.value.code == "access_params_missing"


def test_a_legacy_brand_row_needs_no_new_parameters():
    entry = connection.capability_entry(
        _profile(code="dell-idrac8-vnc", console_impl=IDRAC_VNC_ADAPTER_ID,
                 access_params="{}"),
        detection={"model": "PowerEdge R740", "raw": {"Manufacturer": "Dell"}})
    assert entry["adapter"] == RFB_RELAY_ADAPTER_ID
    assert LEGACY_RELAY_PROFILES[IDRAC_VNC_ADAPTER_ID]["port"] == 5901



def test_access_params_reject_unknown_or_unsafe_values():
    with pytest.raises(ValueError, match="unknown access parameter"):
        parse_access_params({"pasword": "x"})
    with pytest.raises(ValueError, match="access port"):
        parse_access_params({"port": 0})
    with pytest.raises(ValueError, match="pin source"):
        parse_access_params({"port": 5901, "tls": "none",
                             "pin_source": "asset_then_env"})
    with pytest.raises(ValueError, match="encodings"):
        parse_access_params({"port": 5901, "encodings": [99]})


def test_spec_rejects_a_plaintext_link_with_a_pin_source():
    with pytest.raises(ValueError, match="pin source"):
        freeze_specs([DriverSpec("x-vnc", "x-vnc", "standard8", True, "local_novnc",
                                 tls="none", pin_source="asset_then_env")])


def test_spec_rejects_an_out_of_range_port():
    with pytest.raises(ValueError, match="relay port"):
        freeze_specs([DriverSpec("x-vnc", "x-vnc", "standard8", True, "local_novnc",
                                 port=70000)])



def test_data_plane_store_keeps_access_params(tmp_path):
    from kvmhub.store import Store

    store = Store(tmp_path / "relay.sqlite", b"k" * 32,
                  clock=lambda: 2_000_000_000.0)
    try:
        store.register_capability({
            "id": "cap-acme", "vendor": "Acme", "model": "BMC 9000",
            "firmware": "1.0", "adapter": RFB_RELAY_ADAPTER_ID,
            "models": ["BMC 9000"], "firmware_min": "", "firmware_max": "",
            "protocol_versions": ["RFB 003.008"], "input_shaping": {},
            "logout_path": "",
            "access_params": {"port": 5911, "tls": "pinned",
                              "pin_source": "asset_then_env", "encodings": [0]},
        }, "test")
        stored = store.capability("cap-acme")
        assert json.loads(stored["access_params"]) == {
            "port": 5911, "tls": "pinned", "pin_source": "asset_then_env",
            "encodings": [0]}
    finally:
        store.close()


def test_retarget_moves_an_old_row_to_the_template_without_a_new_revision(tmp_path):
    from kvmhub.store import Store

    store = Store(tmp_path / "retarget.sqlite", b"k" * 32,
                  clock=lambda: 2_000_000_000.0)
    try:
        store.register_capability({
            "id": "cap-dell", "vendor": "Dell", "model": "PowerEdge R740",
            "firmware": "3.89", "adapter": IDRAC_VNC_ADAPTER_ID,
            "models": ["PowerEdge R740"], "firmware_min": "", "firmware_max": "",
            "protocol_versions": ["RFB 003.008"], "input_shaping": {},
            "logout_path": "", "access_params": {},
        }, "test")
        before = store.capability("cap-dell")["revision"]
        assert store.retarget_capability(
            "cap-dell", adapter=RFB_RELAY_ADAPTER_ID,
            access_params=dict(LEGACY_RELAY_PROFILES[IDRAC_VNC_ADAPTER_ID])) is True
        after = store.capability("cap-dell")
        assert after["adapter"] == RFB_RELAY_ADAPTER_ID
        assert json.loads(after["access_params"])["port"] == 5901
        assert after["revision"] == before
        assert store.retarget_capability(
            "cap-dell", adapter=RFB_RELAY_ADAPTER_ID,
            access_params=dict(LEGACY_RELAY_PROFILES[IDRAC_VNC_ADAPTER_ID])) is False
    finally:
        store.close()


def test_data_plane_store_rejects_an_invalid_parameter_set(tmp_path):
    from kvmhub.store import Store

    store = Store(tmp_path / "bad.sqlite", b"k" * 32,
                  clock=lambda: 2_000_000_000.0)
    try:
        with pytest.raises(Problem) as exc:
            store.register_capability({
                "id": "cap-bad", "vendor": "Acme", "model": "BMC 9000",
                "firmware": "1.0", "adapter": RFB_RELAY_ADAPTER_ID,
                "models": ["BMC 9000"], "firmware_min": "", "firmware_max": "",
                "protocol_versions": ["RFB 003.008"], "input_shaping": {},
                "logout_path": "",
                "access_params": {"port": 5911, "tls": "none",
                                  "pin_source": "asset_then_env"},
            }, "test")
        assert exc.value.code == "capability_incomplete"
    finally:
        store.close()
