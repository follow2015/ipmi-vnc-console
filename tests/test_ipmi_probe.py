"""IPMI fallback for BMCs that expose IPMI but no Redfish."""
from __future__ import annotations

import pytest

from kvmhub.platform import ipmi_probe


class FakeIpmi:
    def __init__(self):
        self.session = self
        self.target = None

    def set_session_type_rmcp(self, host, port=623):
        assert port == 623

    def set_auth_type_user(self, user, password):
        assert user and password

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def get_device_id(self):
        class Device:
            manufacturer_name = "Super Micro Computer"
            product_id = 2084
            fw_revision = "8.33"
        return Device()

    def get_fru_board_area(self, fru_id=0):
        if fru_id != 1:
            raise ValueError("empty FRU")

        class Board:
            product_name = "X10DRT-PT"
            manufacturer = "Supermicro"
        return Board()


def test_ipmi_identity_uses_device_id_and_fru(monkeypatch):
    fake = FakeIpmi()
    monkeypatch.setattr(ipmi_probe.pyipmi.interfaces, "create_interface", lambda *a, **k: object())
    monkeypatch.setattr(ipmi_probe.pyipmi, "create_connection", lambda itf: fake)
    out = ipmi_probe.probe_identity("192.0.2.60", "admin", "pw")
    manager = out["inventory"]["resources"]["Managers"][0]
    assert manager["Manufacturer"] == "Super Micro Computer"
    assert manager["Model"] == "X10DRT-PT"
    assert manager["FirmwareVersion"] == "8.33"
    assert out["fingerprint"] == ""


def test_ipmi_port_is_not_a_generic_probe_surface():
    with pytest.raises(ipmi_probe.IpmiProbeError) as exc:
        ipmi_probe.probe_identity("192.0.2.60", "admin", "pw", port=80)
    assert exc.value.code == "invalid_ipmi_port"
