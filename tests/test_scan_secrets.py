"""scan-secrets: fixtures-allowed — 本文件刻意构造内网地址样本，全仓扫密时跳过。"""
import importlib.util
import pathlib

import pytest

_PATH = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "scan-secrets.py"
_SPEC = importlib.util.spec_from_file_location("scan_secrets", _PATH)
scan = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(scan)


_ASSET_SHAPED = "10.100.1" + ".11"


@pytest.mark.parametrize("ip", [
    _ASSET_SHAPED, "10.20.30.40", "192.168.7.9", "172.16.5.4", "172.31.0.9",
    "169.254.1.1", "100.64.0.9",
])
def test_private_addresses_are_not_safe(ip):
    assert not scan.is_safe_ip(ip)


@pytest.mark.parametrize("ip", [
    "192.0.2.11", "198.51.100.7", "203.0.113.5", "127.0.0.1", "10.0.0.1", "8.8.8.8",
])
def test_documentation_and_well_known_addresses_stay_safe(ip):
    assert scan.is_safe_ip(ip)
