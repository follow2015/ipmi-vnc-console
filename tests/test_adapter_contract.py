"""Adapter contract and the discovery-only Supermicro X10 adapter."""
import inspect

import pytest

from kvmhub import adapter_contract as contract
from kvmhub.adapters import SupermicroX10IKVMAdapter
from kvmhub.adapter_contract import (
    ADAPTERS,
    ENABLED_ADAPTER_IDS,
    AdapterDiscoveryError,
    AdapterPolicyError,
    AdapterUnavailable,
    is_enabled,
)
from kvmhub import store as store_module

MANAGER = {
    "Model": "ASPEED",
    "FirmwareVersion": "8.78",
    "GraphicalConsole": {"ServiceEnabled": True, "ConnectTypesSupported": ["KVMIP"]},
    "Oem": {"Supermicro": {"MouseMode": {"Mode": "Absolute"}}},
}
NETWORK = {"KVMIP": {"ProtocolEnabled": True, "Port": 5900}}
CHASSIS = {"Model": "X10DRT-PS"}
WEB_UI = {"java_route": True}


def evidence(**overrides):
    base = {"manager": MANAGER, "network_protocol": NETWORK,
            "chassis": CHASSIS, "web_ui": WEB_UI}
    base.update(overrides)
    return base


def adapter():
    return SupermicroX10IKVMAdapter()


def test_only_mock_adapter_is_enabled():
    assert ENABLED_ADAPTER_IDS == frozenset({"mock-v1"})
    assert is_enabled("mock-v1") is True
    assert is_enabled(SupermicroX10IKVMAdapter.adapter_id) is False
    assert is_enabled("supermicro-x10-passthrough") is False
    assert ADAPTERS[SupermicroX10IKVMAdapter.adapter_id] is SupermicroX10IKVMAdapter
    assert SupermicroX10IKVMAdapter.capability_status == "unverified"
    source = inspect.getsource(store_module)
    assert "passthrough_targets: tuple[str, ...] = ()" in source
    assert "PASSTHROUGH_ADAPTER_ID" in source


def test_discover_returns_measured_capability_key():
    result = adapter().discover(evidence())
    assert result.vendor == "Supermicro (Inspur OEM)"
    assert result.model == "X10DRT-PS"
    assert result.firmware == "8.78"
    assert result.kvm_service_port == 5900
    assert result.candidate_consoles == ("ikvm-html5-novnc-ast2100", "java-jviewer-jnlp")
    assert "AST2100" in result.console_implementation
    assert any("independently" in item for item in result.unconfirmed)
    assert len(result.evidence) >= 6


def test_discover_is_pure_and_does_not_open_sockets():
    first = adapter().discover(evidence())
    second = adapter().discover(evidence())
    assert first == second
    assert isinstance(first.evidence, tuple) and isinstance(first.unconfirmed, tuple)


@pytest.mark.parametrize("bad", [
    evidence(manager={}),
    evidence(network_protocol={}),
    evidence(manager={**MANAGER, "GraphicalConsole": {"ServiceEnabled": False, "ConnectTypesSupported": ["KVMIP"]}}),
    evidence(manager={**MANAGER, "GraphicalConsole": {"ServiceEnabled": True, "ConnectTypesSupported": []}}),
    evidence(network_protocol={"KVMIP": {"ProtocolEnabled": False, "Port": 5900}}),
    evidence(network_protocol={"KVMIP": {"ProtocolEnabled": True, "Port": 99999}}),
    evidence(network_protocol={"KVMIP": {"ProtocolEnabled": True, "Port": True}}),
    evidence(manager={**MANAGER, "Oem": {}}),
    evidence(manager={**MANAGER, "FirmwareVersion": ""}),
])
def test_discover_rejects_unmatched_evidence(bad):
    with pytest.raises(AdapterDiscoveryError):
        adapter().discover(bad)


def test_console_spec_matches_on_device_measurement():
    spec = adapter().console_spec()
    assert spec.websocket_scheme == "wss"
    assert spec.websocket_port == 443, "HTML5 client uses 443, not the KVMIP 5900 service port"
    assert spec.websocket_binary is True
    assert spec.websocket_path == "/"
    assert spec.entry_path.endswith("man_ikvm_html5_bootstrap")
    assert "AST2100" in spec.codec and "055.008" in spec.codec
    assert "never sent to browser" in spec.upstream_auth or "reaches the browser" in spec.upstream_auth
    assert "scheme 16" in spec.upstream_auth
    assert "logout.cgi" in spec.close_rule and "cleanup=ok" in spec.close_rule
    assert spec.max_frame_bytes == 1024 * 1024


def test_rewrite_request_drops_browser_credentials_and_sets_upstream_origin():
    spec = adapter().console_spec()
    headers = {"Cookie": "platform_sid=abc", "Authorization": "Basic xxx",
               "X-Auth-Token": "secret", "X-CSRF-Token": "csrf",
               "Host": "attacker.example", "Origin": "https://worker.example",
               "Referer": "https://worker.example/page", "Accept": "text/html"}
    clean = adapter().rewrite_request(
        "GET", spec.entry_path, headers, upstream_host="192.0.2.11",
        browser_origin="https://worker.example", expected_origin="https://worker.example")
    assert "Cookie" not in clean and "Authorization" not in clean
    assert "X-Auth-Token" not in clean and "X-CSRF-Token" not in clean
    assert "Referer" not in clean
    assert clean["Host"] == "192.0.2.11"
    assert clean["Origin"] == "https://192.0.2.11"
    assert clean["Accept"] == "text/html"


@pytest.mark.parametrize("method,path,origin,headers", [
    ("DELETE", "/cgi/url_redirect.cgi?url_name=man_ikvm_html5_bootstrap", "https://worker.example", {}),
    ("GET", "/cgi/url_redirect.cgi?url_name=man_chassis", "https://worker.example", {}),
    ("GET", "/cgi/url_redirect.cgi?url_name=config_port", "https://worker.example", {}),
    ("GET", "/cgi/url_redirect.cgi?url_name=man_ikvm_html5_auto", "https://worker.example", {}),
    ("POST", "/cgi/ipmi.cgi", "https://worker.example", {}),
    ("POST", "/cgi/url_redirect.cgi?url_name=man_chassis", "https://worker.example", {}),
    ("GET", "/novnc/include/rfb.js", "https://evil.example", {}),
    ("GET", "/../etc/passwd", "https://worker.example", {}),
    ("GET", "/novnc/include/rfb.js", "https://worker.example", {"Sec-WebSocket-Key": "x"}),
])
def test_rewrite_request_denies_out_of_policy_requests(method, path, origin, headers):
    with pytest.raises(AdapterPolicyError):
        adapter().rewrite_request(method, path, headers, upstream_host="192.0.2.11",
                                  browser_origin=origin, expected_origin="https://worker.example")


def test_rewrite_request_allows_static_console_assets():
    clean = adapter().rewrite_request(
        "GET", "/novnc/include/rfb.js", {}, upstream_host="192.0.2.11",
        browser_origin="https://worker.example", expected_origin="https://worker.example")
    assert clean["Host"] == "192.0.2.11"


def test_post_is_allowed_only_on_the_login_endpoint():
    spec = adapter().console_spec()
    clean = adapter().rewrite_request(
        "POST", spec.login_path, {"Content-Type": "application/x-www-form-urlencoded"},
        upstream_host="192.0.2.11", browser_origin="https://worker.example",
        expected_origin="https://worker.example")
    assert clean["Host"] == "192.0.2.11"
    assert spec.entry_path in spec.allowed_exact_paths
    assert "/cgi/" not in spec.allowed_path_prefixes, "broad CGI prefix would expose power/config pages"


def test_rewrite_response_absorbs_upstream_auth_material():
    headers = [("Set-Cookie", "bmc_session=abc; Path=/"), ("Set-Cookie", "lang=en; Path=/"),
               ("X-Auth-Token", "secret"), ("Authorization", "Basic xxx"),
               ("Content-Type", "text/html"), ("Cache-Control", "no-store")]
    out, absorbed = adapter().rewrite_response(headers, upstream_host="192.0.2.11")
    assert len(absorbed) == 2
    assert [k for k, _ in out] == ["Content-Type", "Cache-Control"]
    assert all(k.lower() not in contract.RESPONSE_AUTH_HEADERS for k, _ in out)


def test_rewrite_response_accepts_same_host_redirect_only():
    ok = adapter().rewrite_response([("Location", "/cgi/url_redirect.cgi?url_name=mainmenu")],
                                    upstream_host="192.0.2.11")
    assert ok[0] == [("Location", "/cgi/url_redirect.cgi?url_name=mainmenu")]
    same = adapter().rewrite_response([("Location", "https://192.0.2.11/cgi/login.cgi")],
                                      upstream_host="192.0.2.11")
    assert len(same[0]) == 1
    for bad in ("https://evil.example/x", "//evil.example/x", "http://192.0.2.11/x"):
        with pytest.raises(AdapterPolicyError):
            adapter().rewrite_response([("Location", bad)], upstream_host="192.0.2.11")


@pytest.mark.parametrize("operation", ["authenticate", "open_console", "keepalive", "logout"])
def test_data_plane_is_explicitly_unavailable(operation):
    with pytest.raises(AdapterUnavailable) as exc:
        getattr(adapter(), operation)()
    assert exc.value.operation == operation
    assert "adapter_capability" in str(exc.value)
