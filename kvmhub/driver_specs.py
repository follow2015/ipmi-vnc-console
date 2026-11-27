"""Immutable implementation descriptions, never device authorization."""
from dataclasses import dataclass
from types import MappingProxyType

from .common import (ATEN_JAVA_ADAPTER_ID, HUAWEI_IBMC_KVM_GATEWAY_ID,
                     HUAWEI_IBMC_VNC_ADAPTER_ID, IDRAC_VNC_ADAPTER_ID,
                     PASSTHROUGH_ADAPTER_ID, RFB_RELAY_ADAPTER_ID)

ACCESS_PARAM_KEYS = frozenset({"port", "tls", "pin_source", "encodings"})
TLS_MODES = frozenset({"none", "pinned"})
PIN_SOURCES = frozenset({"", "asset_then_env"})


@dataclass(frozen=True)
class DriverSpec:

    id: str
    console_impl: str | None
    input_protocol: str
    real_console: bool
    client_bundle: str
    controlled_network: bool = False
    vendor_layout_check: bool = True
    connection_limit: int = 1
    login_budget: float = 10.0
    supports_upstream_recovery: bool = False
    port: int = 0
    tls: str = "none"
    pin_source: str = ""
    encodings: tuple[int, ...] | None = None
    translated_client: bool = False

    @property
    def access_defaults(self) -> dict:
        return {"port": self.port, "tls": self.tls,
                "pin_source": self.pin_source, "encodings": self.encodings}


def parse_access_params(raw) -> dict:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise ValueError("access_params must be an object")
    unknown = sorted(set(raw) - ACCESS_PARAM_KEYS)
    if unknown:
        raise ValueError(f"unknown access parameter: {unknown[0]}")
    result = {}
    if "port" in raw:
        port = raw["port"]
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise ValueError("access port must be an integer in 1..65535")
        result["port"] = port
    if "tls" in raw:
        tls = raw["tls"]
        if tls not in TLS_MODES:
            raise ValueError("unsupported tls mode")
        result["tls"] = tls
    if "pin_source" in raw:
        source = raw["pin_source"]
        if source not in PIN_SOURCES:
            raise ValueError("unsupported pin source")
        result["pin_source"] = source
    if "encodings" in raw:
        encodings = raw["encodings"]
        if encodings is not None:
            if (not isinstance(encodings, (list, tuple)) or not encodings
                    or any(isinstance(item, bool) or not isinstance(item, int)
                           or not 0 <= item <= 32 for item in encodings)):
                raise ValueError("encodings must be a non-empty list of 0..32")
            encodings = tuple(encodings)
        result["encodings"] = encodings
    if result.get("tls", "none") == "none" and result.get("pin_source"):
        raise ValueError("plaintext link cannot declare a pin source")
    return result


LEGACY_RELAY_PROFILES = MappingProxyType({
    IDRAC_VNC_ADAPTER_ID: MappingProxyType(
        {"port": 5901, "tls": "none", "pin_source": "", "encodings": (0, 1)}),
    HUAWEI_IBMC_VNC_ADAPTER_ID: MappingProxyType(
        {"port": 5900, "tls": "pinned", "pin_source": "asset_then_env",
         "encodings": None}),
})
ADAPTER_ALIASES = MappingProxyType({
    IDRAC_VNC_ADAPTER_ID: RFB_RELAY_ADAPTER_ID,
    HUAWEI_IBMC_VNC_ADAPTER_ID: RFB_RELAY_ADAPTER_ID,
})


def resolve_adapter(name) -> str:
    value = str(name or "").strip()
    return ADAPTER_ALIASES.get(value, value)


def relay_preset(console_impl) -> dict:
    return dict(LEGACY_RELAY_PROFILES.get(str(console_impl or "").strip(), {}))


def freeze_specs(specs):
    result = {}
    implementations = set()
    for spec in specs:
        if spec.id in result or (spec.console_impl is not None
                                 and spec.console_impl in implementations):
            raise ValueError("duplicate driver or console implementation")
        if spec.tls not in TLS_MODES:
            raise ValueError("unsupported tls mode")
        if not 0 <= spec.port <= 65535:
            raise ValueError("invalid relay port")
        if spec.tls == "none" and spec.pin_source:
            raise ValueError("plaintext driver cannot declare a pin source")
        result[spec.id] = spec
        if spec.console_impl is not None:
            implementations.add(spec.console_impl)
    return MappingProxyType(result)


DRIVERS = freeze_specs((
    DriverSpec("mock-v1", None, "insyde18", False, "mock", connection_limit=4),
    DriverSpec(PASSTHROUGH_ADAPTER_ID, "passthrough", "insyde18", True, "local_novnc",
               supports_upstream_recovery=True, translated_client=True),
    DriverSpec(RFB_RELAY_ADAPTER_ID, RFB_RELAY_ADAPTER_ID, "standard8", True,
               "local_novnc", controlled_network=True, vendor_layout_check=False,
               login_budget=28.0),
    DriverSpec(HUAWEI_IBMC_KVM_GATEWAY_ID, HUAWEI_IBMC_KVM_GATEWAY_ID, "standard8", True,
               "local_novnc", controlled_network=True, login_budget=35.0),
    DriverSpec(ATEN_JAVA_ADAPTER_ID, ATEN_JAVA_ADAPTER_ID, "insyde18", True,
               "local_novnc", controlled_network=True, login_budget=26.0),
))
REAL_ADAPTER_IDS = frozenset(key for key, spec in DRIVERS.items() if spec.real_console)
CONSOLE_DRIVERS = MappingProxyType({spec.console_impl: spec.id for spec in DRIVERS.values()
                                   if spec.console_impl is not None})
CONSOLE_IMPL_NAMES = frozenset(CONSOLE_DRIVERS) | frozenset(LEGACY_RELAY_PROFILES)


def spec_for_adapter(adapter) -> DriverSpec | None:
    return DRIVERS.get(resolve_adapter(getattr(adapter, "adapter_id", "")))
