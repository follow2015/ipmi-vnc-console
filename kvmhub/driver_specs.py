"""Immutable implementation descriptions, never device authorization."""
from dataclasses import dataclass
from types import MappingProxyType

from .common import (ATEN_JAVA_ADAPTER_ID, HUAWEI_IBMC_KVM_GATEWAY_ID,
                     HUAWEI_IBMC_VNC_ADAPTER_ID, IDRAC_VNC_ADAPTER_ID,
                     PASSTHROUGH_ADAPTER_ID)


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


def freeze_specs(specs):
    result = {}
    implementations = set()
    for spec in specs:
        if spec.id in result or (spec.console_impl is not None
                                 and spec.console_impl in implementations):
            raise ValueError("duplicate driver or console implementation")
        result[spec.id] = spec
        if spec.console_impl is not None:
            implementations.add(spec.console_impl)
    return MappingProxyType(result)


DRIVERS = freeze_specs((
    DriverSpec("mock-v1", None, "insyde18", False, "mock", connection_limit=4),
    DriverSpec(PASSTHROUGH_ADAPTER_ID, "passthrough", "insyde18", True, "upstream", supports_upstream_recovery=True),
    DriverSpec(IDRAC_VNC_ADAPTER_ID, IDRAC_VNC_ADAPTER_ID, "standard8", True,
               "local_novnc", controlled_network=True, vendor_layout_check=False, login_budget=28.0),
    DriverSpec(HUAWEI_IBMC_VNC_ADAPTER_ID, HUAWEI_IBMC_VNC_ADAPTER_ID, "standard8", True,
               "local_novnc", controlled_network=True, vendor_layout_check=False, login_budget=28.0),
    DriverSpec(HUAWEI_IBMC_KVM_GATEWAY_ID, HUAWEI_IBMC_KVM_GATEWAY_ID, "standard8", True,
               "local_novnc", controlled_network=True, login_budget=35.0),
    DriverSpec(ATEN_JAVA_ADAPTER_ID, ATEN_JAVA_ADAPTER_ID, "insyde18", True,
               "local_novnc", controlled_network=True, login_budget=26.0),
))
REAL_ADAPTER_IDS = frozenset(key for key, spec in DRIVERS.items() if spec.real_console)
CONSOLE_DRIVERS = MappingProxyType({spec.console_impl: spec.id for spec in DRIVERS.values()
                                   if spec.console_impl is not None})


def spec_for_adapter(adapter) -> DriverSpec | None:
    return DRIVERS.get(getattr(adapter, "adapter_id", ""))
