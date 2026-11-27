"""Worker-only explicit executable factories. Registration grants no access."""
from types import MappingProxyType

from .adapter import MockAdapter
from .adapters.aten_java import AtenJavaAdapter
from .adapters.huawei_ibmc_kvm_gateway import HuaweiIbmcKvmGatewayAdapter
from .adapters.idrac_vnc import IdracVncAdapter
from .adapters.passthrough import PassthroughAdapter
from .adapters.rfb_relay import RfbRelayAdapter
from .common import Problem
from .driver_specs import (DRIVERS, REAL_ADAPTER_IDS, relay_preset,
                           resolve_adapter)

FACTORIES = MappingProxyType({cls.adapter_id: cls for cls in (
    MockAdapter, PassthroughAdapter, RfbRelayAdapter,
    HuaweiIbmcKvmGatewayAdapter, AtenJavaAdapter,
)})
REGISTRY_GAPS = tuple(sorted(set(REAL_ADAPTER_IDS) - set(FACTORIES)))
UNDECLARED_FACTORIES = tuple(sorted(set(FACTORIES) - set(DRIVERS)))


def make_adapter(info):
    raw = str(info.get("adapter") or "").strip()
    name = resolve_adapter(raw)
    factory = FACTORIES.get(name)
    if factory is None or name not in DRIVERS:
        raise Problem("adapter_not_verified", 403)
    payload = {**info, "adapter": name}
    preset = relay_preset(raw)
    if preset:
        payload["access_params"] = {**preset, **(info.get("access_params") or {})}
    return factory(payload)
