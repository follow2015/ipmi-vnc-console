"""Worker-only explicit executable factories. Registration grants no access."""
from types import MappingProxyType

from .adapter import MockAdapter
from .adapters.aten_java import AtenJavaAdapter
from .adapters.huawei_ibmc_kvm_gateway import HuaweiIbmcKvmGatewayAdapter
from .adapters.huawei_ibmc_vnc import HuaweiIbmcVncAdapter
from .adapters.idrac_vnc import IdracVncAdapter
from .adapters.passthrough import PassthroughAdapter
from .common import Problem
from .driver_specs import DRIVERS

FACTORIES = MappingProxyType({cls.adapter_id: cls for cls in (
    MockAdapter, PassthroughAdapter, IdracVncAdapter,
    HuaweiIbmcVncAdapter, HuaweiIbmcKvmGatewayAdapter, AtenJavaAdapter,
)})
if FACTORIES.keys() != DRIVERS.keys():
    raise RuntimeError("driver descriptions and executable factories disagree")


def make_adapter(info):
    factory = FACTORIES.get(info["adapter"])
    if factory is None:
        raise Problem("adapter_not_verified", 403)
    return factory(info)
