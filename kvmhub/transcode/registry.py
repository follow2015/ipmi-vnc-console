"""Build-time static plugin manifest. No hot load, no dynamic import."""
from __future__ import annotations

from types import MappingProxyType

from ..common import Problem
from .ast2100 import Ast2100Family
from .contract import API_VERSION, PluginSpec
from .huawei import HuaweiFamily
from .standard_rfb import StandardRfbFamily

_ROOT = 'kvmhub/transcode'

PLUGINS = MappingProxyType({
    spec.family: spec for spec in (
        PluginSpec('huawei-kvm-v1', '1.0.0', 'kvmhub.transcode.huawei',
                   f'{_ROOT}/huawei.py',
                   '53339f690eb35cc622547fb0462dbefd9702791fc39948b73ec5ff41c8cf8d54'),
        PluginSpec('standard-rfb-v1', '1.0.0', 'kvmhub.transcode.standard_rfb',
                   f'{_ROOT}/standard_rfb.py',
                   '9e040a9948ebe8f4d5dd813513bfc3c655b1c7f22f488fd918d0274cc118454e'),
        PluginSpec('ast2100-x10', '0.0.0', 'kvmhub.transcode.ast2100',
                   f'{_ROOT}/ast2100.py',
                   'ba4e5330a78ad9f52568f49e2ce56e2b256d876defb571618f47f7751b2d3b0f',
                   detects='ast2100'),
    )
})

_FACTORIES = MappingProxyType({
    'huawei-kvm-v1': HuaweiFamily,
    'standard-rfb-v1': StandardRfbFamily,
    'ast2100-x10': Ast2100Family,
})


def verify(root) -> None:
    for spec in PLUGINS.values():
        spec.check_source(root)


def select(family, observation=None):
    spec = PLUGINS.get(family)
    if spec is None or spec.api_version != API_VERSION:
        raise Problem('transcode_family_unsupported', 503)
    if observation is not None and spec.detects:
        detector = getattr(_FACTORIES[family], 'detect', None)
        if detector is not None and not detector(observation):
            raise Problem('transcode_family_unsupported', 503)
    return spec


def build(family, root, observation=None):
    spec = select(family, observation)
    factory = _FACTORIES[family]
    if not getattr(factory, 'available', True):
        raise Problem('transcode_family_unsupported', 503)
    verify(root)
    return factory()
