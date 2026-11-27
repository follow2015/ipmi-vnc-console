"""Build-time static plugin manifest. No hot load, no dynamic import."""
from __future__ import annotations

from types import MappingProxyType

from ..common import Problem
from .ast2100 import Ast2100Family
from .contract import API_VERSION, PluginSpec
from .huawei import HuaweiFamily
from .standard_rfb import StandardRfbFamily

_ROOT = 'kvmhub/transcode'

#: Only these families exist. Adding a file at runtime cannot register a plugin;
#: a new family requires a source change, a locked digest and a release.
PLUGINS = MappingProxyType({
    spec.family: spec for spec in (
        PluginSpec('huawei-kvm-v1', '1.0.0', 'kvmhub.transcode.huawei',
                   f'{_ROOT}/huawei.py',
                   '53339f690eb35cc622547fb0462dbefd9702791fc39948b73ec5ff41c8cf8d54'),
        PluginSpec('standard-rfb-v1', '1.0.0', 'kvmhub.transcode.standard_rfb',
                   f'{_ROOT}/standard_rfb.py',
                   '2858e83868b180f55e28e34686b6d803ecf05019249053b366d6f70a2b55c1a0'),
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


def verify(root, families=None) -> None:
    """Check locked source digests.

    With no argument this checks the whole manifest, which is what CI and the
    release gate want. A build checks only the family it selected: a broken or
    unavailable sibling family must not take down every other family at
    runtime. These digests only catch accidental edits and release transforms;
    they live in the same commit as the code, so they are not a supply-chain
    control and must never be described as one.
    """
    specs = (PLUGINS[name] for name in families) if families is not None else PLUGINS.values()
    for spec in specs:
        spec.check_source(root)


def select(family, observation=None):
    """Resolve a family from an explicit approval; never from observation alone."""
    spec = PLUGINS.get(family)
    if spec is None or spec.api_version != API_VERSION:
        raise Problem('transcode_family_unsupported', 503)
    if observation is not None and spec.detects:
        detector = getattr(_FACTORIES[family], 'detect', None)
        if detector is not None and not detector(observation):
            raise Problem('transcode_family_unsupported', 503)
    return spec


def build(family, root, observation=None):
    """Build an instance after digest verification; registry selection is mandatory."""
    spec = select(family, observation)
    factory = _FACTORIES[family]
    if not getattr(factory, 'available', True):
        raise Problem('transcode_family_unsupported', 503)
    # Only this family's bytes matter to this build. Verifying every plugin
    # here used to let an unavailable, unrelated family (ast2100-x10) refuse
    # the standard RFB path with a 503.
    spec.check_source(root)
    return factory()
