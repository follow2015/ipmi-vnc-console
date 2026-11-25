"""Factory for one transcode session over the shared video runtime."""
import asyncio

from ..common import Problem
from ..video.runtime import ManagedDecoder
from ..video.session import VideoSession
from .registry import build as build_plugin

_FAMILY_KIND = '_transcode_family'


def build_decoder(family, width, height, header=b'', *, root=None, budget=None,
                  before_resync=None, require_resync_permit=False):
    from pathlib import Path
    root = root or Path(__file__).resolve().parents[2]
    plugin = build_plugin(family, root)
    decoder = ManagedDecoder(budget=budget, before_resync=before_resync,
                             require_resync_permit=require_resync_permit)
    decoder.transcode_family = family
    decoder.transcode_plugin = plugin
    decoder.plugin_root = root
    setattr(decoder, _FAMILY_KIND, True)
    return decoder, plugin


async def open_pipeline(family, width, height, header=b'', *, root=None,
                        budget=None, before_resync=None, tight=False):
    decoder, plugin = build_decoder(
        family, width, height, header, root=root, budget=budget,
        before_resync=before_resync, require_resync_permit=before_resync is not None)
    session = VideoSession(decoder=decoder, tight=tight)
    plugin.init(width, height, header)
    decoder.start()
    decoder.reset(width, height, header, family=family)
    session._bind_framebuffer(width, height, decoder.epoch)
    return session
