"""Unified transcode platform (R unit, offline).

Every protocol family enters the same bounded decode -> framebuffer -> standard
RFB pipeline through one audited plugin. Nothing here is imported by the
console path yet; registration grants no device access.
"""
from .contract import Decoded, PluginSpec
from .registry import PLUGINS, build, select, verify
from .pipeline import build_decoder, open_pipeline

__all__ = ["Decoded", "PluginSpec", "PLUGINS", "build", "select", "verify",
           "build_decoder", "open_pipeline"]
