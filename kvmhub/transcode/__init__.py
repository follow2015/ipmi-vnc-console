"""Unified transcode platform (R unit, offline)."""
from .contract import Decoded, PluginSpec
from .registry import PLUGINS, build, select, verify
from .pipeline import build_decoder, open_pipeline

__all__ = ["Decoded", "PluginSpec", "PLUGINS", "build", "select", "verify",
           "build_decoder", "open_pipeline"]
