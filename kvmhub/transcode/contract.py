"""Platform/plugin contract. No dynamic import, no network, no credentials."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass

from ..common import Problem
from ..video.framebuffer import Update

API_VERSION = 1


@dataclass(frozen=True)
class Decoded:
    update: Update
    jpegs: tuple = ()


@dataclass(frozen=True)
class PluginSpec:
    family: str
    version: str
    module: str
    source: str
    sha256: str
    api_version: int = API_VERSION
    needs_credentials: bool = False
    network: str = "none"
    detects: str = ""

    def check_source(self, root) -> None:
        """Verify the locked source digest; a mismatch refuses registration."""
        from pathlib import Path
        payload = (Path(root) / self.source).read_bytes()
        if hashlib.sha256(payload).hexdigest() != self.sha256:
            raise Problem('transcode_family_unsupported', 503)


class FamilyDecoder:
    """Session-scoped decoder. Subclasses must not share mutable state."""

    #: A family can be detected and listed without being buildable. AST2100
    #: deliberately opts out until its bitstream self-containment is proven.
    available = True

    def init(self, width: int, height: int, header: bytes = b'') -> int:
        raise NotImplementedError

    def feed(self, stream: bytes) -> Decoded:
        raise NotImplementedError
