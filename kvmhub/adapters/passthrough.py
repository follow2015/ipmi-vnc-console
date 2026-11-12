"""Real-device adapter that relays the measured X10 console to a browser."""
from __future__ import annotations

import re
from urllib.parse import urlsplit

from ..common import PASSTHROUGH_ADAPTER_ID, Problem
from ..passthrough import BrowserHandshake, RfbPassthroughSession
from ..rfb_upstream import RfbUpstream, UpstreamConfig

ASSET_PATH = re.compile(
    r"^/(?:novnc/include/[A-Za-z0-9_.-]{1,64}\.js"
    r"|js/[A-Za-z0-9_.-]{1,64}\.js"
    r"|css/[A-Za-z0-9_.-]{1,64}\.css"
    r"|images/[A-Za-z0-9_./-]{1,120}\.(?:png|gif|jpg|svg)"
    r"|favicon\.ico)$")

CONTENT_TYPES = {
    ".js": "application/javascript",
    ".css": "text/css",
    ".ico": "image/x-icon",
    ".png": "image/png",
    ".gif": "image/gif",
    ".jpg": "image/jpeg",
    ".svg": "image/svg+xml",
}


def content_type_for(path: str) -> str:
    for suffix, value in CONTENT_TYPES.items():
        if path.endswith(suffix):
            return value
    return "application/octet-stream"


class PassthroughAdapter:
    adapter_id = PASSTHROUGH_ADAPTER_ID

    def __init__(self, info):
        target = urlsplit(info["target"])
        try:
            host = target.hostname
            fingerprint = bytes.fromhex(info["fingerprint"])
        except (TypeError, ValueError):
            raise Problem("invalid_target_policy", 502) from None
        if (target.scheme != "https" or not host or target.username or target.password
                or target.path not in ("", "/") or target.query or target.fragment
                or len(fingerprint) != 32 or info["adapter"] != self.adapter_id):
            raise Problem("adapter_not_verified", 403)
        self.target = info["target"]
        self.cfg = UpstreamConfig(
            host=host,
            port=target.port or 443,
            cert_sha256=fingerprint.hex(),
            max_frame_bytes=1024 * 1024,
            max_total_bytes=64 * 1024 * 1024,
            max_frames=4000,
        )
        self.upstream: RfbUpstream | None = None
        self.session: RfbPassthroughSession | None = None

    async def login(self, username, password):
        self.upstream = RfbUpstream(self.cfg)
        await self.upstream.login(username, password)
        await self.upstream.open(request_frames=False)

    async def connect(self, offered):
        if "binary" not in offered:
            raise Problem("subprotocol_required", 400)
        if self.session is not None and not self.session.closed:
            raise Problem("connection_limit")
        if self.upstream is None or not self.upstream.server_init_raw:
            raise Problem("upstream_handshake_failed", 502)
        session = RfbPassthroughSession(
            self.upstream, BrowserHandshake(self.upstream.server_init_raw))
        await session.start()
        self.session = session
        return session

    async def fetch_asset(self, path: str) -> tuple[str, bytes]:
        if not ASSET_PATH.fullmatch(path):
            raise Problem("route_denied", 404)
        if self.upstream is None:
            raise Problem("upstream_unavailable", 502)
        _upstream_type, body = await self.upstream.fetch_asset(path)
        return content_type_for(path), body

    async def close(self):
        if self.session is not None:
            await self.session.close()
            self.session = None
        if self.upstream is None:
            return False
        cleaned = await self.upstream.close() == "ok"
        self.upstream = None
        return cleaned
