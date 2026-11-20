"""Dell iDRAC built-in VNC adapter: standard RFB over bare TCP."""
from __future__ import annotations

from urllib.parse import urlsplit

from ..common import (IDRAC_VNC_ADAPTER_ID, Problem, bmc_allowed_networks_from_env,
                      require_controlled_host)
from ..passthrough import RfbPassthroughSession
from ..rfb_tcp_upstream import (RfbTcpConfig, RfbTcpUpstream,
                                StandardRfbBrowserHandshake)
from .idrac8 import ASSET_DIR, ASSET_PATH, KNOWN_ASSETS

IDRAC_VNC_PORT = 5901


class IdracVncAdapter:
    adapter_id = IDRAC_VNC_ADAPTER_ID
    connection_limit = 1
    supports_upstream_recovery = False
    login_budget = 28.0

    def __init__(self, info: dict, *, networks=None) -> None:
        target = urlsplit(info["target"])
        host = target.hostname
        if (target.scheme not in ("https", "http") or not host
                or target.username or target.password or target.query or target.fragment
                or target.path not in ("", "/") or info["adapter"] != self.adapter_id):
            raise Problem("invalid_target_policy", 502)
        require_controlled_host(
            host,
            bmc_allowed_networks_from_env() if networks is None else networks,
        )
        self.target = info["target"]
        self.host = host
        self.port = IDRAC_VNC_PORT
        self.upstream: RfbTcpUpstream | None = None
        self.session: RfbPassthroughSession | None = None

    async def login(self, username: str, password: str) -> None:
        if not isinstance(password, str) or not password:
            raise Problem("credential_unavailable", 503)
        upstream = RfbTcpUpstream(RfbTcpConfig(
            host=self.host, port=self.port, password=password))
        self.upstream = upstream
        await upstream.connect()

    async def connect(self, offered: list[str]) -> RfbPassthroughSession:
        if "binary" not in offered:
            raise Problem("subprotocol_required", 400)
        if self.session is not None and not self.session.closed:
            raise Problem("connection_limit")
        if self.upstream is None or not self.upstream.server_init_raw:
            raise Problem("upstream_handshake_failed", 502)
        version = (self.upstream.protocol_version or "RFB 003.008") + "\n"
        handshake = StandardRfbBrowserHandshake(
            self.upstream.server_init_raw, version=version.encode("ascii"))
        session = RfbPassthroughSession(self.upstream, handshake)
        await session.start()
        self.session = session
        return session

    async def fetch_asset(self, path: str) -> tuple[str, bytes]:
        match = ASSET_PATH.fullmatch(path or "")
        if match is None:
            raise Problem("route_denied", 404)
        name = match.group(1)
        if not name.endswith(".js"):
            name += ".js"
        if name not in KNOWN_ASSETS:
            raise Problem("route_denied", 404)
        target = ASSET_DIR / name
        if not target.is_file():
            raise Problem("route_denied", 404)
        return "application/javascript", target.read_bytes()

    async def close(self) -> bool:
        if self.session is not None:
            await self.session.close()
            self.session = None
        if self.upstream is None:
            return False
        upstream, self.upstream = self.upstream, None
        await upstream.close()
        return True
