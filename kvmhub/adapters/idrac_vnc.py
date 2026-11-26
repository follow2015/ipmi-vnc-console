"""Dell iDRAC built-in VNC adapter: standard RFB over bare TCP."""
from __future__ import annotations

from urllib.parse import urlsplit

from ..driver_specs import DRIVERS
from ..common import (IDRAC_VNC_ADAPTER_ID, Problem, bmc_allowed_networks_from_env,
                      require_controlled_host)
from ..rfb_tcp_upstream import RfbTcpConfig, RfbTcpUpstream
from ..passthrough import RfbPassthroughSession
from ..client_assets import ASSET_DIR, ASSET_PATH, KNOWN_ASSETS
from .rfb_tcp_family import RfbTcpFamilyAdapter

IDRAC_VNC_PORT = 5901



class IdracVncAdapter(RfbTcpFamilyAdapter):
    adapter_id = IDRAC_VNC_ADAPTER_ID
    connection_limit = DRIVERS[adapter_id].connection_limit
    supports_upstream_recovery = DRIVERS[adapter_id].supports_upstream_recovery
    login_budget = DRIVERS[adapter_id].login_budget
    client_encodings = (0, 1)

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
