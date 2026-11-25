"""ATEN Java ticket/TCP console using the platform's AST2100 client assets."""
from urllib.parse import urlsplit

from ..aten_java_upstream import AtenJavaUpstream
from ..driver_specs import DRIVERS
from ..common import (ATEN_JAVA_ADAPTER_ID, Problem, bmc_allowed_networks_from_env)
from ..passthrough import (BrowserHandshake, INSYDE_CLIENT_MESSAGES,
                           INSYDE_MESSAGE_SIZES, RfbPassthroughSession)
from ..client_assets import ASSET_DIR, ASSET_PATH, KNOWN_ASSETS, fetch_asset as fetch_client_asset


class AtenJavaAdapter:
    adapter_id = ATEN_JAVA_ADAPTER_ID
    connection_limit = DRIVERS[adapter_id].connection_limit
    supports_upstream_recovery = DRIVERS[adapter_id].supports_upstream_recovery
    login_budget = DRIVERS[adapter_id].login_budget

    def __init__(self, info, *, networks=None):
        try:
            target = urlsplit(info["target"])
            port = target.port
        except (TypeError, ValueError):
            raise Problem("invalid_target_policy", 502) from None
        if (info["adapter"] != self.adapter_id or target.scheme != "https"
                or not target.hostname or port not in (None, 443)
                or target.username or target.password or target.query or target.fragment
                or target.path not in ("", "/")
                or tuple(info.get("protocol_versions") or ("RFB 003.008",)) != ("RFB 003.008",)
                or info.get("message_profile") not in (None, "", "insyde")
                or info.get("protocol")
                or info.get("input_shaping")
                or info.get("login_path") not in (None, "", "/cgi/login.cgi")
                or info.get("logout_path") not in (None, "", "/cgi/logout.cgi")):
            raise Problem("invalid_target_policy", 502)
        self.target = info["target"]
        self.host = target.hostname
        self.asset_pattern = info.get("asset_pattern") or ASSET_PATH
        self.upstream = AtenJavaUpstream(
            target.hostname, info.get("fingerprint", ""),
            networks=bmc_allowed_networks_from_env() if networks is None else networks)
        self.session = None
        self.cleanup_outcome = None

    async def login(self, username, password):
        await self.upstream.login(username, password)

    async def connect(self, offered):
        if "binary" not in offered:
            raise Problem("subprotocol_required", 400)
        if self.session is not None and not self.session.closed:
            raise Problem("connection_limit", 409)
        if not self.upstream.server_init_raw:
            raise Problem("upstream_handshake_failed", 502)
        self.session = RfbPassthroughSession(
            self.upstream, BrowserHandshake(self.upstream.server_init_raw, version=b"RFB 003.008\n"),
            allowed_client_messages=INSYDE_CLIENT_MESSAGES, message_sizes=INSYDE_MESSAGE_SIZES)
        await self.session.start()
        return self.session

    async def fetch_asset(self, path: str) -> tuple[str, bytes]:
        return await fetch_client_asset(path)

    async def close(self):
        if self.session is not None:
            await self.session.close()
            self.session = None
        confirmed = await self.upstream.close()
        self.cleanup_outcome = self.upstream.cleanup_outcome
        return confirmed
