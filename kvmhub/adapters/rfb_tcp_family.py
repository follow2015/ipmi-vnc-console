"""Shared standard-RFB browser lifecycle; target/auth policy stays in drivers."""
from ..common import Problem
from ..client_assets import fetch_asset
from ..passthrough import RfbPassthroughSession
from ..rfb_tcp_upstream import BROWSER_RFB_VERSION, StandardRfbBrowserHandshake


class RfbTcpFamilyAdapter:
    async def connect(self, offered: list[str]) -> RfbPassthroughSession:
        if "binary" not in offered:
            raise Problem("subprotocol_required", 400)
        if self.session is not None and not self.session.closed:
            raise Problem("connection_limit")
        if self.upstream is None or not self.upstream.server_init_raw:
            raise Problem("upstream_handshake_failed", 502)
        handshake = StandardRfbBrowserHandshake(
            self.upstream.server_init_raw,
            version=(BROWSER_RFB_VERSION + "\n").encode("ascii"))
        session = RfbPassthroughSession(
            self.upstream, handshake,
            client_encodings=getattr(self, "client_encodings", None))
        await session.start()
        self.session = session
        return session

    async def fetch_asset(self, path: str) -> tuple[str, bytes]:
        return await fetch_asset(path)

    async def close(self) -> bool:
        if self.session is not None:
            await self.session.close()
            self.session = None
        if self.upstream is None:
            return False
        upstream, self.upstream = self.upstream, None
        await upstream.close()
        return True
