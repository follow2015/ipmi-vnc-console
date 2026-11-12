"""The only enabled adapter is a synthetic, explicitly versioned test device."""
import asyncio
import ipaddress
import json
from urllib.parse import urlsplit

import aiohttp

from .common import Problem


class MockAdapter:
    adapter_id = "mock-v1"
    connection_limit = 4

    def __init__(self, info):
        target = urlsplit(info["target"])
        try:
            loopback = ipaddress.ip_address(target.hostname).is_loopback
            fingerprint = bytes.fromhex(info["fingerprint"])
        except (ValueError, TypeError):
            raise Problem("invalid_target_policy", 502) from None
        if (target.scheme != "https" or not loopback or target.username or target.password
                or target.path or target.query or target.fragment or len(fingerprint) != 32
                or info["adapter"] != self.adapter_id):
            raise Problem("adapter_not_verified", 403)
        self.target = info["target"]
        trace = aiohttp.TraceConfig()

        async def sending_headers(session, context, params):
            if params.method == "POST" and params.url.path == "/session":
                self.possible_session = True

        async def reject_redirect(session, context, params):
            params.response.close()
            raise Problem("upstream_redirect_denied")

        trace.on_request_headers_sent.append(sending_headers)
        trace.on_request_redirect.append(reject_redirect)
        self.http = aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(ssl=aiohttp.Fingerprint(fingerprint), limit=4),
            cookie_jar=aiohttp.DummyCookieJar(), trust_env=False,
            timeout=aiohttp.ClientTimeout(total=5, connect=3), auto_decompress=False,
            trace_configs=[trace])
        self.token = None
        self.logout_path = None
        self.possible_session = False

    async def login(self, username, password):
        async with self.http.post(self.target + "/session", json={"username": username, "password": password},
                                  allow_redirects=False) as response:
            if response.status in (401, 403):
                self.possible_session = False
            if response.status != 201:
                raise Problem("bmc_auth_failed", 502)
            data = await response.content.read(4097)
            if len(data) > 4096:
                raise Problem("upstream_invalid_response", 502)
            try:
                self.token = json.loads(data)["token"]
            except (ValueError, KeyError, TypeError):
                raise Problem("upstream_invalid_response", 502) from None
            if not isinstance(self.token, str) or not self.token:
                raise Problem("upstream_invalid_response", 502)
            self.logout_path = "/session"

    async def connect(self, offered):
        if "binary" not in offered:
            raise Problem("subprotocol_required", 400)
        ws = await self.http.ws_connect(self.target + "/console", protocols=("binary",),
                                        headers={"X-Mock-Session": self.token},
                                        heartbeat=20, max_msg_size=1024 * 1024,
                                        timeout=aiohttp.ClientWSTimeout(ws_close=2), compress=0)
        if ws.protocol != "binary":
            await ws.close()
            raise Problem("upstream_handshake_failed", 502)
        return ws

    async def close(self):
        cleaned = not self.possible_session
        try:
            if self.token and self.logout_path:
                async with asyncio.timeout(5):
                    async with self.http.delete(self.target + self.logout_path,
                                                headers={"X-Mock-Session": self.token},
                                                allow_redirects=False) as r:
                        cleaned = r.status in (204, 404)
        except (aiohttp.ClientError, TimeoutError):
            cleaned = False
        finally:
            await self.http.close()
            self.token = None
        return cleaned
