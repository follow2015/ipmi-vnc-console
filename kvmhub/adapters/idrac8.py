"""Dell iDRAC8 HTML5 viewer adapter: AVSP/DVC -> RFB for the browser."""
from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import re
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from aiohttp import WSMessage, WSMsgType

from ..common import IDRAC8_ADAPTER_ID, Problem
from ..idrac8_upstream import Idrac8Upstream, UpstreamError
from ..passthrough import BrowserHandshake, BrowserHandshakeError
from ..rfb_server import build_raw_framebuffer_update, build_server_init

logger = logging.getLogger(__name__)

IDRAC8_SESSION_RECOVERY_ENV = "KVMHUB_IDRAC8_SESSION_RECOVERY"


def _clear_bmc_sessions(host: str, username: str, password: str) -> bool:
    try:
        import paramiko  # type: ignore[import-not-found]
    except ImportError:  # pragma: no cover - depends on host tooling
        logger.warning("iDRAC8 session recovery needs paramiko on the worker")
        return False
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    channel = None
    try:
        client.connect(host, port=22, username=username, password=password,
                       timeout=6, auth_timeout=6, banner_timeout=6,
                       look_for_keys=False, allow_agent=False)
        channel = client.invoke_shell(width=200, height=50)
        time.sleep(0.6)
        channel.recv(65536)
        channel.send("racadm closessn -a\n")
        time.sleep(1.2)
        channel.recv(65536)
        return True
    except Exception as exc:  # noqa: BLE001 - recovery must never mask the login error
        logger.warning("iDRAC8 session recovery failed: %s", type(exc).__name__)
        return False
    finally:
        if channel is not None:
            with contextlib.suppress(Exception):
                channel.close()
        client.close()


VIEW_WIDTH = 1024
VIEW_HEIGHT = 768
VIEW_NAME = "iDRAC8"
IDRAC8_KVM_PORT = 5900
OUTPUT_QUEUE_BYTES = 16 * 1024 * 1024

ASSET_DIR = Path(__file__).resolve().parents[1] / "static" / "novnc" / "include"
ASSET_PATH = re.compile(r"^/novnc/include/([A-Za-z0-9_-]{1,48}(?:\.js)?)$")
KNOWN_ASSETS = frozenset({
    "util.js", "webutil.js", "base64.js", "websock.js", "des.js",
    "keysymdef.js", "keyboard.js", "input.js", "display.js", "jsunzip.js",
    "rfb.js", "keysym.js", "ast2100.js",
})


class Idrac8RfbSession:

    protocol = "binary"

    def __init__(self, upstream: Idrac8Upstream) -> None:
        self.upstream = upstream
        handshake = BrowserHandshake(
            build_server_init(VIEW_WIDTH, VIEW_HEIGHT, VIEW_NAME),
            version=b"RFB 003.008\n")
        self.handshake = handshake
        self._out: asyncio.Queue[bytes | None] = asyncio.Queue(maxsize=128)
        self._relay_task: asyncio.Task[None] | None = None
        self._closed = False
        self._buffered = 0
        self.error: str | None = None
        self.reload_requested = False
        self.client_bytes = 0
        self.server_bytes = 0
        self.frames = 0
        self.client_messages = 0
        self.started = False

    async def start(self) -> None:
        if self.started:
            return
        self.started = True
        await self._emit(self.handshake.start())

    async def _emit(self, data: bytes) -> None:
        if not data or self._closed:
            return
        while self._buffered + len(data) > OUTPUT_QUEUE_BYTES and not self._closed:
            await asyncio.sleep(0.02)
        if self._closed:
            return
        self._buffered += len(data)
        self.server_bytes += len(data)
        await self._out.put(bytes(data))

    async def send_bytes(self, data: bytes) -> None:
        if self._closed or not data:
            return
        self.client_bytes += len(data)
        if self.handshake.completed:
            self.client_messages += 1
            return
        try:
            out, _trailing = self.handshake.feed(data)
        except BrowserHandshakeError as exc:
            self.error = exc.args[0] if exc.args else "handshake_failed"
            await self.close(code=1002)
            return
        if out:
            await self._emit(out)
        if self.handshake.completed:
            self._start_relay()

    async def send_str(self, data: str) -> None:
        self.error = "unexpected_text_frame"
        await self.close(code=1003)

    def _start_relay(self) -> None:
        if self._relay_task is None and not self._closed:
            self._relay_task = asyncio.create_task(self._relay())

    async def _relay(self) -> None:
        try:
            decoder = self.upstream.decoder()
            async for frame in self.upstream.frames():
                if self._closed:
                    break
                pixels = decoder.uncompress(frame.payload, color_mode=True)
                for message in build_raw_framebuffer_update(
                        pixels, VIEW_WIDTH, VIEW_HEIGHT):
                    await self._emit(message)
                self.frames += 1
        except asyncio.CancelledError:
            raise
        except (UpstreamError, ValueError, OSError) as exc:
            self.error = getattr(exc, "code", None) or type(exc).__name__
        except Exception as exc:  # pragma: no cover - classified, never logged raw
            self.error = type(exc).__name__
        finally:
            with contextlib.suppress(asyncio.QueueFull):
                self._out.put_nowait(None)

    async def close(self, code: int = 1000) -> None:
        if self._closed:
            return
        self._closed = True
        if self._relay_task is not None and not self._relay_task.done():
            self._relay_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._relay_task
        with contextlib.suppress(asyncio.QueueFull):
            self._out.put_nowait(None)

    def __aiter__(self) -> "Idrac8RfbSession":
        return self

    @property
    def closed(self) -> bool:
        return self._closed

    async def __anext__(self) -> WSMessage:
        item = await self._out.get()
        if item is None:
            raise StopAsyncIteration
        self._buffered -= len(item)
        return WSMessage(WSMsgType.BINARY, item, "")

    def as_dict(self) -> dict[str, Any]:
        return {
            "protocol": self.protocol,
            "handshake_completed": self.handshake.completed,
            "frames": self.frames,
            "client_bytes": self.client_bytes,
            "server_bytes": self.server_bytes,
            "error": self.error,
        }


class Idrac8Adapter:
    adapter_id = IDRAC8_ADAPTER_ID
    connection_limit = 1
    supports_upstream_recovery = False
    login_budget = 30.0

    def __init__(self, info: dict) -> None:
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
        self.host = host
        self.port = IDRAC8_KVM_PORT
        self.upstream: Idrac8Upstream | None = None
        self.session: Idrac8RfbSession | None = None

    async def login(self, username: str, password: str) -> None:
        deadline = time.monotonic() + 28.0
        last_error: OSError | None = None
        recovery_done = False
        recovery_enabled = os.environ.get(IDRAC8_SESSION_RECOVERY_ENV, "") in {
            "1", "true", "yes", "on",
        }
        for attempt in range(4):
            remaining = deadline - time.monotonic()
            if remaining <= 3.0:
                break
            if attempt == 2 and recovery_enabled and not recovery_done:
                recovery_done = True
                await asyncio.to_thread(
                    _clear_bmc_sessions, self.host, username, password)
            upstream = Idrac8Upstream(
                self.host, port=self.port, username=username, password=password,
                timeout=min(20.0, remaining - 1.0))
            self.upstream = upstream
            try:
                await upstream.connect()
                return
            except OSError as exc:
                last_error = exc
                logger.warning("iDRAC8 handshake attempt %d failed: %s",
                               attempt + 1, type(exc).__name__)
                if attempt == 3 or time.monotonic() + 3.0 >= deadline:
                    raise
                await asyncio.sleep(1.5)
        if last_error is not None:
            raise last_error

    async def connect(self, offered: list[str]) -> Idrac8RfbSession:
        if "binary" not in offered:
            raise Problem("subprotocol_required", 400)
        if self.session is not None and not self.session.closed:
            raise Problem("connection_limit")
        if self.upstream is None or self.upstream.capabilities is None:
            raise Problem("upstream_handshake_failed", 502)
        session = Idrac8RfbSession(self.upstream)
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
