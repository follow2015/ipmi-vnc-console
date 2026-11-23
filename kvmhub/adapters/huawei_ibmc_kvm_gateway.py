"""Huawei iBMC private KVM gateway adapter (2198 WebSocket -> RFB for browser)."""
from __future__ import annotations

import asyncio
import contextlib
import logging
from typing import Any
from urllib.parse import urlsplit

log = logging.getLogger("kvmhub.huawei_kvm_gateway")

from aiohttp import WSMessage, WSMsgType

from ..common import (HUAWEI_IBMC_KVM_GATEWAY_ID, Problem,
                      bmc_allowed_networks_from_env, require_controlled_host)
from ..huawei_kvm_input import BrowserInputTranslator, packet_command
from ..huawei_kvm_jpeg import jpeg_header
from ..huawei_kvm_protocol import (C_CMD_KEYBOARD, C_CMD_MOUSE,
                                   HuaweiFrameDecoder)
from ..huawei_kvm_upstream import (HuaweiKvmUpstream, UpstreamError,
                                   huawei_kvm_pin_from_env, valid_pin)
from ..passthrough import BrowserHandshake, BrowserHandshakeError
from ..rfb_server import (build_raw_fbu_from_bgrx32, build_server_init_32bpp,
                          rgb24_to_bgrx32)
from .idrac8 import ASSET_DIR, ASSET_PATH, KNOWN_ASSETS

OUTPUT_QUEUE_BYTES = 16 * 1024 * 1024
VIEW_NAME = "iBMC-KVM"


class HuaweiKvmRfbSession:

    protocol = "binary"

    def __init__(self, upstream: HuaweiKvmUpstream, width: int, height: int) -> None:
        self.upstream = upstream
        self.width = width
        self.height = height
        handshake = BrowserHandshake(
            build_server_init_32bpp(width, height, VIEW_NAME),
            version=b"RFB 003.008\n",
            security_type=BrowserHandshake.SECURITY_TYPE_NONE)
        self.handshake = handshake
        self.input = BrowserInputTranslator(upstream.tag_id, width, height)
        self.decoder = HuaweiFrameDecoder()
        self._out: asyncio.Queue[bytes | None] = asyncio.Queue(maxsize=128)
        self._relay_task: asyncio.Task[None] | None = None
        self._closed = False
        self._buffered = 0
        self.error: str | None = None
        self.started = False
        self.frames = 0
        self.client_messages = 0
        self.server_bytes = 0
        self.client_bytes = 0

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
            await self._forward_input(data)
            return
        try:
            out, trailing = self.handshake.feed(data)
        except BrowserHandshakeError as exc:
            self.error = exc.args[0] if exc.args else "handshake_failed"
            await self.close(code=1002)
            return
        if out:
            await self._emit(out)
        if self.handshake.completed:
            log.info("huawei_kvm browser handshake completed, starting relay")
            self._start_relay()
            if trailing:
                await self._forward_input(trailing)

    async def _forward_input(self, data: bytes) -> None:
        self.client_messages += 1
        try:
            packets = self.input.feed(data)
        except ValueError:
            self.input.stats.errors += 1
            return
        if packets and (self.input.stats.keys <= 2 or self.input.stats.pointers <= 2):
            log.info("huawei_kvm input received keys=%s pointers=%s packets=%s",
                     self.input.stats.keys, self.input.stats.pointers, len(packets))
        for packet in packets:
            command = packet_command(packet)
            if command not in (C_CMD_KEYBOARD, C_CMD_MOUSE):
                self.input.stats.ignored += 1
                continue
            try:
                await self.upstream.send_input(packet)
            except (UpstreamError, OSError) as exc:
                self.error = getattr(exc, "code", None) or type(exc).__name__
                log.warning("huawei_kvm input forward stopped code=%s", self.error)
                return
            self.input.stats.forwarded += 1

    async def send_str(self, data: str) -> None:
        self.error = "unexpected_text_frame"
        await self.close(code=1003)

    def _start_relay(self) -> None:
        if self._relay_task is None and not self._closed:
            self._relay_task = asyncio.create_task(self._relay())

    async def _relay(self) -> None:
        try:
            log.info("huawei_kvm relay started geometry=%sx%s", self.width, self.height)
            async for blocks, width, height, quant in self.upstream.frames():
                if self._closed:
                    break
                header = jpeg_header(quant)
                bgr = self.decoder.decode(blocks, width, height, quant, header)
                bgrx = rgb24_to_bgrx32(bgr, self.width, self.height)
                emitted = 0
                for message in build_raw_fbu_from_bgrx32(
                        bgrx, self.width, self.height):
                    await self._emit(message)
                    emitted += 1
                self.frames += 1
                if self.frames <= 3 or self.frames % 30 == 0:
                    log.info("huawei_kvm relay frame=%s decoded=%sx%s q=%s fbu=%s bytes=%s",
                             self.frames, width, height, quant, emitted, self.server_bytes)
        except asyncio.CancelledError:
            raise
        except (UpstreamError, ValueError, OSError) as exc:
            self.error = getattr(exc, "code", None) or type(exc).__name__
            log.warning("huawei_kvm relay stopped code=%s frames=%s", self.error, self.frames)
        except Exception as exc:  # pragma: no cover - classified, never logged raw
            self.error = type(exc).__name__
            log.warning("huawei_kvm relay crashed type=%s frames=%s", self.error, self.frames)
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

    def __aiter__(self) -> "HuaweiKvmRfbSession":
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
            "decode_ok_blocks": self.decoder.decoded_blocks,
            "decode_failed_blocks": self.decoder.failed_blocks,
            "client_messages": self.client_messages,
            "input_keys": self.input.stats.keys,
            "input_pointers": self.input.stats.pointers,
            "input_forwarded": self.input.stats.forwarded,
            "input_unmapped": self.input.stats.unmapped,
            "client_bytes": self.client_bytes,
            "server_bytes": self.server_bytes,
            "error": self.error,
        }


def _rgb_to_pixels(rgb: bytes) -> list[int]:
    n = len(rgb) // 3
    out = [0] * n
    for i in range(n):
        r, g, b = rgb[i * 3], rgb[i * 3 + 1], rgb[i * 3 + 2]
        out[i] = (r << 16) | (g << 8) | b
    return out


class HuaweiIbmcKvmGatewayAdapter:
    adapter_id = HUAWEI_IBMC_KVM_GATEWAY_ID
    connection_limit = 1
    supports_upstream_recovery = False
    login_budget = 35.0

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
            adapter_id=self.adapter_id,
        )
        expected_pin = huawei_kvm_pin_from_env()
        if not valid_pin(expected_pin):
            raise Problem("bmc_cert_pin_unconfigured", 503)
        self.target = info["target"]
        self.host = host
        self.tls_pin = expected_pin
        self.upstream: HuaweiKvmUpstream | None = None
        self.session: HuaweiKvmRfbSession | None = None

    async def login(self, username: str, password: str) -> None:
        if not isinstance(username, str) or not username or not isinstance(password, str) or not password:
            raise Problem("credential_unavailable", 503)
        upstream = HuaweiKvmUpstream(self.host, username, password, tls_pin=self.tls_pin)
        self.upstream = upstream
        try:
            await upstream.connect()
        except UpstreamError as exc:
            raise Problem(exc.code, exc.status) from exc

    async def connect(self, offered: list[str]) -> HuaweiKvmRfbSession:
        if "binary" not in offered:
            raise Problem("subprotocol_required", 400)
        if self.session is not None and not self.session.closed:
            raise Problem("connection_limit")
        if self.upstream is None or not self.upstream.connected or self.upstream.ticket is None:
            raise Problem("upstream_handshake_failed", 502)
        width = self.upstream.framebuffer_width
        height = self.upstream.framebuffer_height
        session = HuaweiKvmRfbSession(self.upstream, width, height)
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
