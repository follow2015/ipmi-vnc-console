"""Huawei iBMC private KVM gateway adapter (2198 WebSocket -> RFB for browser)."""
from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import time
from typing import Any
from urllib.parse import urlsplit

log = logging.getLogger("kvmhub.huawei_kvm_gateway")

from aiohttp import WSMessage, WSMsgType

from ..driver_specs import DRIVERS
from ..video_metrics import VideoMetrics
from ..common import (HUAWEI_IBMC_KVM_GATEWAY_ID, Problem,
                      bmc_allowed_networks_from_env, require_controlled_host)
from ..huawei_kvm_input import BrowserInputTranslator, packet_command
from ..huawei_kvm_jpeg import jpeg_header
from ..huawei_kvm_protocol import (C_CMD_KEYBOARD, C_CMD_MOUSE,
                                   HuaweiFrameDecoder)
from ..huawei_kvm_upstream import (HuaweiKvmUpstream, UpstreamError,
                                   huawei_kvm_pin_from_env, resolve_huawei_pin,
                                   valid_pin)
from ..passthrough import BrowserHandshake, BrowserHandshakeError
from ..rfb_server import (build_raw_fbu_from_bgrx32, build_server_init_32bpp,
                          rgb24_to_bgrx32)
from ..client_assets import ASSET_DIR, ASSET_PATH, KNOWN_ASSETS, fetch_asset as fetch_client_asset

OUTPUT_QUEUE_BYTES = 16 * 1024 * 1024
VIEW_NAME = "iBMC-KVM"


class HuaweiKvmRfbSession:

    protocol = "binary"

    def __init__(self, upstream: HuaweiKvmUpstream, width: int, height: int, *,
                 measure_video: bool = False) -> None:
        self.upstream = upstream
        self.width = width
        self.height = height
        handshake = BrowserHandshake(
            build_server_init_32bpp(width, height, VIEW_NAME),
            version=b"RFB 003.008\n",
            security_type=BrowserHandshake.SECURITY_TYPE_NONE)
        self.handshake = handshake
        self.input = BrowserInputTranslator(upstream.tag_id, width, height)
        self.video_metrics = VideoMetrics() if measure_video else None
        self.decoder = HuaweiFrameDecoder(observations=self.video_metrics)
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
                with (self.video_metrics.measure('decode_convert') if self.video_metrics
                      else contextlib.nullcontext()):
                    bgr = self.decoder.decode(blocks, width, height, quant, header)
                    bgrx = rgb24_to_bgrx32(bgr, self.width, self.height)
                emitted = 0
                messages = build_raw_fbu_from_bgrx32(bgrx, self.width, self.height)
                if self.video_metrics is not None:
                    messages = self.video_metrics.messages(messages)
                for message in messages:
                    if self.video_metrics is None:
                        await self._emit(message)
                    else:
                        started = time.perf_counter()
                        queued_before = self.server_bytes
                        await self._emit(message)
                        self.video_metrics.queued_video_bytes += self.server_bytes - queued_before
                        elapsed = time.perf_counter() - started
                        self.video_metrics.stage_wall['enqueue'] += elapsed
                        self.video_metrics.stage_max_wall['enqueue'] = max(
                            self.video_metrics.stage_max_wall['enqueue'], elapsed)
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
            "video_metrics": self.video_metrics.public() if self.video_metrics else None,
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
    connection_limit = DRIVERS[adapter_id].connection_limit
    supports_upstream_recovery = DRIVERS[adapter_id].supports_upstream_recovery
    login_budget = DRIVERS[adapter_id].login_budget

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
        asset_pin = str(info.get("fingerprint") or "").strip().lower().replace(":", "")
        if asset_pin and not valid_pin(asset_pin):
            raise Problem("bmc_cert_pin_invalid", 400)
        expected_pin = resolve_huawei_pin(info, huawei_kvm_pin_from_env())
        if not valid_pin(expected_pin):
            raise Problem("bmc_cert_pin_unconfigured", 503)
        self.target = info["target"]
        self.host = host
        self.tls_pin = expected_pin
        self.upstream: HuaweiKvmUpstream | None = None
        self.session: HuaweiKvmRfbSession | None = None
        self.video_lane = info.get('video_lane') or ''
        if self.video_lane and (self.video_lane != 'transcode-v1' or not info.get('video_binding')):
            raise Problem('pipeline_version_unavailable', 503)
        self.client_v2 = False
        if self.video_lane:
            from ..video.client_v2 import protocol_contract, verify_bundle
            if str(info.get('video_contract') or '') != protocol_contract():
                raise Problem('pipeline_version_unavailable', 503)
            verify_bundle()
            self.client_v2 = True
        self.video_before_resync = None
        self._video_connected_once = False

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
        if self.video_lane and self.session is not None and self.session.release_failed:
            raise Problem('upstream_handshake_failed', 502)
        if self.upstream is None or not self.upstream.connected or self.upstream.ticket is None:
            raise Problem("upstream_handshake_failed", 502)
        if self.video_lane:
            if self.video_before_resync is None:
                raise Problem('pipeline_version_unavailable', 503)
            if self._video_connected_once:
                await self.video_before_resync()
                old = self.upstream
                await old.close()
                self.upstream = HuaweiKvmUpstream(self.host, old.username, old.password,
                                                  tls_pin=self.tls_pin)
                try:
                    await self.upstream.connect()
                except UpstreamError as exc:
                    raise Problem(exc.code, exc.status) from exc
            from ..video.huawei_session import HuaweiV1RfbSession
            session = HuaweiV1RfbSession(self.upstream,
                self.upstream.framebuffer_width, self.upstream.framebuffer_height,
                before_resync=self.video_before_resync)
            try:
                await session.start()
            except (ValueError, RuntimeError, OSError, TimeoutError) as exc:
                raise Problem('pipeline_version_unavailable', 503) from exc
            self._video_connected_once = True
            self.session = session
            return session
        width = self.upstream.framebuffer_width
        height = self.upstream.framebuffer_height
        session = HuaweiKvmRfbSession(self.upstream, width, height,
            measure_video=os.environ.get("KVMHUB_HUAWEI_VIDEO_METRICS", "") == "1")
        await session.start()
        self.session = session
        return session

    async def fetch_asset(self, path: str) -> tuple[str, bytes]:
        return await fetch_client_asset(path)

    async def close(self) -> bool:
        input_cleanup_ok = True
        if self.session is not None:
            await self.session.close()
            input_cleanup_ok = not getattr(self.session, 'release_failed', False)
            self.session = None
        if self.upstream is None:
            return False
        upstream, self.upstream = self.upstream, None
        await upstream.close()
        return input_cleanup_ok
