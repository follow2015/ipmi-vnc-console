"""Huawei iBMC private KVM upstream (2198 WebSocket) -> decoded frame stream."""
from __future__ import annotations

import asyncio
import contextlib
import hashlib
import logging
import os
import re
import ssl
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import AsyncIterator

import aiohttp

from . import huawei_kvm_protocol as P
from .common import Problem

logger = logging.getLogger(__name__)

DEFAULT_KVM_PORT = 2198
LOGIN_TIMEOUT = 12.0
HANDSHAKE_TIMEOUT = 15.0
MAX_FRAME_BYTES = 4 * 1024 * 1024
PIN_ENV = "KVMHUB_HUAWEI_VNC_PIN"


def huawei_kvm_pin_from_env() -> str:
    return os.environ.get(PIN_ENV, "").strip().lower().replace(":", "")


def valid_pin(pin: str) -> bool:
    return len(pin) == 64 and all(c in "0123456789abcdef" for c in pin)


def tls_der_matches_pin(der: bytes | None, pin: str) -> bool:
    if not der or not valid_pin(pin):
        return False
    return hashlib.sha256(der).hexdigest() == pin


class UpstreamError(Exception):
    def __init__(self, code: str, status: int = 502) -> None:
        super().__init__(code)
        self.code = code
        self.status = status


@dataclass
class KvmTicket:
    verify_id: int
    decrykey: str
    port: int
    compress: int
    verify_value_ext: str
    host: str


def parse_jnlp(xml_text: str, host: str) -> KvmTicket:
    params = dict(re.findall(r'<param\s+name="([^"]+)"\s+value="([^"]*)"', xml_text))
    try:
        return KvmTicket(
            verify_id=int(params["verifyValue"]),
            decrykey=params["decrykey"],
            port=int(params.get("port", DEFAULT_KVM_PORT)),
            compress=int(params.get("compress", "0")),
            verify_value_ext=params.get("verifyValueExt", ""),
            host=params.get("IPA", host),
        )
    except (KeyError, ValueError) as exc:
        raise UpstreamError("kvm_ticket_invalid") from exc


class HuaweiKvmUpstream:

    def __init__(self, host: str, username: str, password: str,
                 *, port: int = DEFAULT_KVM_PORT, verify_ssl: bool = False,
                 tls_pin: str = "") -> None:
        self.host = host
        self.username = username
        self.password = password
        self.port = port
        self.verify_ssl = verify_ssl
        self.tls_pin = tls_pin.strip().lower().replace(":", "")
        self.ticket: KvmTicket | None = None
        self._session: aiohttp.ClientSession | None = None
        self._ws: aiohttp.ClientWebSocketResponse | None = None
        self._buf = bytearray()
        self.tag_id = 0
        self.assembler = P.ImageAssembler()
        self.frame_count = 0
        self.connected = False
        self.framebuffer_width = 1024
        self.framebuffer_height = 768

    async def connect(self) -> None:
        await self._verify_tls_pin()
        timeout = aiohttp.ClientTimeout(total=LOGIN_TIMEOUT + HANDSHAKE_TIMEOUT)
        connector = aiohttp.TCPConnector(ssl=None if self.verify_ssl else _insecure_ssl())
        self._session = aiohttp.ClientSession(timeout=timeout, connector=connector)
        try:
            await self._obtain_ticket()
            await self._open_console_ws()
        except Exception:
            await self.close()
            raise

    async def _verify_tls_pin(self) -> None:
        if self.verify_ssl:
            return
        if not valid_pin(self.tls_pin):
            raise UpstreamError("bmc_cert_pin_unconfigured", 503)
        ctx = _insecure_ssl()
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port, ssl=ctx,
                                        server_hostname=self.host),
                timeout=HANDSHAKE_TIMEOUT,
            )
        except (OSError, ssl.SSLError, TimeoutError) as exc:
            raise UpstreamError("bmc_tls_pin_check_failed") from exc
        try:
            ssl_obj = writer.get_extra_info("ssl_object")
            der = ssl_obj.getpeercert(binary_form=True) if ssl_obj is not None else None
            if not tls_der_matches_pin(der, self.tls_pin):
                raise UpstreamError("bmc_cert_pin_mismatch", 502)
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

    async def _obtain_ticket(self) -> None:
        base = f"https://{self.host}"
        sess = self._session
        assert sess is not None
        login_headers = {"Content-Type": "application/json", "From": "WebUI"}
        login_body = {"UserName": self.username, "Password": self.password,
                      "Oem": {"Huawei": {"Domain": "LocaliBMC"}}}
        try:
            async with sess.post(base + "/redfish/v1/SessionService/Sessions/",
                                 json=login_body, headers=login_headers) as resp:
                if resp.status not in (200, 201):
                    raise UpstreamError("bmc_login_failed", 401)
                token = resp.headers.get("Token") or resp.headers.get("X-Auth-Token", "")
                location = resp.headers.get("Location", "")
                session_id = ""
                cookie = resp.headers.get("Set-Cookie", "")
                m = re.search(r"SessionId=([^;]+)", cookie)
                if m:
                    session_id = m.group(1)
                if not token:
                    raise UpstreamError("bmc_token_missing", 401)
        except aiohttp.ClientError as exc:
            raise UpstreamError("bmc_unreachable") from exc

        authed = {"From": "WebUI", "Token": token, "Accept": "application/json"}
        if session_id:
            authed["Cookie"] = f"SessionId={session_id}"
        json_ct = dict(authed)
        json_ct["Content-Type"] = "application/json;charset=utf-8"

        if location:
            await self._post_ok(base + location + "/Oem/Huawei/Actions/Session.RefreshActivationState",
                                {"Mode": "Activate"}, json_ct, optional=True)

        export_body = {"Type": "URI", "Content": "/tmp/web/kvm.jnlp", "Mode": "Shared"}
        await self._post_ok(base + "/redfish/v1/Managers/1/KvmService/Actions/KvmService.ExportKvmStartupFile",
                            export_body, json_ct)

        dl_body = {"TransferProtocol": "HTTPS", "Path": "/tmp/web/kvm.jnlp"}
        try:
            async with sess.post(base + "/redfish/v1/Managers/1/Actions/Oem/Huawei/Manager.GeneralDownload",
                                 json=dl_body, headers=json_ct) as resp:
                if resp.status != 200:
                    raise UpstreamError("kvm_jnlp_download_failed", resp.status)
                xml_text = await resp.text()
        except aiohttp.ClientError as exc:
            raise UpstreamError("kvm_jnlp_download_failed") from exc
        self.ticket = parse_jnlp(xml_text, self.host)

    async def _post_ok(self, url: str, body: dict, headers: dict, *, optional: bool = False) -> None:
        sess = self._session
        assert sess is not None
        try:
            async with sess.post(url, json=body, headers=headers) as resp:
                if resp.status != 200 and not optional:
                    raise UpstreamError("kvm_session_action_failed", resp.status)
        except aiohttp.ClientError as exc:
            if optional:
                return
            raise UpstreamError("kvm_session_action_failed") from exc

    async def _open_console_ws(self) -> None:
        ticket = self.ticket
        assert ticket is not None
        if ticket.compress != 0:
            raise UpstreamError("kvm_encryption_unsupported")
        self.tag_id = ticket.verify_id
        url = f"wss://{self.host}:{ticket.port}/websocket"
        sess = self._session
        assert sess is not None
        try:
            self._ws = await sess.ws_connect(
                url, heartbeat=None, max_msg_size=MAX_FRAME_BYTES,
                protocols=(), receive_timeout=HANDSHAKE_TIMEOUT)
        except aiohttp.ClientError as exc:
            raise UpstreamError("kvm_ws_connect_failed") from exc

        await self._send(P.get_suite_packet(self.tag_id))
        deadline = asyncio.get_running_loop().time() + HANDSHAKE_TIMEOUT
        suite_done = False
        while asyncio.get_running_loop().time() < deadline and not suite_done:
            msg = await self._ws.receive(timeout=max(0.1, deadline - asyncio.get_running_loop().time()))
            if msg.type != aiohttp.WSMsgType.BINARY:
                if msg.type in (aiohttp.WSMsgType.CLOSE, aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.ERROR):
                    raise UpstreamError("kvm_ws_closed_during_handshake")
                continue
            for payload in self._feed(msg.data):
                if payload and payload[0] == P.RSP_SUITE:
                    suite = P.parse_suite(payload)
                    if suite is None:
                        raise UpstreamError("kvm_suite_unsupported")
                    _hmac, iterations = suite
                    await self._send(P.set_suite_packet(self.tag_id, 3, iterations))
                    await self._send(P.connect_packet(self.tag_id))
                    suite_done = True
            await self._send(P.heartbeat_packet(self.tag_id))
        if not suite_done:
            raise UpstreamError("kvm_handshake_timeout")

        deadline = asyncio.get_running_loop().time() + HANDSHAKE_TIMEOUT
        seen_image = False
        while asyncio.get_running_loop().time() < deadline and not seen_image:
            msg = await self._ws.receive(timeout=max(0.1, deadline - asyncio.get_running_loop().time()))
            if msg.type != aiohttp.WSMsgType.BINARY:
                if msg.type in (aiohttp.WSMsgType.CLOSE, aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.ERROR):
                    raise UpstreamError("kvm_ws_closed_after_connect")
                continue
            for payload in self._feed(msg.data):
                if not payload:
                    continue
                if payload[0] == P.H_CMD_CONNECT_STATE and len(payload) >= 3 and payload[2] not in (0, 1):
                    raise UpstreamError("kvm_connect_rejected")
                if payload[0] == P.H_CMD_IMAGE and len(payload) >= 19:
                    if ((payload[2] << 8) | payload[3]) == 0:
                        self.framebuffer_width = ((payload[9] << 8) | payload[10]) & 0x7FFF
                        self.framebuffer_height = (payload[11] << 8) | payload[12]
                    seen_image = True
            await self._send(P.heartbeat_packet(self.tag_id))
        self.connected = True

    async def _send(self, data: bytes) -> None:
        if self._ws is None or self._ws.closed:
            raise UpstreamError("kvm_ws_not_open")
        await self._ws.send_bytes(data)

    def _feed(self, data: bytes) -> list[bytes]:
        self._buf.extend(data)
        frames, self._buf = P.parse_messages(self._buf)
        return frames

    async def frames(self) -> AsyncIterator[tuple[bytes, int, int, int]]:
        ws = self._ws
        if ws is None:
            raise UpstreamError("kvm_ws_not_open")
        try:
            async for msg in ws:
                if msg.type != aiohttp.WSMsgType.BINARY:
                    if msg.type in (aiohttp.WSMsgType.CLOSE, aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.ERROR):
                        break
                    continue
                await self._send(P.heartbeat_packet(self.tag_id))
                for payload in self._feed(msg.data):
                    if not payload or payload[0] != P.H_CMD_IMAGE:
                        continue
                    done = self.assembler.feed(payload)
                    if done is not None:
                        blocks, w, h, q = done
                        self.frame_count += 1
                        yield blocks, w, h, q
        except aiohttp.ClientError as exc:
            raise UpstreamError("kvm_stream_error") from exc

    async def send_input(self, data: bytes) -> None:
        await self._send(data)

    async def close(self) -> bool:
        had = self._ws is not None or self._session is not None
        self._ws = None
        if self._session is not None:
            await self._session.close()
            self._session = None
        self.connected = False
        return had


def _insecure_ssl() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx
