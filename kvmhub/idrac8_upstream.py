"""Server-side iDRAC8 HTML5 KVM upstream (HTTP login + WSS/APCP/AVSP)."""
from __future__ import annotations

import asyncio
import json
import logging
import re
import secrets
import ssl
from dataclasses import dataclass
from typing import AsyncIterator

import aiohttp

from .idrac8_dvc import DvcDecompressor, VidsFrame, VidsFrameAssembler
from .idrac8_protocol import (
    APCP_REQUEST,
    APCP_SECONDARY_VIDEO,
    APCP_SESSION_ID,
    VIDEO_ENABLE_PRIMARY_FRAMES,
    Capabilities,
    ProtocolError,
    build_apcp_control,
    build_client_info,
    build_session_close,
    build_session_setup,
    build_video_channel_auth,
    build_video_enable,
    build_video_socket_auth,
    parse_apcp_header,
    parse_beef_header,
    parse_capabilities,
)

logger = logging.getLogger(__name__)

FRAME_GAP_S = 0.12

CLIENT_INFO_JSON = bytes.fromhex(
    "7b22636c69656e745f74797065223a202248544d4c35222c2276657273696f6e223a2022312e31302e38222c"
    "22656e6372797074696f6e5f74797065223a20226e6f6e65222c22656e6372797074696f6e5f76657273696f6e22"
    "3a202230222c224f532f62726f77736572223a202257696e646f777337222c2270726f746f636f6c73223a207b20"
    "2241504350223a207b2276657273696f6e223a2022312e33227d2c2241564d50223a207b2276657273696f6e223a"
    "2022312e3133227d2c2241565350223a207b2276657273696f6e223a2022322e3430227d2c224b564d58223a207b"
    "2276657273696f6e223a2022312e"
)

BEEF_AUTH_HEADER = b"BEEF" + bytes([0x01, 0x02, 0x00, 0xD9])
LOGIN_PAYLOAD_SIZE = 209


class UpstreamError(RuntimeError):
    pass


@dataclass(frozen=True)
class TempCredentials:
    user: str
    password: str
    aim_session: str
    cookie: str = ""


def _session_cookie(response: object, session: aiohttp.ClientSession) -> str:
    pairs: list[str] = []
    headers = getattr(response, "headers", None)
    raw_cookies = headers.getall("Set-Cookie", []) if headers is not None else []
    for raw in raw_cookies:
        pair = raw.split(";", 1)[0].strip()
        if "=" in pair:
            pairs.append(pair)
    if not pairs:
        pairs = [
            f"{morsel.key}={morsel.value}"
            for morsel in getattr(session, "cookie_jar", [])
        ]
    return "; ".join(pairs)


def build_user_login_request(
    user: str,
    password: str,
    *,
    client_random: int = 59,
    port_id: bytes = b"",
    channel_id: bytes = b"",
    shared_mode: int = 0,
) -> bytes:
    if not (0 <= client_random <= 0xFFFFFFFF):
        raise UpstreamError("client_random_out_of_range")
    if len(port_id) > 255 or len(channel_id) > 255:
        raise UpstreamError("identifier_too_long")
    body = bytearray()
    body.append(len(user))
    body += user.encode("utf-8")[:96].ljust(96, b"\x00")
    body.append(len(password))
    body += password.encode("utf-8")[:96].ljust(96, b"\x00")
    body += bytes(8)
    body.append(len(port_id))
    body.append(len(channel_id))
    body += client_random.to_bytes(4, "big")
    body.append(shared_mode)
    if len(body) != LOGIN_PAYLOAD_SIZE:
        raise UpstreamError(f"login_payload_size:{len(body)}")
    return BEEF_AUTH_HEADER + bytes(body)


def parse_user_login_request(frame: bytes) -> dict[str, object]:
    if len(frame) != 8 + LOGIN_PAYLOAD_SIZE or frame[:4] != b"BEEF":
        raise ProtocolError("bad_user_login_frame")
    body = frame[8:]
    user_len = body[0]
    pass_len = body[97]
    return {
        "user": body[1:1 + user_len].decode("utf-8", "replace"),
        "password": body[98:98 + pass_len].decode("utf-8", "replace"),
        "reserved": body[194:202],
        "port_id": body[202],
        "channel_id": body[203],
        "client_random": int.from_bytes(body[204:208], "big"),
        "shared_mode": body[208],
    }


def to_rfb_rgb24(pixels: list[int]) -> bytes:
    out = bytearray(len(pixels) * 3)
    for index, value in enumerate(pixels):
        out[index * 3] = (value >> 16) & 0xFF
        out[index * 3 + 1] = (value >> 8) & 0xFF
        out[index * 3 + 2] = value & 0xFF
    return bytes(out)


class Idrac8Upstream:

    def __init__(
        self,
        host: str,
        port: int = 5900,
        username: str = "root",
        password: str = "calvin",
        *,
        verify_tls: bool | ssl.SSLContext = False,
        timeout: float = 20.0,
        client_random: int | None = None,
    ) -> None:
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.verify_tls = verify_tls
        self.timeout = timeout
        self.client_random = (secrets.randbelow(0xFFFFFFFF + 1)
                              if client_random is None else client_random)
        self._http: aiohttp.ClientSession | None = None
        self._ws: aiohttp.ClientWebSocketResponse | None = None
        self._video_ws: aiohttp.ClientWebSocketResponse | None = None
        self._drain_task: asyncio.Task[None] | None = None
        self._assembler = VidsFrameAssembler()
        self.capabilities: Capabilities | None = None
        self._session_cookie: str = ""

    @property
    def base_url(self) -> str:
        return f"https://{self.host}"

    @property
    def ws_url(self) -> str:
        return f"wss://{self.host}:{self.port}/"

    async def _fetch_temp_credentials(self, session: aiohttp.ClientSession) -> TempCredentials:
        response = await session.post(
            self.base_url + "/data/login",
            data={"user": self.username, "password": self.password},
            headers={"Referer": self.base_url + "/login.html"},
            timeout=aiohttp.ClientTimeout(total=self.timeout),
        )
        body = await response.text()
        st1 = re.search(r"ST1=([0-9a-fA-F]+)", body)
        st2 = re.search(r"ST2=([0-9a-fA-F]+)", body)
        if response.status != 200 or not st1 or not st2:
            raise UpstreamError("idrac_login_failed")

        cookie = _session_cookie(response, session)
        cookie = f"{cookie}; tokenvalue={st1.group(1)}".strip("; ")
        st2 = st2.group(1)

        response = await session.get(
            self.base_url + "/session?getSsnVar="
            "aimSession,username,loginToDRAC,accessConsoleRedirection",
            headers={"Cookie": cookie, "ST2": st2,
                     "X-Requested-With": "XMLHttpRequest"},
            timeout=aiohttp.ClientTimeout(total=self.timeout),
        )
        try:
            ssn = json.loads(await response.text())
            aim = ssn["getSsnVar"]["aimSession"]
        except (ValueError, KeyError, TypeError) as exc:
            raise UpstreamError("aim_session_unavailable") from exc

        response = await session.get(
            self.base_url + f"/session?setTempCredential={aim}",
            headers={"Cookie": cookie, "ST2": st2},
            timeout=aiohttp.ClientTimeout(total=self.timeout),
        )
        try:
            prop = json.loads(await response.text())["aimGetProp"]
            user, password = prop["tempUser"], prop["tempPass"]
        except (ValueError, KeyError, TypeError) as exc:
            raise UpstreamError("temp_credentials_unavailable") from exc
        if not user or not password:
            raise UpstreamError("temp_credentials_empty")
        return TempCredentials(user, password, str(aim), cookie)

    async def _open_socket(self, cookie: str) -> aiohttp.ClientWebSocketResponse:
        assert self._http is not None
        return await self._http.ws_connect(
            self.ws_url,
            protocols=["lws-dvc-protocol"],
            headers={"Cookie": cookie},
            ssl=self.verify_tls,
            heartbeat=None,
            timeout=aiohttp.ClientTimeout(total=self.timeout),
        )

    @staticmethod
    async def _receive_binary(ws: aiohttp.ClientWebSocketResponse,
                              timeout: float) -> bytes:
        message = await asyncio.wait_for(ws.receive(), timeout)
        if message.type != aiohttp.WSMsgType.BINARY:
            raise UpstreamError("handshake_socket_closed")
        return message.data

    async def _paced_send(self, ws: aiohttp.ClientWebSocketResponse,
                          frame: bytes) -> None:
        await ws.send_bytes(frame)
        await asyncio.sleep(FRAME_GAP_S)

    async def _drain_primary_once(
            self, ws: aiohttp.ClientWebSocketResponse) -> bytes | None:
        session_id: bytes | None = None
        for _ in range(8):
            try:
                message = await asyncio.wait_for(ws.receive(), 0.05)
            except asyncio.TimeoutError:
                break
            if message.type in (aiohttp.WSMsgType.CLOSE, aiohttp.WSMsgType.CLOSED,
                                aiohttp.WSMsgType.CLOSING, aiohttp.WSMsgType.ERROR):
                break
            if message.type != aiohttp.WSMsgType.BINARY:
                continue
            frame = message.data
            if (frame[:4] == b"APCP" and len(frame) > 11
                    and frame[9] == APCP_SESSION_ID):
                session_id = frame
        return session_id

    async def _drain_primary(self, ws: aiohttp.ClientWebSocketResponse) -> None:
        try:
            while True:
                message = await ws.receive()
                if message.type in (aiohttp.WSMsgType.CLOSE, aiohttp.WSMsgType.CLOSED,
                                    aiohttp.WSMsgType.CLOSING, aiohttp.WSMsgType.ERROR):
                    return
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # pragma: no cover - transport failure path
            logger.debug("iDRAC8 primary drain stopped: %s", type(exc).__name__)

    async def _open_video_channel(self, cookie: str) -> None:
        assert self._ws is not None
        session_id_response: bytes | None = None
        post_login_frames = (
            build_apcp_control(APCP_REQUEST, APCP_SECONDARY_VIDEO, 0x00, bytes(4)),
            build_apcp_control(0x01, APCP_SESSION_ID, 0x00,
                               bytes(2) + bytes([1]) + bytes(33)),
            build_video_channel_auth(),
            build_video_enable(),
        )
        for index, frame in enumerate(post_login_frames):
            try:
                await self._ws.send_bytes(frame)
            except Exception as exc:
                logger.warning("iDRAC8 post-login frame %d send failed: %s",
                               index, type(exc).__name__)
                raise
            await asyncio.sleep(FRAME_GAP_S)
            reply = await self._drain_primary_once(self._ws)
            session_id_response = session_id_response or reply

        if session_id_response is None:
            for _ in range(8):
                frame = await self._receive_binary(self._ws, self.timeout)
                if (frame[:4] == b"APCP" and len(frame) > 11
                        and frame[9] == APCP_SESSION_ID):
                    session_id_response = frame
                    break
        if session_id_response is None:
            raise UpstreamError("video_session_id_timeout")

        self._video_ws = await self._open_socket(cookie)
        await self._video_ws.send_bytes(build_session_setup(secondary=True))
        response = await self._receive_binary(self._video_ws, self.timeout)
        header = parse_apcp_header(response)
        if not header.is_response or header.command != 0x04:
            raise UpstreamError("video_session_setup_rejected")
        await self._video_ws.send_bytes(build_video_socket_auth(self.client_random))

        for index, frame in enumerate(VIDEO_ENABLE_PRIMARY_FRAMES):
            try:
                await self._ws.send_bytes(frame)
            except Exception as exc:
                logger.warning("iDRAC8 video-enable frame %d send failed: %s",
                               index, type(exc).__name__)
                raise
            await asyncio.sleep(FRAME_GAP_S)
            await self._drain_primary_once(self._ws)

        self._drain_task = asyncio.create_task(self._drain_primary(self._ws))

    async def connect(self) -> Capabilities:
        self._http = aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(ssl=self.verify_tls)
        )
        try:
            creds = await self._fetch_temp_credentials(self._http)
            self._session_cookie = creds.cookie
            self._ws = await self._open_socket(creds.cookie)
            await self._ws.send_bytes(build_session_setup())
            setup_response = await self._receive_binary(self._ws, self.timeout)
            header = parse_apcp_header(setup_response)
            if not header.is_response or header.command != 0x04:
                raise UpstreamError("session_setup_rejected")

            await self._ws.send_bytes(build_client_info(CLIENT_INFO_JSON))
            await self._ws.send_bytes(
                build_user_login_request(creds.user, creds.password,
                                         client_random=self.client_random),
            )

            for _ in range(12):
                frame = await self._receive_binary(self._ws, self.timeout)
                if frame[:4] == b"BEEF":
                    continue
                if frame[:4] == b"APCP" and len(frame) > 1000:
                    self.capabilities = parse_capabilities(frame[20:])
                    break
            else:
                raise UpstreamError("capabilities_timeout")
            if self.capabilities is None:
                raise UpstreamError("capabilities_timeout")
            if self.capabilities.video_on_secondary_socket:
                await self._open_video_channel(creds.cookie)
            return self.capabilities
        except Exception as exc:
            logger.warning("iDRAC8 handshake failed: %s: %s",
                           type(exc).__name__, getattr(exc, "code", "") or str(exc)[:120])
            await self.close()
            raise

    async def read_frame(self) -> VidsFrame | None:
        ws = self._video_ws or self._ws
        if ws is None:
            raise UpstreamError("upstream_not_connected")
        while True:
            message = await asyncio.wait_for(ws.receive(), self.timeout)
            if message.type in (aiohttp.WSMsgType.CLOSE, aiohttp.WSMsgType.CLOSED):
                return None
            if message.type != aiohttp.WSMsgType.BINARY:
                continue
            frame = message.data
            if frame[:4] != b"VIDS":
                continue
            complete = self._assembler.feed(frame)
            if complete is not None:
                return complete

    async def frames(self) -> AsyncIterator[VidsFrame]:
        while True:
            frame = await self.read_frame()
            if frame is None:
                return
            yield frame

    def decoder(self) -> DvcDecompressor:
        return DvcDecompressor(1024, 768, color_depth=15)

    async def close(self) -> None:
        task = self._drain_task
        self._drain_task = None
        if task is not None:
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass
        ws, video, http = self._ws, self._video_ws, self._http
        self._ws, self._video_ws, self._http = None, None, None
        for sock in (video, ws):
            if sock is not None:
                try:
                    await sock.send_bytes(build_session_close())
                except Exception:
                    pass
                if sock is ws:
                    try:
                        await asyncio.wait_for(sock.receive(), 0.15)
                    except Exception:
                        pass
                try:
                    await sock.close()
                except Exception:
                    pass
        if http is not None:
            try:
                headers = {"Cookie": self._session_cookie} if self._session_cookie else {}
                await http.get(self.base_url + "/data/logout", headers=headers,
                               timeout=aiohttp.ClientTimeout(total=self.timeout))
            except Exception:
                pass
            await http.close()
        self._session_cookie = ""
        self.capabilities = None

    async def __aenter__(self) -> "Idrac8Upstream":
        await self.connect()
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.close()
