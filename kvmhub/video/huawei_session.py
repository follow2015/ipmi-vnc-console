"""Opt-in Huawei V1 browser bridge, using the isolated VideoSession core."""
import asyncio
import struct
import time

from aiohttp import WSMessage, WSMsgType

from ..huawei_kvm_input import BrowserInputTranslator, packet_command
from ..huawei_kvm_jpeg import jpeg_header
from ..huawei_kvm_protocol import C_CMD_KEYBOARD, C_CMD_MOUSE
from ..passthrough import BrowserHandshake
from ..rfb_server import RFB_PIXEL_FORMAT_32BPP, build_server_init_32bpp
from .framebuffer import Rect
from .runtime import ManagedDecoder, VideoProtocolError
from .session import VideoSession

CLIENT = 'browser'
MAX_BUFFER = 65536
MAX_PREOPEN_REQUESTS = 32


class HuaweiV1RfbSession:
    protocol = 'binary'

    def __init__(self, upstream, width, height, *, before_resync, read_only=False,
                 decoder=None):
        if before_resync is None:
            raise VideoProtocolError('video_resync_permit_missing')
        self.upstream, self.width, self.height = upstream, width, height
        self.read_only = read_only
        self.video = VideoSession(decoder=decoder or ManagedDecoder(
            before_resync=before_resync, require_resync_permit=True), tight=False)
        self.handshake = BrowserHandshake(build_server_init_32bpp(width, height, 'iBMC-KVM-V1'),
            version=b'RFB 003.008\n', security_type=BrowserHandshake.SECURITY_TYPE_NONE)
        self.input = BrowserInputTranslator(upstream.tag_id, width, height)
        self._control = asyncio.Queue(maxsize=8)
        self._wake = asyncio.Event()
        self._buf = bytearray()
        self._requests = []
        self.dropped_preopen_requests = 0
        self._relay_task = None
        self._messages = None
        self._batch = None
        self._closed = False
        self._ended = False
        self._keys = set()
        self._pointer = None
        self._quant = None
        self._input_window = time.monotonic()
        self._input_count = 0
        self.frames = self.server_bytes = self.client_bytes = 0
        self.error = None
        self.release_failed = False
        self.send_timeout = self.video.decoder.budget.output_age
        self.reload_requested = False
        self.geometry_before = self.geometry_after = None
        self.reload_reason = ''

    @property
    def closed(self):
        return self._closed

    async def start(self):
        try:
            self.video.decoder.start()
            self._control.put_nowait(self.handshake.start())
        except BaseException:
            self.video.close()
            raise

    async def send_str(self, data):
        raise VideoProtocolError('unexpected_text_frame')

    async def send_bytes(self, data):
        if self._closed:
            return
        if type(data) is not bytes or len(data) + len(self._buf) > MAX_BUFFER:
            raise VideoProtocolError('video_client_buffer_budget')
        self.client_bytes += len(data)
        if not self.handshake.completed:
            reply, data = self.handshake.feed(data)
            if reply:
                self._control.put_nowait(reply)
                self._wake.set()
            if not self.handshake.completed:
                return
            if self._relay_task is None:
                self._relay_task = asyncio.create_task(self._relay())
        self._buf.extend(data)
        while self._buf:
            kind = self._buf[0]
            size = {0: 20, 2: 4, 3: 10, 4: 8, 5: 6}.get(kind)
            if size is None:
                raise VideoProtocolError('video_client_message_denied')
            if len(self._buf) < size:
                break
            if kind == 2:
                count = int.from_bytes(self._buf[2:4], 'big')
                if count > 256:
                    raise VideoProtocolError('video_encodings_budget')
                size += count * 4
                if len(self._buf) < size:
                    break
            message = bytes(self._buf[:size])
            del self._buf[:size]
            await self._handle(message)

    async def _handle(self, message):
        kind = message[0]
        if kind == 0:
            rgbx = bytearray(RFB_PIXEL_FORMAT_32BPP)
            rgbx[10], rgbx[12] = 0, 16
            if message[4:] not in (RFB_PIXEL_FORMAT_32BPP, bytes(rgbx)):
                raise VideoProtocolError('video_pixel_format_unsupported')
            self.video.rgbx = message[4:] == bytes(rgbx)
        elif kind == 2:
            encodings = [int.from_bytes(message[i:i+4], 'big', signed=True)
                         for i in range(4, len(message), 4)]
            self.video.tight = 7 in encodings
        elif kind == 3:
            if message[1] not in (0, 1):
                raise VideoProtocolError('video_request_invalid')
            rect = Rect(*struct.unpack('>HHHH', message[2:]))
            rect.validate(self.width, self.height)
            if self.video.framebuffer is None:
                request = (rect, bool(message[1]))
                if request not in self._requests:
                    if len(self._requests) < MAX_PREOPEN_REQUESTS:
                        self._requests.append(request)
                    else:
                        self.dropped_preopen_requests += 1
            else:
                self.video.request(CLIENT, rect, incremental=bool(message[1]))
            self._wake.set()
        elif not self.read_only:
            now = time.monotonic()
            if now - self._input_window >= 1:
                self._input_window, self._input_count = now, 0
            self._input_count += 1
            if self._input_count > 240:
                raise VideoProtocolError('video_input_rate_budget')
            if kind == 4:
                if message[1] not in (0, 1) or message[2:4] != b'\0\0':
                    raise VideoProtocolError('video_key_invalid')
                key = int.from_bytes(message[4:], 'big')
                if message[1]:
                    if len(self._keys) >= 64 and key not in self._keys:
                        raise VideoProtocolError('video_keys_budget')
                    self._keys.add(key)
                else:
                    self._keys.discard(key)
            else:
                x, y = struct.unpack('>HH', message[2:])
                if x >= self.width or y >= self.height or message[1] & ~7:
                    raise VideoProtocolError('video_pointer_invalid')
                self._pointer = (x, y)
            await self._input(message)

    async def _input(self, message):
        for packet in self.input.feed(message):
            if packet_command(packet) not in (C_CMD_KEYBOARD, C_CMD_MOUSE):
                raise VideoProtocolError('video_input_command_denied')
            await self.upstream.send_input(packet)
            self.input.stats.forwarded += 1

    async def _relay(self):
        try:
            async for blocks, width, height, quant in self.upstream.frames():
                if self._closed:
                    break
                if (width, height) != (self.width, self.height):
                    self.reload_requested = True
                    self.geometry_before = {'width': self.width, 'height': self.height}
                    self.geometry_after = {'width': width, 'height': height}
                    self.reload_reason = 'video_geometry_changed'
                    break
                if self.video.framebuffer is None:
                    await self.video.open(width, height, jpeg_header(quant))
                    self._quant = quant
                    self.video.attach(CLIENT)
                    for rect, incremental in self._requests:
                        self.video.request(CLIENT, rect, incremental=incremental)
                    self._requests.clear()
                elif quant != self._quant:
                    raise VideoProtocolError('video_source_header_changed')
                await self.video.feed(blocks)
                self.frames += 1
                self._wake.set()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self.error = getattr(exc, 'code', None) or type(exc).__name__
        finally:
            self._ended = True
            self._wake.set()

    def __aiter__(self):
        return self

    async def __anext__(self):
        while not self._closed:
            if not self._control.empty():
                data = self._control.get_nowait()
                return WSMessage(WSMsgType.BINARY, data, '')
            if self._ended:
                raise StopAsyncIteration
            if self._messages is not None:
                self.video.queues[CLIENT].check()
                try:
                    data = next(self._messages)
                    self.server_bytes += len(data)
                    return WSMessage(WSMsgType.BINARY, data, '')
                except StopIteration:
                    self.video.sent(CLIENT, self._batch)
                    self._messages, self._batch = None, None
            self._wake.clear()
            if self.video.framebuffer is not None:
                self._batch = self.video.prepare(CLIENT)
                if self._batch is not None:
                    self._messages = self.video.messages(CLIENT, self._batch)
                    continue
            await self._wake.wait()
        raise StopAsyncIteration

    async def close(self, code=1000):
        if self._closed:
            return
        self._closed = True
        self._wake.set()
        if self._relay_task is not None:
            self._relay_task.cancel()
            await asyncio.gather(self._relay_task, return_exceptions=True)
        self.release_failed = False
        if not self.read_only:
            try:
                async with asyncio.timeout(1):
                    for key in sorted(self._keys):
                        await self._input(struct.pack('>BBHI', 4, 0, 0, key))
                    if self._pointer is not None:
                        await self._input(struct.pack('>BBHH', 5, 0, *self._pointer))
            except Exception:
                self.release_failed = True
                self.error = self.error or 'video_input_release_failed'
        self._keys.clear()
        self.video.close()
        self._messages = self._batch = None

    def as_dict(self):
        stream = self.video.streams.get(CLIENT)
        return {'protocol': self.protocol, 'lane': 'transcode-v1', 'frames': self.frames,
                'handshake_completed': self.handshake.completed,
                'dropped_preopen_requests': self.dropped_preopen_requests,
                'dropped_requests': getattr(stream, 'dropped_requests', 0),
                'server_bytes': self.server_bytes, 'client_bytes': self.client_bytes,
                'input_keys': self.input.stats.keys, 'input_pointers': self.input.stats.pointers,
                'input_forwarded': self.input.stats.forwarded, 'error': self.error}
