"""Standard RFB family plugin: server frames -> bounded framebuffer ops."""
import struct
import zlib

from ..video.framebuffer import (Copy, Fill, Raw, Rect, Update, MAX_RECTS,
                                 MAX_UPDATE_BYTES, geometry)
from .contract import Decoded, FamilyDecoder

_TYPE_FRAME = 0
_TYPE_BELL = 2
_TYPE_CUT = 3
_ENC_RAW = 0
_ENC_COPY = 1
_ENC_TIGHT = 7
_MAX_BUFFER = 2 * MAX_UPDATE_BYTES
_RECT = struct.Struct('>HHHHI')
_PIXEL = struct.Struct('>BBBBHHHBBBxxx')


def bgrx(rgb: bytes) -> bytes:
    if type(rgb) is not bytes or len(rgb) != 3:
        raise ValueError('transcode_family_pixel_invalid')
    return bytes((rgb[2], rgb[1], rgb[0], 0))


def _pixel_format(header: bytes) -> None:
    if not header:
        return
    if len(header) < _PIXEL.size:
        raise ValueError('transcode_family_header_invalid')
    bpp, depth, big_endian, true_colour, rmax, gmax, bmax, rs, gs, bs = \
        _PIXEL.unpack_from(header)
    if (bpp, depth, big_endian, true_colour, rmax, gmax, bmax, rs, gs, bs) != \
            (32, 24, 0, 1, 255, 255, 255, 16, 8, 0):
        raise ValueError('transcode_family_pixel_format_unsupported')


def _tight_payload_length(control: int, rect: Rect) -> int | None:
    if control & 0x80:
        return 3
    if control & 0x40:
        raise ValueError('transcode_family_encoding_unsupported')
    filter_id = control & 0x0F
    if filter_id == 0:
        return None
    raise ValueError('transcode_family_encoding_unsupported')


def _compact_length(buf: bytearray, offset: int) -> tuple[int, int]:
    size = shift = 0
    for index in range(3):
        if offset + index >= len(buf):
            raise ValueError('transcode_family_message_truncated')
        value = buf[offset + index]
        size |= (value & 0x7F) << shift
        if not value & 0x80:
            return size, offset + index + 1
        shift += 7
    raise ValueError('transcode_family_length_invalid')


class StandardRfbFamily(FamilyDecoder):
    def __init__(self):
        self.width = self.height = 0
        self.buf = bytearray()
        self.seq = 0

    def init(self, width, height, header=b''):
        geometry(width, height)
        _pixel_format(header)
        self.width, self.height = width, height
        self.buf.clear()
        self.seq = 0
        return 1

    def feed(self, stream):
        if not self.width or type(stream) is not bytes:
            raise ValueError('transcode_family_not_initialized')
        self.buf += stream
        if len(self.buf) > _MAX_BUFFER:
            raise ValueError('transcode_family_input_budget')
        operations = []
        try:
            while self._consume(operations):
                pass
        except (ValueError, zlib.error):
            self.buf.clear()
            raise
        self.seq += 1
        return Decoded(Update(1, self.seq, tuple(operations)))

    def _consume(self, operations) -> bool:
        buf = self.buf
        if not buf:
            return False
        kind = buf[0]
        if kind == _TYPE_BELL:
            if len(buf) < 1:
                return False
            del buf[:1]
            return True
        if kind == _TYPE_CUT:
            if len(buf) < 8:
                return False
            size = int.from_bytes(buf[4:8], 'big')
            if len(buf) < 8 + size or size > MAX_UPDATE_BYTES:
                if size > MAX_UPDATE_BYTES:
                    raise ValueError('transcode_family_input_budget')
                return False
            del buf[:8 + size]
            return True
        if kind != _TYPE_FRAME or len(buf) < 4:
            if kind not in (_TYPE_FRAME, _TYPE_BELL, _TYPE_CUT):
                raise ValueError('transcode_family_message_unsupported')
            return False
        count = int.from_bytes(buf[2:4], 'big')
        if count > MAX_RECTS:
            raise ValueError('transcode_family_rects_budget')
        offset = 4
        staged = []
        total = 0
        for _ in range(count):
            if offset + _RECT.size > len(buf):
                return False
            x, y, w, h, encoding = _RECT.unpack_from(buf, offset)
            rect = Rect(x, y, w, h)
            rect.validate(self.width, self.height)
            cursor = offset + _RECT.size
            if encoding == _ENC_RAW:
                length = w * h * 4
                if cursor + length > len(buf):
                    return False
                if length > MAX_UPDATE_BYTES:
                    raise ValueError('transcode_family_input_budget')
                staged.append(Raw(rect, bytes(buf[cursor:cursor + length])))
                cursor += length
            elif encoding == _ENC_COPY:
                if cursor + 4 > len(buf):
                    return False
                sx, sy = struct.unpack_from('>HH', buf, cursor)
                Rect(sx, sy, w, h).validate(self.width, self.height)
                staged.append(Copy(rect, sx, sy))
                cursor += 4
            elif encoding == _ENC_TIGHT:
                if cursor + 1 > len(buf):
                    return False
                control = buf[cursor]
                cursor += 1
                if control & 0x80:
                    if cursor + 3 > len(buf):
                        return False
                    staged.append(Fill(rect, bgrx(bytes(buf[cursor:cursor + 3]))))
                    cursor += 3
                else:
                    length, cursor = _compact_length(buf, cursor)
                    if length > MAX_UPDATE_BYTES or cursor + length > len(buf):
                        if length > MAX_UPDATE_BYTES:
                            raise ValueError('transcode_family_input_budget')
                        return False
                    rgb = zlib.decompress(bytes(buf[cursor:cursor + length]))
                    if len(rgb) != w * h * 3:
                        raise ValueError('transcode_family_raw_invalid')
                    pixels = bytearray(w * h * 4)
                    pixels[0::4], pixels[1::4], pixels[2::4] = rgb[2::3], rgb[1::3], rgb[0::3]
                    staged.append(Raw(rect, bytes(pixels)))
                    cursor += length
            else:
                raise ValueError('transcode_family_encoding_unsupported')
            total += 4 * w * h
            if total > MAX_UPDATE_BYTES:
                raise ValueError('transcode_family_input_budget')
            offset = cursor
        del buf[:offset]
        operations.extend(staged)
        return True
