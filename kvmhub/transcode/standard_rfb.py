"""Standard RFB family plugin: server frames -> bounded framebuffer ops.

Only the encodings the platform's northbound encoder can re-emit are accepted:
Raw, CopyRect and one Tight subset — fill (subencoding 8) and basic copy-filter
on the independent zlib stream 0 (subencoding 0). Anything else rejects the
whole update.

Tight's control byte is *not* a bit flag: the high nibble is the subencoding and
the low nibble says which zlib streams to reset. JPEG (9) and PNG (10) reuse the
0x80 bit, so testing ``control & 0x80`` for "fill" would read a JPEG header as a
colour. The parser below therefore switches on the nibble and rejects
palette/gradient filters, streams 1-3, continued streams and JPEG/PNG by name.
"""
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
_TIGHT_FILL = 8
_TIGHT_JPEG = 9
_TIGHT_PNG = 10
#: Tight sends uncompressed pixels without a length prefix below this size.
_TIGHT_RAW_BELOW = 12
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
        #: True once a basic rect has been decoded. A later basic rect without
        #: the reset bit continues a zlib stream whose state is not kept here.
        self._tight_stream = False

    def init(self, width, height, header=b''):
        geometry(width, height)
        _pixel_format(header)
        self.width, self.height = width, height
        self.buf.clear()
        self.seq = 0
        self._tight_stream = False
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
            # A malformed message invalidates the whole feed: no half-applied
            # rectangle may survive, and the framing state must not keep the
            # rejected bytes for the next update.
            self.buf.clear()
            raise
        self.seq += 1
        return Decoded(Update(1, self.seq, tuple(operations)))

    def _tight_rect(self, buf, cursor, rect):
        """Parse one Tight rect; None means the message is still incomplete.

        Accepted: fill, and basic copy-filter on a freshly reset stream 0.
        Rejected by name: JPEG, PNG, palette/gradient filters, streams 1-3 and
        continued streams. The northbound encoder cannot re-emit them, and
        guessing would corrupt pixels instead of failing the frame.
        """
        if cursor >= len(buf):
            return None
        control = buf[cursor]
        cursor += 1
        subencoding = control >> 4
        if subencoding == _TIGHT_FILL:
            if cursor + 3 > len(buf):
                return None
            return Fill(rect, bgrx(bytes(buf[cursor:cursor + 3]))), cursor + 3
        if subencoding in (_TIGHT_JPEG, _TIGHT_PNG) or subencoding & 0x8:
            raise ValueError('transcode_family_encoding_unsupported')
        # Basic: bits 0-1 pick the zlib stream, bit 2 announces a filter byte.
        if subencoding & 0x3:
            raise ValueError('transcode_family_encoding_unsupported')
        if subencoding & 0x4:
            if cursor >= len(buf):
                return None
            filter_id = buf[cursor]
            cursor += 1
            if filter_id != 0:
                raise ValueError('transcode_family_encoding_unsupported')
        if not (control & 0x01) and self._tight_stream:
            raise ValueError('transcode_family_encoding_unsupported')
        size = rect.w * rect.h * 3
        if size < _TIGHT_RAW_BELOW:
            if cursor + size > len(buf):
                return None
            rgb = bytes(buf[cursor:cursor + size])
            cursor += size
        else:
            length, cursor = _compact_length(buf, cursor)
            if length > MAX_UPDATE_BYTES:
                raise ValueError('transcode_family_input_budget')
            if cursor + length > len(buf):
                return None
            # Tight streams are flushed with Z_SYNC_FLUSH, so they are not
            # self-terminating; zlib.decompress() would reject every real
            # source. Decompress with an explicit output bound instead.
            inflater = zlib.decompressobj()
            rgb = inflater.decompress(bytes(buf[cursor:cursor + length]), size)
            cursor += length
            if inflater.unconsumed_tail:
                raise ValueError('transcode_family_raw_invalid')
        if len(rgb) != size:
            raise ValueError('transcode_family_raw_invalid')
        pixels = bytearray(rect.w * rect.h * 4)
        pixels[0::4], pixels[1::4], pixels[2::4] = rgb[2::3], rgb[1::3], rgb[0::3]
        self._tight_stream = True
        return Raw(rect, bytes(pixels)), cursor

    def _consume(self, operations) -> bool:
        """Consume one complete server message; False means need more bytes."""
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
                parsed = self._tight_rect(buf, cursor, rect)
                if parsed is None:
                    return False
                operation, cursor = parsed
                staged.append(operation)
            else:
                raise ValueError('transcode_family_encoding_unsupported')
            total += 4 * w * h
            if total > MAX_UPDATE_BYTES:
                raise ValueError('transcode_family_input_budget')
            offset = cursor
        del buf[:offset]
        operations.extend(staged)
        return True
