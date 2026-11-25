"""Bounded serialization of decoded framebuffer operations across the IPC pipe."""
import struct

from .framebuffer import (MAX_HEIGHT, MAX_RECTS, MAX_UPDATE_BYTES, MAX_WIDTH,
                          Copy, Fill, Raw, Rect, Update)
from .runtime import VideoProtocolError

_HEADER = struct.Struct('>III')
_OP = struct.Struct('>IIIIB')
_U32 = struct.Struct('>I')
_RAW, _FILL, _COPY = 1, 2, 3
DEFAULT_LIMIT = (MAX_WIDTH, MAX_HEIGHT)


def _limit(limit):
    if limit is None:
        return DEFAULT_LIMIT
    if type(limit) is not tuple or len(limit) != 2:
        raise VideoProtocolError('video_wire_limit_invalid')
    width, height = limit
    if (type(width) is not int or type(height) is not int
            or min(width, height) <= 0 or width > MAX_WIDTH or height > MAX_HEIGHT):
        raise VideoProtocolError('video_wire_limit_invalid')
    return width, height


def pack_update(update: Update, *, limit=None) -> bytes:
    width, height = _limit(limit)
    operations = update.operations
    if type(operations) is not tuple or len(operations) > MAX_RECTS:
        raise VideoProtocolError('video_wire_count_invalid')
    out = bytearray(_HEADER.pack(len(operations), update.epoch, update.seq))
    for op in operations:
        rect = op.rect
        rect.validate(width, height)
        if type(op) is Raw:
            if type(op.pixels) is not bytes or len(op.pixels) != rect.w * rect.h * 4:
                raise VideoProtocolError('video_wire_raw_invalid')
            out += _OP.pack(rect.x, rect.y, rect.w, rect.h, _RAW)
            out += _U32.pack(len(op.pixels)) + op.pixels
        elif type(op) is Fill:
            if type(op.pixel) is not bytes or len(op.pixel) != 4:
                raise VideoProtocolError('video_wire_fill_invalid')
            out += _OP.pack(rect.x, rect.y, rect.w, rect.h, _FILL) + op.pixel
        elif type(op) is Copy:
            Rect(op.source_x, op.source_y, rect.w, rect.h).validate(width, height)
            out += _OP.pack(rect.x, rect.y, rect.w, rect.h, _COPY)
            out += _U32.pack(op.source_x) + _U32.pack(op.source_y)
        else:
            raise VideoProtocolError('video_wire_kind_unknown')
    if len(out) > MAX_UPDATE_BYTES:
        raise VideoProtocolError('video_wire_payload_budget')
    return bytes(out)


def unpack_update(payload: bytes, *, limit=None) -> Update:
    width, height = _limit(limit)
    if type(payload) is not bytes or len(payload) < _HEADER.size:
        raise VideoProtocolError('video_wire_header_truncated')
    count, epoch, seq = _HEADER.unpack_from(payload)
    if count > MAX_RECTS or epoch < 1 or seq < 1:
        raise VideoProtocolError('video_wire_count_invalid')
    offset = _HEADER.size
    operations = []
    for _ in range(count):
        if offset + _OP.size > len(payload):
            raise VideoProtocolError('video_wire_operation_truncated')
        x, y, w, h, kind = _OP.unpack_from(payload, offset)
        offset += _OP.size
        rect = Rect(x, y, w, h)
        rect.validate(width, height)
        if kind == _RAW:
            if offset + _U32.size > len(payload):
                raise VideoProtocolError('video_wire_raw_truncated')
            size = _U32.unpack_from(payload, offset)[0]
            offset += _U32.size
            if size != w * h * 4 or offset + size > len(payload):
                raise VideoProtocolError('video_wire_raw_invalid')
            operations.append(Raw(rect, payload[offset:offset + size]))
            offset += size
        elif kind == _FILL:
            if offset + 4 > len(payload):
                raise VideoProtocolError('video_wire_fill_truncated')
            operations.append(Fill(rect, payload[offset:offset + 4]))
            offset += 4
        elif kind == _COPY:
            if offset + 2 * _U32.size > len(payload):
                raise VideoProtocolError('video_wire_copy_truncated')
            source_x, source_y = struct.unpack_from('>II', payload, offset)
            offset += 2 * _U32.size
            Rect(source_x, source_y, w, h).validate(width, height)
            operations.append(Copy(rect, source_x, source_y))
        else:
            raise VideoProtocolError('video_wire_kind_unknown')
    if offset != len(payload):
        raise VideoProtocolError('video_wire_trailing_bytes')
    return Update(epoch, seq, tuple(operations))
