"""Bounded standard 32bpp RFB output; Tight uses independently reset stream 0."""
import struct
import zlib

from .framebuffer import MAX_HEIGHT, MAX_WIDTH, Snapshot


def compact_length(size):
    if not 0 <= size <= 0x3FFFFF:
        raise ValueError('tight_payload_too_large')
    out = bytearray()
    for _ in range(2):
        if size < 128:
            out.append(size)
            return bytes(out)
        out.append((size & 127) | 128)
        size >>= 7
    out.append(size)
    return bytes(out)


def encode_snapshot(snapshot: Snapshot, *, tight=True, max_message=65536, limit=None,
                    rgbx=False):
    width, height = limit or (MAX_WIDTH, MAX_HEIGHT)
    r = snapshot.rect
    r.validate(width, height)
    if len(snapshot.pixels) != r.w * r.h * 4 or r.w < 1 or r.h < 1:
        raise ValueError('video_raw_size_invalid')
    if max_message < 64 or r.w * 4 + 16 > max_message:
        raise ValueError('video_message_budget')
    rows = max(1, (max_message - 16) // (r.w * 4))
    for top in range(0, r.h, rows):
        height = min(rows, r.h - top)
        bgrx = snapshot.pixels[top * r.w * 4:(top + height) * r.w * 4]
        if rgbx:
            raw = bytearray(bgrx)
            raw[0::4], raw[2::4] = bgrx[2::4], bgrx[0::4]
            payload = bytes(raw)
        else:
            payload = bgrx
        encoding = 0
        if tight:
            rgb = bytearray(len(bgrx) // 4 * 3)
            rgb[0::3], rgb[1::3], rgb[2::3] = bgrx[2::4], bgrx[1::4], bgrx[0::4]
            if rgb == rgb[:3] * (len(rgb) // 3):
                payload, encoding = b'\x80' + bytes(rgb[:3]), 7
            elif len(rgb) < 12:
                payload, encoding = b'\x01' + bytes(rgb), 7
            else:
                stream = zlib.compressobj(level=1)
                compressed = stream.compress(rgb) + stream.flush(zlib.Z_SYNC_FLUSH)
                candidate = b'\x01' + compact_length(len(compressed)) + compressed
                if len(candidate) < len(bgrx):
                    payload, encoding = candidate, 7
        message = struct.pack('>BBHHHHHi', 0, 0, 1, r.x, r.y + top, r.w, height, encoding) + payload
        if len(message) > max_message:
            raise ValueError('video_message_budget')
        yield message
