"""Strict, offline Huawei candidate decoder. Legacy gateway never imports it."""
from dataclasses import dataclass
from io import BytesIO

from .framebuffer import Framebuffer, Raw, Rect, Update, geometry

BLOCK = 64
MAX_SOURCE_BYTES = 8 * 1024 * 1024


@dataclass(frozen=True)
class Tile:
    pixels: bytes
    jpeg: bytes


@dataclass(frozen=True)
class Decoded:
    update: Update
    jpegs: tuple


class HuaweiDecoder:
    def __init__(self):
        self.framebuffer = None
        self.blocks = {}

    @staticmethod
    def _tile(blob):
        from PIL import Image
        with Image.open(BytesIO(blob)) as image:
            if image.format != 'JPEG' or image.size != (BLOCK, BLOCK):
                raise ValueError('video_jpeg_geometry_invalid')
            rgb = image.convert('RGB').tobytes()
        bgrx = bytearray(BLOCK * BLOCK * 4)
        bgrx[0::4], bgrx[1::4], bgrx[2::4] = rgb[2::3], rgb[1::3], rgb[0::3]
        return Tile(bytes(bgrx), blob)

    def feed(self, stream, width, height, header):
        geometry(width, height)
        if (type(stream) is not bytes or len(stream) > MAX_SOURCE_BYTES
                or type(header) is not bytes or len(header) > 4096):
            raise ValueError('video_source_budget')
        resized = (self.framebuffer is None or
                   (self.framebuffer.width, self.framebuffer.height) != (width, height))
        if resized:
            epoch = self.framebuffer.epoch + 1 if self.framebuffer else 1
            framebuffer, cache = Framebuffer(width, height, epoch=epoch), {}
        else:
            framebuffer, cache = self.framebuffer, self.blocks.copy()
        cols, rows = (width + BLOCK - 1) // BLOCK, (height + BLOCK - 1) // BLOCK
        operations, jpegs = [], []
        offset, index = 0, 0
        while offset < len(stream):
            if index >= cols * rows:
                raise ValueError('video_block_count_invalid')
            kind = stream[offset] >> 5
            if kind in (2, 3):
                if offset + 3 > len(stream):
                    raise ValueError('video_block_truncated')
                size = int.from_bytes(stream[offset + 1:offset + 3], 'big')
                if size == 0 or offset + 3 + size > len(stream):
                    raise ValueError('video_block_truncated')
                blob = header + stream[offset + 3:offset + 3 + size] + b'\xff\xd9'
                try:
                    tile = self._tile(blob)
                except (OSError, SyntaxError) as exc:
                    raise ValueError('video_jpeg_invalid') from exc
                offset += 3 + size
            elif kind in (5, 6):
                source = index - cols if kind == 5 else index - 1
                if source < 0 or (kind == 6 and index % cols == 0) or source not in cache:
                    raise ValueError('video_copy_uninitialized')
                tile = cache[source]
                offset += 1
            elif kind == 4:
                offset += 1
                index += 1
                continue
            else:
                raise ValueError('video_block_kind_unknown')
            cache[index] = tile
            x, y = index % cols * BLOCK, index // cols * BLOCK
            w, h = min(BLOCK, width - x), min(BLOCK, height - y)
            rect = Rect(x, y, w, h)
            data = b''.join(tile.pixels[row * BLOCK * 4:row * BLOCK * 4 + w * 4] for row in range(h))
            operations.append(Raw(rect, data))
            if w == h == BLOCK:
                jpegs.append((rect, tile.jpeg))
            index += 1
        update = Update(framebuffer.epoch, framebuffer.seq + 1, tuple(operations))
        framebuffer.apply(update)
        self.framebuffer, self.blocks = framebuffer, cache
        return Decoded(update, tuple(jpegs))
