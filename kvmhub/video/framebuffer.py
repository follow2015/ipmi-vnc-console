"""Bounded BGRX framebuffer with atomic updates and explicit coverage."""
from dataclasses import dataclass

MAX_WIDTH = 4096
MAX_HEIGHT = 2160
MAX_PIXELS = MAX_WIDTH * MAX_HEIGHT
MAX_RECTS = 4096
MAX_UPDATE_BYTES = 40 * 1024 * 1024


@dataclass(frozen=True)
class Rect:
    x: int
    y: int
    w: int
    h: int

    def validate(self, width, height):
        if (any(type(v) is not int for v in (self.x, self.y, self.w, self.h))
                or min(self.x, self.y) < 0 or min(self.w, self.h) <= 0
                or self.x + self.w > width or self.y + self.h > height):
            raise ValueError('video_rect_invalid')

    def intersection(self, other):
        x, y = max(self.x, other.x), max(self.y, other.y)
        right, bottom = min(self.x + self.w, other.x + other.w), min(self.y + self.h, other.y + other.h)
        return Rect(x, y, right - x, bottom - y) if right > x and bottom > y else None

    def subtract(self, other):
        cut = self.intersection(other)
        if cut is None:
            return [self]
        result = []
        for x, y, w, h in (
            (self.x, self.y, self.w, cut.y - self.y),
            (self.x, cut.y + cut.h, self.w, self.y + self.h - cut.y - cut.h),
            (self.x, cut.y, cut.x - self.x, cut.h),
            (cut.x + cut.w, cut.y, self.x + self.w - cut.x - cut.w, cut.h),
        ):
            if w > 0 and h > 0:
                result.append(Rect(x, y, w, h))
        return result


@dataclass(frozen=True)
class Raw:
    rect: Rect
    pixels: bytes


@dataclass(frozen=True)
class Fill:
    rect: Rect
    pixel: bytes


@dataclass(frozen=True)
class Copy:
    rect: Rect
    source_x: int
    source_y: int


@dataclass(frozen=True)
class Update:
    epoch: int
    seq: int
    operations: tuple


@dataclass(frozen=True)
class Snapshot:
    epoch: int
    seq: int
    rect: Rect
    pixels: bytes


def geometry(width, height):
    if (type(width) is not int or type(height) is not int or min(width, height) <= 0
            or width > MAX_WIDTH or height > MAX_HEIGHT or width * height > MAX_PIXELS):
        raise ValueError('video_geometry_invalid')


class Framebuffer:
    def __init__(self, width, height, *, epoch=1):
        self.epoch = 0
        self.seq = 0
        self.resize(epoch, width, height)

    def resize(self, epoch, width, height):
        geometry(width, height)
        if type(epoch) is not int or epoch <= self.epoch:
            raise ValueError('video_epoch_invalid')
        pixels = bytearray(width * height * 4)
        coverage = bytearray(width * height)
        self.width, self.height, self.epoch = width, height, epoch
        self.seq, self.pixels, self.coverage = 0, pixels, coverage

    def _covered(self, coverage, rect):
        return all(all(coverage[y * self.width + rect.x:y * self.width + rect.x + rect.w])
                   for y in range(rect.y, rect.y + rect.h))

    def _read(self, pixels, rect):
        return b''.join(pixels[(y * self.width + rect.x) * 4:(y * self.width + rect.x + rect.w) * 4]
                        for y in range(rect.y, rect.y + rect.h))

    def snapshot(self, rect):
        rect.validate(self.width, self.height)
        if not self._covered(self.coverage, rect):
            return None
        return Snapshot(self.epoch, self.seq, rect, self._read(self.pixels, rect))

    def apply(self, update):
        if (type(update.epoch) is not int or update.epoch != self.epoch
                or type(update.seq) is not int or update.seq != self.seq + 1):
            raise ValueError('video_sequence_invalid')
        if type(update.operations) is not tuple or len(update.operations) > MAX_RECTS:
            raise ValueError('video_update_too_large')
        size = 0
        for op in update.operations:
            if type(op) not in (Raw, Fill, Copy):
                raise ValueError('video_operation_invalid')
            op.rect.validate(self.width, self.height)
            if type(op) is Raw:
                if type(op.pixels) is not bytes or len(op.pixels) != op.rect.w * op.rect.h * 4:
                    raise ValueError('video_raw_size_invalid')
                size += len(op.pixels)
            elif type(op) is Fill:
                if type(op.pixel) is not bytes or len(op.pixel) != 4:
                    raise ValueError('video_fill_invalid')
                size += 4
            else:
                Rect(op.source_x, op.source_y, op.rect.w, op.rect.h).validate(self.width, self.height)
            if size > MAX_UPDATE_BYTES:
                raise ValueError('video_update_too_large')
        pixels, coverage = self.pixels.copy(), self.coverage.copy()
        for op in update.operations:
            r = op.rect
            if type(op) is Copy:
                source = Rect(op.source_x, op.source_y, r.w, r.h)
                if not self._covered(coverage, source):
                    raise ValueError('video_copy_uninitialized')
                data = self._read(pixels, source)
            else:
                data = op.pixels if type(op) is Raw else op.pixel * (r.w * r.h)
            for row in range(r.h):
                offset = ((r.y + row) * self.width + r.x) * 4
                pixels[offset:offset + r.w * 4] = data[row * r.w * 4:(row + 1) * r.w * 4]
                c = (r.y + row) * self.width + r.x
                coverage[c:c + r.w] = b'\x01' * r.w
        self.pixels, self.coverage, self.seq = pixels, coverage, update.seq
        return tuple(op.rect for op in update.operations)
