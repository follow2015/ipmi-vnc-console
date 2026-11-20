"""iDRAC8 AVSP video: VIDS framing, chunk assembly and DVC decompression."""
from __future__ import annotations

import struct
from dataclasses import dataclass, field, replace

FLAG_SOF = 0x01
FLAG_EOF = 0x02
FLAG_REF = 0x04
FLAG_ALPHA = 0x08
FLAG_SOB = 0x10
FLAG_EOB = 0x20
FLAG_PALLET = 0x40
FLAG_PACKED = 0x80

OP_ADVANCE = 0x00
OP_FILL = 0x20
OP_COPY = 0x40
OP_PATTERN = 0x60
OP_RAW = 0x80


class DvcError(ValueError):
    pass


@dataclass(frozen=True)
class VidsFrame:
    magic: str
    frame_length: int
    flags: int
    x_resolution: int
    y_resolution: int
    payload: bytes

    @property
    def is_sof(self) -> bool:
        return bool(self.flags & FLAG_SOF)

    @property
    def is_eof(self) -> bool:
        return bool(self.flags & FLAG_EOF)

    @property
    def is_ref(self) -> bool:
        return bool(self.flags & FLAG_REF)

    @property
    def is_sob(self) -> bool:
        return bool(self.flags & FLAG_SOB)

    @property
    def is_packed(self) -> bool:
        return bool(self.flags & FLAG_PACKED)


def parse_vids(frame: bytes) -> VidsFrame:
    if len(frame) < 20 or frame[:4] != b"VIDS":
        raise DvcError("bad_vids_magic_or_truncated")
    declared = struct.unpack(">H", frame[6:8])[0]
    if declared != len(frame):
        raise DvcError(f"vids_length_mismatch:{declared}!={len(frame)}")
    if frame[8:12] != b"\xde\xad\xbe\xef":
        raise DvcError("bad_vids_marker")
    y_res, x_res = struct.unpack(">HH", frame[12:16])
    return VidsFrame("VIDS", declared, frame[16], x_res, y_res, frame[20:])


@dataclass
class VidsFrameAssembler:

    _buffer: bytearray = field(default_factory=bytearray, repr=False)
    _active: bool = False

    def feed(self, frame: bytes) -> VidsFrame | None:
        vids = parse_vids(frame)
        if vids.is_sob or vids.is_sof:
            self._buffer = bytearray()
            self._active = True
        if not self._active:
            return None
        self._buffer.extend(vids.payload)
        if vids.is_eof:
            complete = replace(vids, payload=bytes(self._buffer))
            self.reset()
            return complete
        return None

    def reset(self) -> None:
        self._buffer = bytearray()
        self._active = False


def pixel_to_argb(value: int, color_depth: int) -> int:
    value &= 0xFFFFFFFF
    if color_depth == 7:
        return 0xFF000000 | ((value & 0xFF) << 16) | (((value >> 8) & 0xFF) << 8) | ((value >> 16) & 0xFF)
    if color_depth in (9, 12, 15):
        r = (value & 0x001F) << 3
        g = (value & 0x03E0) >> 2
        b = (value & 0x7C00) >> 7
        return 0xFF000000 | (r << 16) | (g << 8) | b
    if color_depth in (18, 21, 23):
        r = (value & 0x007F) << 1
        g = (value & 0x7F80) >> 7
        b = (value & 0x7F8000) >> 15
        return 0xFF000000 | (r << 16) | (g << 8) | b
    return 0xFF000000 | ((value & 0xFF) << 16) | (value & 0x00FF00) | ((value >> 16) & 0xFF)


def bpp_for_color_depth(color_depth: int) -> int:
    if color_depth == 7:
        return 1
    if color_depth in (9, 12, 15):
        return 2
    return 3


_DVC7_PERMUTATION = (
    0, 25, 50, 75, 5, 30, 55, 80, 10, 35, 60, 85, 15, 40, 65, 90,
    1, 26, 51, 76, 6, 31, 56, 81, 11, 36, 61, 86, 16, 41, 66, 91,
    2, 27, 52, 77, 7, 32, 57, 82, 12, 37, 62, 87, 17, 42, 67, 92,
    3, 28, 53, 78, 8, 33, 58, 83, 13, 38, 63, 88, 18, 43, 68, 93,
    100, 101, 102, 103, 105, 106, 107, 108, 110, 111, 112, 113, 115, 116, 117, 118,
    20, 45, 70, 95, 21, 46, 71, 96, 22, 47, 72, 97, 23, 48, 73, 98,
    4, 29, 54, 79, 9, 34, 59, 84, 14, 39, 64, 89, 19, 44, 69, 94,
    120, 121, 122, 123, 104, 109, 114, 119, 24, 49, 74, 99, 124, 125, 126, 127,
)
_DVC7_LEVELS = (0, 70, 127, 191, 255)


def _build_dvc7_table() -> tuple[int, ...]:
    base = [0] * 128
    for red in range(5):
        for green in range(5):
            for blue in range(5):
                base[red * 25 + green * 5 + blue] = (
                    0xFF000000
                    | (_DVC7_LEVELS[red] << 16)
                    | (_DVC7_LEVELS[green] << 8)
                    | _DVC7_LEVELS[blue]
                )
    base[125] = 0xFF5F5F5F
    base[126] = 0xFF9F9F9F
    base[127] = 0xFFDFDFDF
    return tuple(base[index] for index in _DVC7_PERMUTATION)


DVC7_COLOR_TABLE = _build_dvc7_table()


class DvcDecompressor:

    def __init__(self, width: int, height: int, color_depth: int = 15):
        if width <= 0 or height <= 0:
            raise DvcError("invalid_frame_size")
        if color_depth not in (7, 9, 12, 15, 18, 21, 23, 24, 32):
            raise DvcError(f"unsupported_color_depth:{color_depth}")
        self.width = width
        self.height = height
        self.color_depth = color_depth
        self.bpp = bpp_for_color_depth(color_depth)

    def _run(self, op: int, count: int, raw: list[int], written: bytearray,
             pos: int, total: int) -> int:
        if self.bpp == 1:
            count += 2
        if pos + count > total:
            return -1
        if op == OP_ADVANCE:
            return pos + count
        if op == OP_FILL:
            last = raw[pos - 1] if pos > 0 else 0
            for index in range(pos, pos + count):
                raw[index] = last
                written[index] = 1
            return pos + count
        if op == OP_COPY:
            source = pos - self.width
            for offset in range(count):
                src = source + offset
                raw[pos + offset] = raw[src] if 0 <= src < total else 0
                written[pos + offset] = 1
            return pos + count
        return pos

    def uncompress(self, data: bytes, color_mode: bool = True) -> list[int]:
        total = self.width * self.height
        raw = [0] * total
        written = bytearray(total)
        pos = 0
        index = 0
        remaining = len(data)
        pending_op: int | None = None
        run_count = 0
        run_bytes = 0
        has_pending = False

        def read_byte() -> int:
            nonlocal index
            if index >= len(data):
                return 0
            value = data[index]
            index += 1
            return value

        while remaining > 0 and pos < total:
            ctrl = read_byte()
            op = ctrl & 0xE0
            remaining -= 1

            if has_pending:
                if pending_op == op:
                    run_bytes += 1
                    run_count |= (ctrl & 0x1F) << (run_bytes * 5)
                    continue
                new_pos = self._run(pending_op, run_count, raw, written, pos, total)
                if new_pos < 0:
                    return self._to_argb(raw, written)
                pos = new_pos
                has_pending = False
                run_count = 0

            if op in (OP_ADVANCE, OP_FILL, OP_COPY):
                run_bytes = 0
                pending_op = op
                run_count = ctrl & 0x1F
                has_pending = True
            elif op == OP_PATTERN:
                current = raw[pos - 1] if pos > 0 else 0
                different = current
                for earlier in range(pos - 1, -1, -1):
                    if raw[earlier] != current:
                        different = raw[earlier]
                        break
                bits = ctrl << 4
                for _ in range(4):
                    if pos >= total:
                        break
                    raw[pos] = different if bits & 0x80 else current
                    written[pos] = 1
                    pos += 1
                    bits <<= 1
                more = bool(ctrl & 0x10)
                while more and pos + 7 <= total:
                    byte = read_byte()
                    if remaining:
                        remaining -= 1
                    bits = byte << 1
                    for _ in range(7):
                        raw[pos] = different if bits & 0x80 else current
                        written[pos] = 1
                        pos += 1
                        bits <<= 1
                    more = bool(byte & 0x80)
            else:
                if self.bpp == 1:
                    value = ctrl & 0x7F
                    if color_mode:
                        raw[pos] = DVC7_COLOR_TABLE[value]
                    else:
                        gray = value << 1
                        raw[pos] = 0xFF000000 | (gray << 16) | (gray << 8) | gray
                elif self.bpp == 2:
                    raw[pos] = ((ctrl & 0x7F) << 8) | read_byte()
                    remaining -= 1
                else:
                    first = read_byte()
                    second = read_byte()
                    raw[pos] = ((ctrl & 0x7F) << 16) | (first << 8) | second
                    remaining -= 2
                written[pos] = 1
                pos += 1

        if has_pending:
            new_pos = self._run(pending_op, run_count, raw, written, pos, total)
            if new_pos >= 0:
                pos = new_pos

        return self._to_argb(raw, written)

    def _to_argb(self, raw: list[int], written: bytearray) -> list[int]:
        return [
            pixel_to_argb(value, self.color_depth) if written[index] else 0
            for index, value in enumerate(raw)
        ]
