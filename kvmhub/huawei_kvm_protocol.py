"""Pure wire-format helpers for the Huawei iBMC private KVM protocol (2198/WS)."""
from __future__ import annotations

import struct

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

C_CMD_GET_SUITE = 0x42
C_CMD_SET_SUITE = 0x44
C_CMD_CONNECT = 0x06
C_CMD_HEARTBEAT = 0x09
C_CMD_MOUSE = 0x05
C_CMD_KEYBOARD = 0x03
RSP_SUITE = 0x43
H_CMD_IMAGE = 0x02
H_CMD_KEYBOARD_STATE = 0x04
H_CMD_CONNECT_STATE = 0x08
H_CMD_MOUSE_MODE = 0x25
H_CMD_DEFINITION = 0x28
H_CMD_REPORT_KVMKEY = 0x40

SYNC = b"\xfe\xf6\x00"
BLOCK = 64
CHUNK = 220

FORBIDDEN_COMMANDS = frozenset({0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x33})


def make_packet(tag_id: int, payload: bytes) -> bytes:
    if tag_id < 0 or tag_id > 0xFFFFFFFF:
        raise ValueError("invalid_tag_id")
    dlen = len(payload) + 2
    if dlen > 250:
        raise ValueError("payload_too_large")
    return (SYNC + bytes((dlen,)) + struct.pack(">I", tag_id) + b"\x00\x00" + payload)


def get_suite_packet(tag_id: int, blade: int = 0) -> bytes:
    return make_packet(tag_id, bytes((C_CMD_GET_SUITE, blade)))


def heartbeat_packet(tag_id: int, blade: int = 0) -> bytes:
    return make_packet(tag_id, bytes((C_CMD_HEARTBEAT, blade)))


def set_suite_packet(tag_id: int, hmac: int, iterations: int, blade: int = 0) -> bytes:
    return make_packet(tag_id, bytes((C_CMD_SET_SUITE, blade, hmac))
                       + struct.pack(">I", iterations))


def connect_packet(tag_id: int, blade: int = 0) -> bytes:
    return make_packet(tag_id, bytes((C_CMD_CONNECT, blade, 0, 1, 1)))


def _input_cipher_key(tag_id: int) -> bytes:
    key = bytearray((1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8))
    key[0:4] = struct.pack(">I", tag_id)
    return bytes(key)


def encrypt_input(tag_id: int, data: bytes) -> bytes:
    if len(data) % 16:
        data = data + b"\x00" * (16 - len(data) % 16)
    cipher = Cipher(algorithms.AES(_input_cipher_key(tag_id)),
                    modes.CBC(b"\x00" * 16)).encryptor()
    return cipher.update(data) + cipher.finalize()


def keyboard_packet(tag_id: int, modifiers: int, usb_key: int) -> bytes:
    if not 0 <= modifiers <= 0xFF or not 0 <= usb_key <= 0xFF:
        raise ValueError("invalid_key")
    key_data = bytes((modifiers, 0, usb_key, 0, 0, 0, 0, 0))
    return make_packet(tag_id, bytes((C_CMD_KEYBOARD, 0)) + encrypt_input(tag_id, key_data))


def mouse_packet(tag_id: int, x: int, y: int, buttons: int, *, absolute: bool = True) -> bytes:
    if absolute:
        payload = bytes((C_CMD_MOUSE, 0, buttons & 0xFF,
                         (x >> 8) & 0xFF, x & 0xFF, (y >> 8) & 0xFF, y & 0xFF, 0))
    else:
        payload = bytes((C_CMD_MOUSE, 0, buttons & 0xFF, x & 0xFF, y & 0xFF, 0))
    return make_packet(tag_id, payload)


def parse_messages(buf: bytearray) -> tuple[list[bytes], bytearray]:
    out: list[bytes] = []
    start = 0
    while True:
        idx = buf.find(SYNC, start)
        if idx < 0:
            break
        if idx + 4 > len(buf):
            break
        dlen = buf[idx + 3]
        if not 3 <= dlen <= 250:
            start = idx + 1
            continue
        if idx + 4 + dlen > len(buf):
            break
        out.append(bytes(buf[idx + 6:idx + 4 + dlen]))
        start = idx + 4 + dlen
    del buf[:start]
    return out, buf


def parse_suite(payload: bytes) -> tuple[int, int] | None:
    if len(payload) < 4:
        return None
    count = payload[2]
    offset = 3
    for i in range(count):
        pos = offset + i * 5
        if pos + 5 > len(payload):
            break
        hmac = payload[pos]
        iterations = int.from_bytes(payload[pos + 1:pos + 5], "big")
        if hmac == 3:
            return hmac, iterations
    return None


class ImageAssembler:

    def __init__(self) -> None:
        self._pending: dict[int, dict] = {}

    def feed(self, payload: bytes) -> tuple[bytes, int, int, int] | None:
        if len(payload) < 19 or payload[0] != H_CMD_IMAGE:
            return None
        offset = (payload[2] << 8) | payload[3]
        seq = payload[4]
        if offset == 0:
            image_len = int.from_bytes(payload[5:9], "big")
            width = ((payload[9] << 8) | payload[10]) & 0x7FFF
            height = (payload[11] << 8) | payload[12]
            quant = payload[18] & 0x0F
            chunks = (image_len + CHUNK - 1) // CHUNK + 1
            self._pending[seq] = {
                "raw": bytearray(image_len), "chunks": chunks,
                "width": width, "height": height, "quant": quant,
            }
            return None
        st = self._pending.get(seq)
        if st is None:
            return None
        dst = (offset - 1) * CHUNK
        chunk = payload[5:]
        if dst + len(chunk) <= len(st["raw"]):
            st["raw"][dst:dst + len(chunk)] = chunk
        if st["chunks"] == offset + 1:
            done = self._pending.pop(seq)
            return (bytes(done["raw"]), done["width"], done["height"], done["quant"])
        return None

    def geometry(self, seq: int) -> tuple[int, int, int] | None:
        st = self._pending.get(seq)
        if st is None:
            return None
        return st["width"], st["height"], st["quant"]


def decode_blocks(blocks: bytes, width: int, height: int, quant: int,
                  jpeg_header: bytes) -> bytearray:
    out = bytearray(width * height * 3)
    cache: dict[int, bytes] = {}
    cols = (width + BLOCK - 1) // BLOCK
    count = 0
    i = 0
    tail = b"\xff\xd9"
    while i < len(blocks):
        kind = (blocks[i] & 0xE0) >> 5
        if kind in (2, 3):
            if i + 3 > len(blocks):
                break
            length = (blocks[i + 1] << 8) | blocks[i + 2]
            blob = bytes(jpeg_header) + blocks[i + 3:i + 3 + length] + tail
            _paste_jpeg(blob, out, count, cols, width, height)
            cache[count] = blob
            i += 3 + length
            count += 1
        elif kind == 4:
            i += 1
            count += 1
        elif kind == 5:
            _paste_jpeg(cache.get(count - cols), out, count, cols, width, height)
            i += 1
            count += 1
        elif kind == 6:
            _paste_jpeg(cache.get(count - 1), out, count, cols, width, height)
            i += 1
            count += 1
        else:
            i += 1
    return out


def _decode_jpeg_block(blob: bytes | None) -> bytes | None:
    if not blob:
        return None
    try:
        from PIL import Image
        import io
        return Image.open(io.BytesIO(blob)).convert("RGB").tobytes()
    except Exception:
        return None


def _paste_jpeg(blob: bytes | None, out: bytearray, count: int, cols: int,
                width: int, height: int) -> None:
    if not blob:
        return
    try:
        from PIL import Image
        import io
        img = Image.open(io.BytesIO(blob)).convert("RGB")
    except Exception:
        return
    x0 = (count % cols) * BLOCK
    y0 = (count // cols) * BLOCK
    bw, bh = img.size
    src = img.tobytes()
    for dy in range(bh):
        y = y0 + dy
        if y >= height:
            break
        row_start = (y * width + x0) * 3
        seg = src[dy * bw * 3:(dy * bw + min(bw, width - x0)) * 3]
        out[row_start:row_start + len(seg)] = seg


class HuaweiFrameDecoder:

    def __init__(self, *, observations=None) -> None:
        self.observations = observations
        self.width = 0
        self.height = 0
        self.quant = 0
        self.canvas = bytearray()
        self.blocks: dict[int, bytes] = {}
        self.frames = 0
        self.decoded_blocks = 0
        self.failed_blocks = 0

    def reset(self, width: int, height: int) -> None:
        if self.observations is not None:
            self.observations.geometry_changes += 1
        self.width = width
        self.height = height
        self.canvas = bytearray(width * height * 3)
        self.blocks = {}
        self.frames = 0
        self.decoded_blocks = 0
        self.failed_blocks = 0

    @staticmethod
    def _paste_tile(tile: bytes | None, out: bytearray, count: int, cols: int,
                    width: int, height: int) -> None:
        if not tile:
            return
        x0 = (count % cols) * BLOCK
        y0 = (count // cols) * BLOCK
        for dy in range(BLOCK):
            y = y0 + dy
            if y >= height:
                break
            copy = min(BLOCK, width - x0)
            if copy <= 0:
                break
            src_off = dy * BLOCK * 3
            seg = tile[src_off:src_off + copy * 3]
            row_start = (y * width + x0) * 3
            out[row_start:row_start + len(seg)] = seg

    def decode(self, stream: bytes, width: int, height: int, quant: int,
               jpeg_header: bytes) -> bytes:
        if (width, height) != (self.width, self.height):
            self.reset(width, height)
        if self.observations is not None:
            self.observations.source_updates += 1
            self.observations.source_bytes += len(stream)
        self.quant = quant
        out = self.canvas
        cols = (width + BLOCK - 1) // BLOCK
        count = 0
        i = 0
        while i < len(stream):
            kind = (stream[i] & 0xE0) >> 5
            if self.observations is not None:
                self.observations.kind_counts[kind] += 1
                if kind not in (2, 3, 4, 5, 6):
                    self.observations.unknown_blocks += 1
            if kind in (2, 3):
                if i + 3 > len(stream):
                    if self.observations is not None:
                        self.observations.truncated_blocks += 1
                    break
                length = (stream[i + 1] << 8) | stream[i + 2]
                if self.observations is not None and i + 3 + length > len(stream):
                    self.observations.truncated_blocks += 1
                blob = bytes(jpeg_header) + stream[i + 3:i + 3 + length] + b"\xff\xd9"
                tile = _decode_jpeg_block(blob)
                if tile is not None:
                    self.blocks[count] = tile
                    self._paste_tile(tile, out, count, cols, width, height)
                    self.decoded_blocks += 1
                else:
                    self.failed_blocks += 1
                i += 3 + length
            elif kind == 4:
                i += 1
            elif kind == 5:
                if self.observations is not None and not self.blocks.get(count - cols):
                    self.observations.missing_copy_sources += 1
                self._paste_tile(self.blocks.get(count - cols), out, count,
                                 cols, width, height)
                i += 1
            elif kind == 6:
                if self.observations is not None and not self.blocks.get(count - 1):
                    self.observations.missing_copy_sources += 1
                self._paste_tile(self.blocks.get(count - 1), out, count,
                                 cols, width, height)
                i += 1
            else:
                i += 1
            count += 1
        self.frames += 1
        return bytes(out)
