"""Minimal RFB server-side framebuffer encoding for decoded KVM frames."""
from __future__ import annotations

import struct

RFB_PIXEL_FORMAT_24BPP = struct.pack(
    ">BBBBHHHBBBxxx",
    24,
    24,
    0,
    1,
    255, 255, 255,
    16,
    8,
    0,
)

RFB_PIXEL_FORMAT_32BPP = struct.pack(
    ">BBBBHHHBBBxxx",
    32,
    24,
    0,
    1,
    255, 255, 255,
    16,
    8,
    0,
)


def build_server_init_32bpp(width: int, height: int, name: str = "KVM") -> bytes:
    encoded = name.encode("utf-8")[:255]
    return (struct.pack(">HH", width, height) + RFB_PIXEL_FORMAT_32BPP
            + struct.pack(">I", len(encoded)) + encoded)


def build_server_init(width: int, height: int, name: str = "iDRAC8") -> bytes:
    encoded = name.encode("utf-8")[:255]
    return (struct.pack(">HH", width, height) + RFB_PIXEL_FORMAT_24BPP
            + struct.pack(">I", len(encoded)) + encoded)


def to_rfb_bgr24(pixels: list[int]) -> bytes:
    out = bytearray(len(pixels) * 3)
    for index, value in enumerate(pixels):
        out[index * 3] = value & 0xFF
        out[index * 3 + 1] = (value >> 8) & 0xFF
        out[index * 3 + 2] = (value >> 16) & 0xFF
    return bytes(out)


def to_rfb_bgr32(pixels: list[int]) -> bytes:
    out = bytearray(len(pixels) * 4)
    for index, value in enumerate(pixels):
        base = index * 4
        out[base] = value & 0xFF
        out[base + 1] = (value >> 8) & 0xFF
        out[base + 2] = (value >> 16) & 0xFF
        out[base + 3] = 0
    return bytes(out)


def rgb24_to_bgrx32(rgb: bytes, width: int, height: int) -> bytes:
    if len(rgb) != width * height * 3:
        raise ValueError(f"rgb24_size_mismatch:{len(rgb)}!={width * height * 3}")
    from PIL import Image
    img = Image.frombytes("RGB", (width, height), rgb)
    r, g, b = img.split()
    alpha = Image.new("L", (width, height), 0)
    return Image.merge("RGBA", (b, g, r, alpha)).tobytes()


def build_raw_fbu_from_bgrx32(
    data: bytes,
    width: int,
    height: int,
    *,
    rows_per_rect: int = 16,
) -> list[bytes]:
    if width <= 0 or height <= 0 or rows_per_rect <= 0:
        raise ValueError("invalid_framebuffer_geometry")
    stride = width * 4
    if len(data) != stride * height:
        raise ValueError(f"bgrx32_size_mismatch:{len(data)}!={stride * height}")
    messages: list[bytes] = []
    for top in range(0, height, rows_per_rect):
        rows = min(rows_per_rect, height - top)
        rect_header = struct.pack(">HHHHI", 0, top, width, rows, 0)
        seg = data[top * stride:(top + rows) * stride]
        messages.append(struct.pack(">BBH", 0, 0, 1) + rect_header + seg)
    return messages


def build_raw_framebuffer_update_32bpp(
    pixels: list[int],
    width: int,
    height: int,
    *,
    rows_per_rect: int = 16,
) -> list[bytes]:
    if width <= 0 or height <= 0 or rows_per_rect <= 0:
        raise ValueError("invalid_framebuffer_geometry")
    if len(pixels) != width * height:
        raise ValueError(f"pixel_count_mismatch:{len(pixels)}!={width * height}")
    messages: list[bytes] = []
    for top in range(0, height, rows_per_rect):
        rows = min(rows_per_rect, height - top)
        rect_header = struct.pack(">HHHHI", 0, top, width, rows, 0)
        data = to_rfb_bgr32(pixels[top * width:(top + rows) * width])
        messages.append(struct.pack(">BBH", 0, 0, 1) + rect_header + data)
    return messages


def build_raw_framebuffer_update(
    pixels: list[int],
    width: int,
    height: int,
    *,
    rows_per_rect: int = 16,
) -> list[bytes]:
    if width <= 0 or height <= 0 or rows_per_rect <= 0:
        raise ValueError("invalid_framebuffer_geometry")
    expected = width * height
    if len(pixels) != expected:
        raise ValueError(f"pixel_count_mismatch:{len(pixels)}!={expected}")

    messages: list[bytes] = []
    for top in range(0, height, rows_per_rect):
        rows = min(rows_per_rect, height - top)
        rect_header = struct.pack(">HHHHI", 0, top, width, rows, 0)
        data = to_rfb_bgr24(pixels[top * width:(top + rows) * width])
        messages.append(struct.pack(">BBH", 0, 0, 1) + rect_header + data)
    return messages
