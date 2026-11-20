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
