"""Tests for the RFB server-side frame encoder used by the iDRAC8 upstream."""
from __future__ import annotations

import struct

import pytest

from kvmhub import rfb_server


def test_server_init_declares_24bpp_true_colour():
    init = rfb_server.build_server_init(1024, 768, "iDRAC8")
    assert struct.unpack(">HH", init[:4]) == (1024, 768)
    assert init[4] == 24
    assert init[5] == 24
    assert init[6] == 0
    assert init[7] == 1
    assert struct.unpack(">HHH", init[8:14]) == (255, 255, 255)
    assert tuple(init[14:17]) == (16, 8, 0)
    assert struct.unpack(">I", init[20:24])[0] == 6
    assert init[24:] == b"iDRAC8"


def test_rfb_pixels_are_bgr_ordered():
    assert rfb_server.to_rfb_bgr24([0xFF102030]) == bytes.fromhex("302010")


def test_frame_update_is_split_into_row_bands():
    pixels = [0xFF000000] * (4 * 5)
    messages = rfb_server.build_raw_framebuffer_update(pixels, 4, 5, rows_per_rect=2)
    assert len(messages) == 3
    offsets = []
    for msg in messages:
        assert msg[:4] == b"\x00\x00\x00\x01"
        x, y, width, rows, encoding = struct.unpack(">HHHHI", msg[4:16])
        assert (x, width, encoding) == (0, 4, 0)
        assert len(msg) == 16 + 4 * rows * 3
        offsets.append(y)
        assert len(msg[16:]) == 4 * rows * 3
    assert offsets == [0, 2, 4]


def test_frame_update_preserves_pixel_order():
    pixels = [0xFF010203, 0xFF040506, 0xFF070809, 0xFF0A0B0C]
    msg = rfb_server.build_raw_framebuffer_update(pixels, 2, 2, rows_per_rect=2)[0]
    assert msg[16:] == bytes.fromhex("0302010605040908070c0b0a")


def test_frame_update_rejects_wrong_pixel_count():
    with pytest.raises(ValueError, match="pixel_count_mismatch"):
        rfb_server.build_raw_framebuffer_update([0], 4, 4)
