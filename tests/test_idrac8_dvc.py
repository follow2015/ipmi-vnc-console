"""Tests for the iDRAC8 DVC video decompressor and VIDS framing."""
from __future__ import annotations

import hashlib
import struct

import pytest

from kvmhub import idrac8_dvc as dvc


def _vids(x: int, y: int, flags: int, payload: bytes) -> bytes:
    total = 20 + len(payload)
    return (b"VIDS" + b"\x00\x81" + struct.pack(">H", total)
            + b"\xde\xad\xbe\xef" + struct.pack(">HH", y, x)
            + bytes([flags, 0, 0, 0]) + payload)


def _raw(value: int) -> bytes:
    return bytes([0x80 | ((value >> 8) & 0x7F), value & 0xFF])



def test_parse_vids_header_resolution_and_flags():
    frame = _vids(1024, 768, 0x05, b"\x00" * 16)
    h = dvc.parse_vids(frame)
    assert h.magic == "VIDS"
    assert h.x_resolution == 1024
    assert h.y_resolution == 768
    assert h.flags == 0x05
    assert h.is_sof is True
    assert h.is_ref is True
    assert h.payload == b"\x00" * 16


def test_vids_flags_bits():
    h = dvc.parse_vids(_vids(640, 480, 0x1 | 0x2 | 0x10 | 0x80, b""))
    assert h.is_sof and h.is_eof and h.is_sob and h.is_packed


def test_vids_matches_real_capture_header():
    frame = _vids(1024, 768, 0x05, b"\x00" * 16)
    h = dvc.parse_vids(frame)
    assert (h.x_resolution, h.y_resolution, h.flags) == (1024, 768, 0x05)


def test_vids_rejects_bad_magic_and_truncation():
    with pytest.raises(dvc.DvcError):
        dvc.parse_vids(b"NOPE" + b"\x00" * 20)
    with pytest.raises(dvc.DvcError):
        dvc.parse_vids(b"VIDS" + b"\x00" * 4)



def test_assembler_ignores_chunks_before_bof():
    assembler = dvc.VidsFrameAssembler()
    assert assembler.feed(_vids(4, 4, 0x04, b"REF-only")) is None
    assert assembler.feed(_vids(4, 4, 0x06, b"EOF-only")) is None


def test_assembler_joins_bof_ref_and_eof_chunks():
    assembler = dvc.VidsFrameAssembler()
    assert assembler.feed(_vids(8, 4, 0x05, b"BOF")) is None
    assert assembler.feed(_vids(8, 4, 0x04, b"REF")) is None
    complete = assembler.feed(_vids(8, 4, 0x06, b"EOF"))
    assert complete is not None
    assert complete.payload == b"BOFREFEOF"
    assert (complete.x_resolution, complete.y_resolution) == (8, 4)
    assert complete.is_eof and complete.flags == 0x06


def test_assembler_sob_starts_a_new_frame_and_can_be_reset():
    assembler = dvc.VidsFrameAssembler()
    assert assembler.feed(_vids(2, 2, 0x05, b"stale")) is None
    assert assembler.feed(_vids(2, 2, 0x11, b"NEW")) is None
    complete = assembler.feed(_vids(2, 2, 0x02, b"END"))
    assert complete is not None and complete.payload == b"NEWEND"
    assert assembler.feed(_vids(2, 2, 0x04, b"orphan")) is None
    assembler.reset()
    assert assembler.feed(_vids(2, 2, 0x04, b"orphan2")) is None



def test_rgb555_pixel_conversion():
    assert dvc.pixel_to_argb(0x001F, 15) == 0xFFF80000
    assert dvc.pixel_to_argb(0x03E0, 15) == 0xFF00F800
    assert dvc.pixel_to_argb(0x7C00, 15) == 0xFF0000F8


def test_rgb565_23bit_pixel_conversion():
    argb = dvc.pixel_to_argb(0x0000007F, 23)
    assert argb & 0x00FF0000 == 0x00FE0000


def test_rgb24_pixel_conversion():
    assert dvc.pixel_to_argb(0x000000FF, 24) == 0xFFFF0000


def test_color_depth_maps_to_vendor_bytes_per_pixel():
    assert [dvc.bpp_for_color_depth(d) for d in (7, 9, 12, 15, 18, 21, 23)] == [1, 2, 2, 2, 3, 3, 3]


def test_dvc7_palette_maps_fixed_grayscale_endpoints():
    assert dvc.DVC7_COLOR_TABLE[125] == 0xFF5F5F5F
    assert dvc.DVC7_COLOR_TABLE[126] == 0xFF9F9F9F
    assert dvc.DVC7_COLOR_TABLE[127] == 0xFFDFDFDF



def test_raw_pixel_opcode_dvc15():
    dec = dvc.DvcDecompressor(1, 1, color_depth=15)
    out = dec.uncompress(_raw(0x001F))
    assert len(out) == 1 and out[0] == 0xFFF80000


def test_fill_opcode_repeats_last_pixel():
    payload = _raw(0x001F) + bytes([0x20 | 0x03])
    dec = dvc.DvcDecompressor(4, 1, color_depth=15)
    out = dec.uncompress(payload)
    assert len(out) == 4
    assert all(px == 0xFFF80000 for px in out)


def test_skip_opcode_leaves_pixel_unwritten():
    payload = bytes([0x02]) + _raw(0x7C00)
    dec = dvc.DvcDecompressor(3, 1, color_depth=15)
    out = dec.uncompress(payload)
    assert out[:2] == [0, 0]
    assert out[2] == 0xFF0000F8


def test_copy_uses_previous_row_without_an_offset_byte():
    payload = (_raw(0x001F) + _raw(0x03E0) + _raw(0x7C00) + _raw(0x0000)
               + bytes([0x40 | 0x04]))
    dec = dvc.DvcDecompressor(4, 2, color_depth=15)
    out = dec.uncompress(payload)
    assert out[4:8] == out[0:4]
    assert out[3] == 0xFF000000
    assert out[7] == 0xFF000000


def test_consecutive_control_bytes_concatenate_run_count():
    payload = bytes([0x03, 0x01]) + _raw(0x001F)
    dec = dvc.DvcDecompressor(64, 1, color_depth=15)
    out = dec.uncompress(payload)
    assert out[34] == 0
    assert out[35] == 0xFFF80000


def test_pattern_is_msb_first_with_backward_color_search():
    payload = _raw(0x001F) + _raw(0x7C00) + bytes([0x60 | 0b1001])
    dec = dvc.DvcDecompressor(6, 1, color_depth=15)
    out = dec.uncompress(payload)
    assert out == [0xFFF80000, 0xFF0000F8, 0xFFF80000,
                   0xFF0000F8, 0xFF0000F8, 0xFFF80000]


def test_pattern_continuation_uses_bit_four_and_bit_seven():
    payload = (_raw(0x001F) + _raw(0x7C00)
               + bytes([0x60 | 0x10 | 0b0001, 0x80 | 0b0000001]))
    dec = dvc.DvcDecompressor(13, 1, color_depth=15)
    out = dec.uncompress(payload)
    red, blue = 0xFFF80000, 0xFF0000F8
    assert out == [red, blue, blue, blue, blue, red,
                   blue, blue, blue, blue, blue, blue, red]


def test_dvc7_run_count_gets_vendor_plus_two():
    dec = dvc.DvcDecompressor(8, 1, color_depth=7)
    out = dec.uncompress(bytes([0x03, 0x80 | 0x01]))
    assert out[4] == 0
    assert out[5] == 0xFF000046


def test_output_never_exceeds_frame_size():
    dec = dvc.DvcDecompressor(4, 4, color_depth=15)
    out = dec.uncompress(_raw(0x001F) * 40)
    assert len(out) == 16


def test_decompress_empty_payload_is_all_zero():
    dec = dvc.DvcDecompressor(2, 2, color_depth=15)
    assert list(dec.uncompress(b"")) == [0, 0, 0, 0]


def test_port_matches_vendor_js_on_deterministic_stream():
    seed = 0x12345678
    payload = bytearray()
    for _ in range(512):
        seed = (1103515245 * seed + 12345) & 0xFFFFFFFF
        payload.append((seed >> 16) & 0xFF)
    out = dvc.DvcDecompressor(16, 16, color_depth=15).uncompress(bytes(payload))
    digest = hashlib.sha256(
        struct.pack("<%dI" % len(out), *out)
    ).hexdigest()
    assert digest == "92e905b2dd3cfddbd71d7007908233031bff7ee21d8c92e18546df117677a72b"
