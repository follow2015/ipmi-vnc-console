"""Offline V1 correctness: request regions, atomic deltas and wire pixels."""
import struct
import zlib

import pytest

from kvmhub.video.encoding import compact_length, encode_snapshot
from kvmhub.video.framebuffer import Copy, Fill, Framebuffer, Raw, Rect, Snapshot, Update
from kvmhub.video.huawei import HuaweiDecoder
from kvmhub.video.requests import RequestStream
from kvmhub.video.synthetic import jpeg_block

RED, BLUE = b'\x00\x00\xff\x00', b'\xff\x00\x00\x00'


def update(fb, *ops):
    return Update(fb.epoch, fb.seq + 1, tuple(ops))


def test_atomic_failure_coverage_overlap_copy_and_epoch():
    fb = Framebuffer(4, 2)
    full = Rect(0, 0, 4, 2)
    assert fb.snapshot(full) is None
    with pytest.raises(ValueError, match='copy_uninitialized'):
        fb.apply(update(fb, Fill(Rect(0, 0, 1, 1), RED), Copy(Rect(1, 1, 1, 1), 2, 1)))
    assert fb.seq == 0 and fb.snapshot(Rect(0, 0, 1, 1)) is None
    fb.apply(update(fb, Fill(full, RED), Raw(Rect(0, 0, 1, 1), BLUE)))
    fb.apply(update(fb, Copy(Rect(1, 0, 3, 1), 0, 0)))
    assert fb.snapshot(full).pixels == BLUE * 2 + RED * 6
    old = fb.epoch
    fb.resize(old + 1, 2, 2)
    assert fb.snapshot(Rect(0, 0, 2, 2)) is None
    with pytest.raises(ValueError, match='sequence'):
        fb.apply(Update(old, 1, ()))


def test_source_updates_do_not_send_without_requests_and_nonincremental_forces_refresh():
    fb = Framebuffer(4, 4)
    client = RequestStream(fb)
    event = update(fb, Fill(Rect(0, 0, 4, 4), RED))
    fb.apply(event); client.changed(event)
    assert client.prepare() is None
    client.request(Rect(0, 0, 4, 4), incremental=False)
    batch = client.prepare()
    client.sent(batch)
    client.request(Rect(0, 0, 4, 4), incremental=True)
    assert client.prepare() is None
    client.request(Rect(1, 1, 1, 1), incremental=False)
    batch = client.prepare()
    assert [s.rect for s in batch.snapshots] == [Rect(1, 1, 1, 1)]
    client.sent(batch)


def test_repeated_requests_are_coalesced_not_fatal():
    fb = Framebuffer(4, 4)
    client = RequestStream(fb)
    event = update(fb, Fill(Rect(0, 0, 4, 4), RED))
    fb.apply(event); client.changed(event)
    for _ in range(64):
        client.request(Rect(0, 0, 4, 4), incremental=False)
    assert len(client.pending) == 1
    assert client.dropped_requests == 0
    batch = client.prepare()
    assert [s.rect for s in batch.snapshots] == [Rect(0, 0, 4, 4)]
    client.sent(batch)


def test_distinct_requests_are_bounded_and_dropped_not_fatal():
    fb = Framebuffer(64, 1)
    client = RequestStream(fb)
    event = update(fb, Fill(Rect(0, 0, 64, 1), RED))
    fb.apply(event); client.changed(event)
    for x in range(64):
        client.request(Rect(x, 0, 1, 1), incremental=False)
    assert len(client.pending) == 32
    assert client.dropped_requests == 32


def test_disjoint_regions_partial_tile_and_update_during_send_barrier():
    fb = Framebuffer(8, 4)
    client = RequestStream(fb)
    event = update(fb, Fill(Rect(0, 0, 8, 4), RED))
    fb.apply(event); client.changed(event)
    for rect in (Rect(0, 0, 2, 2), Rect(6, 2, 2, 2)):
        client.request(rect, incremental=True)
    batch = client.prepare()
    assert [s.rect for s in batch.snapshots] == [Rect(0, 0, 2, 2), Rect(6, 2, 2, 2)]
    event = update(fb, Fill(Rect(0, 0, 1, 1), BLUE))
    fb.apply(event); client.changed(event)
    client.sent(batch)
    client.request(Rect(0, 0, 1, 1), incremental=True)
    next_batch = client.prepare()
    assert next_batch.snapshots[0].pixels == BLUE
    client.sent(next_batch)
    client.request(Rect(2, 0, 1, 1), incremental=True)
    assert client.prepare() is not None


def test_clients_do_not_share_request_or_dirty_state_and_resize_invalidates_inflight():
    fb = Framebuffer(4, 4)
    fb.apply(update(fb, Fill(Rect(0, 0, 4, 4), BLUE)))
    fast, slow = RequestStream(fb), RequestStream(fb)
    fast.request(Rect(0, 0, 4, 4), incremental=False)
    batch = fast.prepare()
    fast.sent(batch)
    assert slow.prepare() is None
    slow.request(Rect(0, 0, 4, 4), incremental=False)
    assert slow.prepare().snapshots[0].pixels == BLUE * 16
    fb.resize(2, 2, 2)
    with pytest.raises(ValueError, match='resize'):
        slow.sent(slow.inflight)
    slow.abort(slow.inflight)
    slow.resized()
    slow.request(Rect(0, 0, 2, 2), incremental=False)
    assert slow.prepare() is None


@pytest.mark.parametrize('dimensions', [(0, 1), (1, 0), (4097, 1), (1, 2161), (True, 1)])
def test_geometry_limit_before_allocation(dimensions):
    with pytest.raises(ValueError, match='geometry'):
        Framebuffer(*dimensions)


def test_request_and_payload_limits():
    fb = Framebuffer(4, 4)
    client = RequestStream(fb)
    for x in range(4):
        for y in range(4):
            client.request(Rect(x, y, 1, 1), incremental=False)
    assert len(client.pending) == 16
    extra = Rect(0, 0, 1, 1)
    for _ in range(16):
        client.request(extra, incremental=False)
    assert len(client.pending) == 16
    with pytest.raises(ValueError, match='rect'):
        RequestStream(fb).request(Rect(3, 3, 2, 2), incremental=False)
    with pytest.raises(ValueError, match='raw_size'):
        fb.apply(update(fb, Raw(Rect(0, 0, 2, 2), b'x')))
    with pytest.raises(ValueError, match='too_large'):
        fb.apply(Update(1, 1, (Fill(Rect(0, 0, 1, 1), RED),) * 4097))


def decode_wire(messages):
    out = []
    for message in messages:
        kind, pad, count, x, y, w, h, encoding = struct.unpack('>BBHHHHHi', message[:16])
        assert (kind, pad, count) == (0, 0, 1)
        payload = message[16:]
        if encoding == 0:
            pixels = payload
        else:
            assert encoding == 7
            control, payload = payload[0], payload[1:]
            if control == 0x80:
                rgb = payload * (w * h)
            elif w * h * 3 < 12:
                assert control == 1
                rgb = payload
            else:
                assert control == 1
                length, shift, consumed = 0, 0, 0
                for byte in payload[:3]:
                    length |= (byte & (255 if consumed == 2 else 127)) << shift
                    consumed += 1
                    if byte < 128 or consumed == 3:
                        break
                    shift += 7
                assert length == len(payload) - consumed
                rgb = zlib.decompressobj().decompress(payload[consumed:])
            pixels = b''.join(bytes((rgb[i + 2], rgb[i + 1], rgb[i], 0)) for i in range(0, len(rgb), 3))
        assert len(pixels) == w * h * 4
        out.append((Rect(x, y, w, h), pixels, encoding))
    return out


@pytest.mark.parametrize('tight', [False, True])
@pytest.mark.parametrize('pattern', ['solid', 'stripes', 'small'])
def test_raw_and_tight_wire_color_order_and_independent_streams(tight, pattern):
    width, height = (1, 2) if pattern == 'small' else (128, 128)
    pixels = RED * (width * height) if pattern != 'stripes' else (RED + BLUE) * (width * height // 2)
    snap = Snapshot(1, 5, Rect(3, 7, width, height), pixels)
    first = list(encode_snapshot(snap, tight=tight))
    list(encode_snapshot(Snapshot(1, 6, Rect(0, 0, width, height), BLUE * (width * height)), tight=tight))
    second = list(encode_snapshot(snap, tight=tight))
    assert first == second and max(map(len, first)) <= 65536
    decoded = decode_wire(first)
    assert b''.join(data for _, data, _ in decoded) == pixels
    assert all(rect.x == 3 for rect, _, _ in decoded)
    assert sum(rect.h for rect, _, _ in decoded) == height
    if tight and pattern == 'solid':
        assert all(encoding == 7 for _, _, encoding in decoded)


@pytest.mark.parametrize('size,expected', [(0,b'\x00'), (127,b'\x7f'), (128,b'\x80\x01'),
                                         (16384,b'\x80\x80\x01'), (4194303,b'\xff\xff\xff')])
def test_tight_lengths(size, expected):
    assert compact_length(size) == expected


@pytest.mark.parametrize('rect', [Rect(-1, 0, 1, 1), Rect(0, 2160, 1, 1),
                                 Rect(4096, 0, 1, 1), Rect(True, 0, 1, 1)])
def test_encoder_rejects_invalid_wire_geometry_before_output(rect):
    with pytest.raises(ValueError, match='rect_invalid'):
        list(encode_snapshot(Snapshot(1, 1, rect, RED)))


def test_huawei_synthetic_incremental_copy_blob_and_edges():
    header, block = jpeg_block()
    decoder = HuaweiDecoder()
    decoded = decoder.feed(block * 4, 128, 128, header)
    assert len(decoded.update.operations) == len(decoded.jpegs) == 4
    original = decoder.framebuffer.snapshot(Rect(0, 0, 128, 128)).pixels
    assert original[2] > original[0] + 150 and original[3] == 0
    result = decoder.feed(b'\x80\xc0\xa0\x80', 128, 128, header)
    assert len(result.update.operations) == len(result.jpegs) == 2
    assert decoder.framebuffer.snapshot(Rect(0, 0, 128, 128)).pixels == original
    edge = decoder.feed(block * 4, 65, 65, header)
    assert len(edge.jpegs) == 1
    assert decoder.framebuffer.epoch == 2
    assert len(decoder.framebuffer.snapshot(Rect(0, 0, 65, 65)).pixels) == 65 * 65 * 4


@pytest.mark.parametrize('bad', [b'\x00', b'\x40', b'\x40\x00\x10x', b'\xa0', b'\xc0', b'\x80' * 5])
def test_huawei_bad_update_is_atomic_and_does_not_change_legacy_path(bad):
    header, block = jpeg_block()
    decoder = HuaweiDecoder()
    decoder.feed(block * 4, 128, 128, header)
    before = decoder.framebuffer.snapshot(Rect(0, 0, 128, 128))
    with pytest.raises(ValueError):
        decoder.feed(bad, 128, 128, header)
    assert decoder.framebuffer.snapshot(before.rect) == before


def test_copy_chain_preserves_vendor_image_cache_semantics():
    header, block = jpeg_block()
    decoder = HuaweiDecoder()
    decoder.feed(block + b'\xc0\xc0', 192, 64, header)
    first = decoder.framebuffer.snapshot(Rect(0, 0, 192, 64))
    assert first is not None and len(decoder.blocks) == 3
    decoder.feed(b'\x80\xc0\xc0', 192, 64, header)
    assert decoder.framebuffer.snapshot(first.rect).pixels == first.pixels


def test_synthetic_benchmark_is_offline_and_static_requests_wait():
    from kvmhub.video.bench import benchmark
    result = benchmark(width=64, height=64, samples=3, warmup=1, workload='static')
    assert result['network_used'] is False and result['synthetic'] is True
    assert result['encoded_bytes_max'] == 0
    assert len(result['source_sha256']) == 64
    with pytest.raises(ValueError):
        benchmark(samples=1001)
