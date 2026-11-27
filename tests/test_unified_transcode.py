"""R-unit invariants for the unified, plugin-driven transcode platform."""
import asyncio
import shutil
import struct
import zlib
from pathlib import Path

import pytest

import kvmhub
from kvmhub.common import Problem
from kvmhub.transcode import pipeline, registry, standard_rfb
from kvmhub.transcode.contract import PluginSpec
from kvmhub.transcode.standard_rfb import StandardRfbFamily
from kvmhub.video.encoding import encode_snapshot
from kvmhub.video.framebuffer import Fill, Rect, Snapshot, Update
from kvmhub.video.runtime import ManagedDecoder, hard_cpu_limit_supported
from kvmhub.video.session import VideoSession
from kvmhub.video.synthetic import jpeg_block

NONCE = b'0123456789abcdef'
ROOT = Path(kvmhub.__file__).resolve().parents[1]
RED = b'\x00\x00\xff\x00'


def _rect(x, y, w, h, encoding=7):
    return struct.pack('>HHHHI', x, y, w, h, encoding)


def _tight_fill(x, y, w, h, rgb):
    return (b'\x00\x00' + struct.pack('>H', 1) + _rect(x, y, w, h)
            + b'\x80' + bytes(rgb))


def _tight_basic(x, y, w, h, rgb, control=0x01):
    compressed = zlib.compress(rgb, 1)
    size = bytearray()
    remaining = len(compressed)
    while True:
        byte = remaining & 0x7F
        remaining >>= 7
        if remaining:
            size.append(byte | 0x80)
        else:
            size.append(byte)
            break
    return (b'\x00\x00' + struct.pack('>H', 1) + _rect(x, y, w, h)
            + bytes([control]) + bytes(size) + compressed)


def _one_rect(payload, w=4, h=4):
    return (b'\x00\x00' + struct.pack('>H', 1) + _rect(0, 0, w, h) + payload)


def _copytree_transcode(tmp_path):
    target = tmp_path / 'root' / 'kvmhub' / 'transcode'
    shutil.copytree(ROOT / 'kvmhub' / 'transcode', target)
    return target


def test_p1_unlisted_family_and_ast2100_build_are_refused():
    assert registry.select('ast2100-x10').family == 'ast2100-x10'
    with pytest.raises(Problem, match='transcode_family_unsupported'):
        registry.select('new-family-from-a-file')
    with pytest.raises(Problem, match='transcode_family_unsupported'):
        registry.build('ast2100-x10', ROOT)


def test_p2_standard_rfb_tight_fill_becomes_a_canonical_fill():
    plugin = StandardRfbFamily()
    plugin.init(4, 4)
    decoded = plugin.feed(_tight_fill(0, 0, 4, 4, (255, 0, 0)))
    assert isinstance(decoded.update.operations[0], Fill)
    assert decoded.update.operations[0].rect == Rect(0, 0, 4, 4)
    assert decoded.update.operations[0].pixel == standard_rfb.bgrx(b'\xff\x00\x00')


def test_p2b_tight_jpeg_png_palette_and_stream_ids_are_refused_by_name():
    cases = {
        'jpeg': b'\x90' + b'\xff\xd8\xff\xe0' + b'\x00' * 32,
        'png': b'\xa0' + b'\x89PNG\r\n\x1a\n' + b'\x00' * 8,
        'palette': b'\x41\x01' + b'\x00' * 16,
        'gradient': b'\x41\x02' + b'\x00' * 16,
        'stream-1': b'\x11' + b'\x00' * 16,
    }
    for name, payload in cases.items():
        plugin = StandardRfbFamily()
        plugin.init(4, 4)
        with pytest.raises(ValueError, match='transcode_family_encoding_unsupported'):
            plugin.feed(_one_rect(payload))
        assert plugin.buf == bytearray(), name


def test_p2c_tight_basic_tiny_rect_carries_no_length_prefix():
    plugin = StandardRfbFamily()
    plugin.init(4, 4)
    decoded = plugin.feed(_one_rect(b'\x01' + b'\x0a\x0b\x0c\x0d\x0e\x0f', 1, 2))
    assert decoded.update.operations[0].pixels == b'\x0c\x0b\x0a\x00\x0f\x0e\x0d\x00'


def test_p2d_a_continued_tight_stream_is_refused_not_misdecoded():
    plugin = StandardRfbFamily()
    plugin.init(4, 4)
    plugin.feed(_tight_basic(0, 0, 4, 4, b'\x01\x02\x03' * 16))
    with pytest.raises(ValueError, match='transcode_family_encoding_unsupported'):
        plugin.feed(_one_rect(b'\x00' + zlib.compress(b'\x04\x05\x06' * 16, 1)))


def test_p2e_encoder_output_round_trips_through_the_source_parser():
    cases = (
        (Rect(0, 0, 4, 4), standard_rfb.bgrx(b'\x11\x22\x33') * 16),
        (Rect(0, 0, 4, 4), bytes(range(64))),
        (Rect(0, 0, 1, 2), bytes(range(8))),
    )
    for rect, pixels in cases:
        snapshot = Snapshot(1, 1, rect, pixels)
        wire = b''.join(encode_snapshot(snapshot, tight=True, max_message=65536,
                                        limit=(4, 4)))
        plugin = StandardRfbFamily()
        plugin.init(4, 4)
        operation = plugin.feed(wire).update.operations[0]
        expected = bytearray(pixels)
        expected[3::4] = b'\x00' * (len(pixels) // 4)
        if isinstance(operation, Fill):
            assert operation.pixel == bytes(expected[:4])
        else:
            assert operation.pixels == bytes(expected)


def test_p3_child_selects_the_declared_family_and_decodes_its_bytes():
    decoder = ManagedDecoder(nonce=NONCE, require_hard_cpu_limit=False)
    decoder.start()
    try:
        assert decoder.reset(4, 4, family='standard-rfb-v1') == 1
        update = decoder.decode_update(_tight_fill(0, 0, 4, 4, (10, 20, 30)))
        assert isinstance(update.operations[0], Fill)
        assert update.operations[0].pixel == standard_rfb.bgrx(b'\x0a\x14\x1e')
    finally:
        decoder.close()


def test_p3_a_family_rejects_the_other_familys_bytes():
    header, block = jpeg_block()
    plugin = StandardRfbFamily()
    plugin.init(64, 64)
    with pytest.raises(ValueError, match='transcode_family_message_unsupported'):
        plugin.feed(block)
    assert plugin.buf == bytearray()

    decoder = ManagedDecoder(nonce=NONCE, require_hard_cpu_limit=False)
    decoder.start()
    try:
        decoder.reset(64, 64, family='standard-rfb-v1')
        with pytest.raises(ValueError, match='transcode_family_message_unsupported'):
            decoder.decode_update(block)
    finally:
        decoder.close()


@pytest.mark.skipif(not hard_cpu_limit_supported(),
                    reason="open_pipeline pins the hard CPU limit; RLIMIT_CPU is POSIX-only")
def test_pipeline_opens_a_named_family_without_a_legacy_huawei_reset():
    async def run():
        session = await pipeline.open_pipeline('standard-rfb-v1', 4, 4)
        try:
            assert session.epoch == 1
            assert session.framebuffer.width == session.framebuffer.height == 4
            assert session.decoder.transcode_family == 'standard-rfb-v1'
        finally:
            session.close()

    asyncio.run(run())


def test_p4_legacy_reset_still_selects_the_huawei_decoder():
    header, block = jpeg_block()
    decoder = ManagedDecoder(nonce=NONCE, require_hard_cpu_limit=False)
    decoder.start()
    try:
        assert decoder.reset(128, 128, header) == 1
        update = decoder.decode_update(block * 4)
        assert len(update.operations) == 4
    finally:
        decoder.close()


def test_p5_malformed_rectangle_is_atomic_and_leaves_the_plugin_usable():
    plugin = StandardRfbFamily()
    plugin.init(4, 4)
    with pytest.raises(ValueError):
        plugin.feed(_tight_fill(3, 3, 2, 2, (1, 2, 3)))
    good = plugin.feed(_tight_fill(0, 0, 4, 4, (4, 5, 6)))
    assert isinstance(good.update.operations[0], Fill)
    assert good.update.operations[0].rect == Rect(0, 0, 4, 4)


def test_p6_two_plugins_do_not_share_geometry_or_framing_state():
    small, large = StandardRfbFamily(), StandardRfbFamily()
    small.init(4, 4)
    large.init(8, 8)
    first = large.feed(_tight_fill(0, 0, 8, 8, (8, 8, 8)))
    second = small.feed(_tight_fill(0, 0, 4, 4, (4, 4, 4)))
    third = large.feed(_tight_fill(0, 0, 8, 8, (9, 9, 9)))
    assert [u.update.operations[0].rect.w for u in (first, second, third)] == [8, 4, 8]
    assert large.buf == bytearray() and small.buf == bytearray()


def test_p7_a_changed_plugin_source_fails_the_locked_digest(tmp_path):
    target = _copytree_transcode(tmp_path)
    (target / 'standard_rfb.py').write_bytes(
        (target / 'standard_rfb.py').read_bytes() + b'\n# tampered\n')
    spec = PluginSpec('standard-rfb-v1', '1.0.0', 'kvmhub.transcode.standard_rfb',
                      'kvmhub/transcode/standard_rfb.py', registry.PLUGINS['standard-rfb-v1'].sha256)
    with pytest.raises(Problem, match='transcode_family_unsupported'):
        spec.check_source(tmp_path / 'root')
    registry.verify(ROOT)


def test_p8_the_manifest_cannot_be_extended_at_runtime(tmp_path):
    target = _copytree_transcode(tmp_path)
    (target / 'hot_loaded.py').write_text('class P: pass\n')
    with pytest.raises(TypeError):
        registry.PLUGINS['hot-loaded'] = registry.PLUGINS['standard-rfb-v1']
    assert 'hot-loaded' not in registry.PLUGINS
    with pytest.raises(Problem, match='transcode_family_unsupported'):
        registry.select('hot-loaded')
    with pytest.raises(Problem, match='transcode_family_unsupported'):
        registry.build('hot-loaded', tmp_path / 'root')
    sources = ''.join(path.read_text(encoding='utf-8')
                      for path in (ROOT / 'kvmhub' / 'transcode').glob('*.py'))
    assert 'importlib' not in sources and '__import__(' not in sources


def test_p9_one_session_over_budget_does_not_poison_another(monkeypatch):
    broken, healthy = StandardRfbFamily(), StandardRfbFamily()
    broken.init(4, 4)
    healthy.init(4, 4)
    monkeypatch.setattr(standard_rfb, '_MAX_BUFFER', 16)
    with pytest.raises(ValueError, match='input_budget'):
        broken.feed(_tight_fill(0, 0, 4, 4, (1, 2, 3)))
    monkeypatch.undo()
    update = healthy.feed(_tight_fill(0, 0, 4, 4, (7, 8, 9)))
    assert isinstance(update.update.operations[0], Fill)


def test_p10_both_families_emit_the_same_standard_rfb_wire():
    header, block = jpeg_block()

    async def run():
        sessions = {}
        for family in ('huawei-kvm-v1', 'standard-rfb-v1'):
            plugin = registry.build(family, ROOT)
            decoder = ManagedDecoder(nonce=NONCE, require_hard_cpu_limit=False)
            decoder.transcode_family = family
            decoder.transcode_plugin = plugin
            session = VideoSession(decoder=decoder, tight=True)
            family_header = header if family == 'huawei-kvm-v1' else b''
            plugin.init(64, 64, family_header)
            await decoder.astart()
            await decoder.areset(64, 64, family_header, family=family)
            session._bind_framebuffer(64, 64, decoder.epoch)
            sessions[family] = session
        try:
            huawei, rfb = sessions['huawei-kvm-v1'], sessions['standard-rfb-v1']
            await huawei.feed(block)
            await rfb.feed(_tight_fill(0, 0, 64, 64, (220, 30, 10)))
            for session in (huawei, rfb):
                framebuffer = session.framebuffer
                framebuffer.apply(Update(framebuffer.epoch, framebuffer.seq + 1,
                                         (Fill(Rect(0, 0, 64, 64), RED),)))
                session.attach('browser')
                session.request('browser', Rect(0, 0, 64, 64), incremental=False)
            wire = {}
            for family, session in sessions.items():
                batch = session.prepare('browser')
                wire[family] = list(session.messages('browser', batch))
                session.sent('browser', batch)
            return wire
        finally:
            for session in sessions.values():
                session.close()

    wire = asyncio.run(run())
    assert wire['standard-rfb-v1'] == wire['huawei-kvm-v1'] and wire['huawei-kvm-v1']
    for message in wire['huawei-kvm-v1']:
        assert message[0] == 0, 'only FramebufferUpdate may reach the browser'
        assert int.from_bytes(message[2:4], 'big') == 1
        encoding = int.from_bytes(message[12:16], 'big', signed=True)
        assert encoding in (0, 7), f'non-platform encoding {encoding} on the wire'
        if encoding == 7:
            assert message[16] in (0x80, 0x01)
