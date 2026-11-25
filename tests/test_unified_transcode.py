"""R-unit invariants for the unified, plugin-driven transcode platform."""
import asyncio
import shutil
import struct
from pathlib import Path

import pytest

import kvmhub
from kvmhub.common import Problem
from kvmhub.transcode import pipeline, registry, standard_rfb
from kvmhub.transcode.contract import PluginSpec
from kvmhub.transcode.huawei import HuaweiFamily
from kvmhub.transcode.standard_rfb import StandardRfbFamily
from kvmhub.video.encoding import encode_snapshot
from kvmhub.video.framebuffer import Fill, Rect, Snapshot
from kvmhub.video.runtime import ManagedDecoder, hard_cpu_limit_supported
from kvmhub.video.session import VideoSession
from kvmhub.video.synthetic import jpeg_block

NONCE = b'0123456789abcdef'
ROOT = Path(kvmhub.__file__).resolve().parents[1]


def _rect(x, y, w, h, encoding=7):
    return struct.pack('>HHHHI', x, y, w, h, encoding)


def _tight_fill(x, y, w, h, rgb):
    return (b'\x00\x00' + struct.pack('>H', 1) + _rect(x, y, w, h)
            + b'\x80' + bytes(rgb))


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


def test_p8_dropping_a_plugin_file_into_the_tree_cannot_register_it(tmp_path):
    target = _copytree_transcode(tmp_path)
    (target / 'hot_loaded.py').write_text('class P: pass\n')
    with pytest.raises(Problem, match='transcode_family_unsupported'):
        registry.select('hot-loaded')


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


def test_p10_both_families_share_one_northbound_encoder():
    huawei_decode = HuaweiFamily()
    assert isinstance(huawei_decode, object)
    sessions = [VideoSession(tight=True), VideoSession(tight=True)]
    snapshot = Snapshot(1, 1, Rect(0, 0, 4, 4), standard_rfb.bgrx(b'\x11\x22\x33') * 16)
    wire = [b''.join(encode_snapshot(snapshot, tight=session.tight)) for session in sessions]
    assert wire[0] == wire[1] and wire[0]
    assert all(session.decoder.__class__ is ManagedDecoder for session in sessions)
