"""V1 IPC wire format: exact roundtrip, budget-aware bounds, hostile mutations."""
import pytest

from kvmhub.video.framebuffer import Copy, Fill, Raw, Rect, Update
from kvmhub.video.runtime import VideoProtocolError
from kvmhub.video.wire import pack_update, unpack_update


def test_wire_roundtrip_preserves_operations():
    update = Update(2, 7, (
        Fill(Rect(0, 0, 8, 8), b'\x01\x02\x03\x04'),
        Copy(Rect(8, 0, 8, 8), 0, 0),
        Raw(Rect(0, 8, 8, 8), bytes(8 * 8 * 4)),
    ))
    payload = pack_update(update, limit=(64, 64))
    assert unpack_update(payload, limit=(64, 64)) == update


@pytest.mark.parametrize('mutation', [
    lambda raw: raw[:-1],
    lambda raw: raw + b'x',
    lambda raw: bytes([raw[0] + 1]) + raw[1:],
    lambda raw: raw[:28] + b'\x09' + raw[29:],
])
def test_wire_mutations_are_rejected(mutation):
    payload = pack_update(Update(1, 1, (Fill(Rect(0, 0, 4, 4), bytes(4)),)))
    with pytest.raises(VideoProtocolError):
        unpack_update(mutation(payload))


def test_wire_rejects_wrong_raw_size_before_building_an_object():
    with pytest.raises(VideoProtocolError, match='video_wire_raw_invalid'):
        pack_update(Update(1, 1, (Raw(Rect(0, 0, 4, 4), b'short'),)))


def test_wire_geometry_follows_the_caller_budget():
    update = Update(1, 1, (Fill(Rect(600, 0, 80, 8), bytes(4)),))
    payload = pack_update(update)
    with pytest.raises(ValueError, match='video_rect_invalid'):
        pack_update(update, limit=(640, 480))
    with pytest.raises(ValueError, match='video_rect_invalid'):
        unpack_update(payload, limit=(640, 480))
    with pytest.raises(VideoProtocolError, match='video_wire_limit_invalid'):
        unpack_update(payload, limit=(0, 0))
