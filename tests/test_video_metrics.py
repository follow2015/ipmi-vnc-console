"""V0 observations preserve the legacy pixels, messages and tolerances."""
import io
import json

from PIL import Image

from kvmhub.adapters.huawei_ibmc_kvm_gateway import HuaweiKvmRfbSession
from kvmhub.huawei_kvm_protocol import HuaweiFrameDecoder
from kvmhub.video_metrics import VideoMetrics


def jpeg_tile():
    output = io.BytesIO()
    Image.new('RGB', (64, 64), (220, 30, 10)).save(output, format='JPEG', quality=75)
    blob = output.getvalue()
    sos = blob.index(b'\xff\xda')
    header_end = sos + 2 + int.from_bytes(blob[sos + 2:sos + 4], 'big')
    header, entropy = blob[:header_end], blob[header_end:-2]
    return header, b'\x40' + len(entropy).to_bytes(2, 'big') + entropy


def test_observation_does_not_change_incremental_pixels_or_legacy_tolerance():
    header, tile = jpeg_tile()
    metrics = VideoMetrics()
    measured = HuaweiFrameDecoder(observations=metrics)
    legacy = HuaweiFrameDecoder()
    streams = [tile * 4, b'\x80\x80\x80\x80', b'\x80\xc0\xa0\x80',
               b'\x00', b'\x40', b'\x40\x00\x04x']
    for stream in streams:
        assert measured.decode(stream, 128, 128, 0, header) == legacy.decode(stream, 128, 128, 0, header)
    stream = b'\xa0\xc0'
    assert measured.decode(stream, 64, 64, 0, header) == legacy.decode(stream, 64, 64, 0, header)
    report = metrics.public()
    assert report['source_updates'] == len(streams) + 1
    assert report['source_bytes'] == sum(map(len, streams)) + len(stream)
    assert report['unknown_blocks'] == 1
    assert report['truncated_blocks'] == 2
    assert report['missing_copy_sources'] == 2
    assert report['geometry_changes'] == 2
    assert len(report['block_kinds']) == 8
    assert measured.decoded_blocks == legacy.decoded_blocks
    assert measured.failed_blocks == legacy.failed_blocks


async def test_metrics_preserve_entire_legacy_raw_output(monkeypatch):
    header, tile = jpeg_tile()
    monkeypatch.setattr('kvmhub.adapters.huawei_ibmc_kvm_gateway.jpeg_header', lambda quant: header)

    class Upstream:
        tag_id = 7
        async def frames(self):
            for stream in (tile * 4, b'\x80\x80\x80\x80', b'\x80\xc0\xa0\x80'):
                yield stream, 128, 128, 0

    async def relay(observe):
        session = HuaweiKvmRfbSession(Upstream(), 128, 128, measure_video=observe)
        await session._relay()
        output = []
        while not session._out.empty():
            item = session._out.get_nowait()
            if item is not None:
                output.append(item)
        return session, output

    legacy, expected = await relay(False)
    observed, actual = await relay(True)
    assert actual == expected and actual
    assert legacy.as_dict()['video_metrics'] is None
    report = observed.as_dict()['video_metrics']
    assert report['source_updates'] == observed.frames == 3
    assert report['encoded_messages'] == len(actual)
    assert report['encoded_bytes'] == sum(map(len, actual))
    assert report['queued_video_bytes'] == sum(map(len, actual))
    assert all(value >= 0 for value in report['stage_cpu_seconds'].values())
    assert all(value >= 0 for value in report['stage_wall_seconds'].values())
    json.dumps(report)
    assert set(report['block_kinds']) == set(range(8))
