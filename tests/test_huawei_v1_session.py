"""Real isolated decoder through the opt-in RFB bridge; synthetic upstream only."""
import asyncio
import struct

import pytest

from kvmhub.common import Problem
from kvmhub.huawei_kvm_input import packet_command
from kvmhub.rfb_server import RFB_PIXEL_FORMAT_32BPP
from kvmhub.video.huawei_session import HuaweiV1RfbSession
from kvmhub.video.runtime import ManagedDecoder, VideoBudgetError, VideoProtocolError
from kvmhub.video.synthetic import jpeg_block


class Source:
    tag_id = 1

    def __init__(self):
        self.queue = asyncio.Queue()
        self.inputs = []

    async def frames(self):
        while True:
            yield await self.queue.get()

    async def send_input(self, data):
        self.inputs.append(data)


async def permit():
    return None


async def connected(monkeypatch, **kwargs):
    header, blocks = jpeg_block()
    monkeypatch.setattr('kvmhub.video.huawei_session.jpeg_header', lambda quant: header)
    source = Source()
    decoder = ManagedDecoder(require_hard_cpu_limit=False, require_resync_permit=True,
                             before_resync=permit)
    session = HuaweiV1RfbSession(source, 64, 64, before_resync=permit, decoder=decoder, **kwargs)
    await session.start()
    assert (await anext(session)).data == b'RFB 003.008\n'
    await session.send_bytes(b'RFB 003.008\n')
    assert (await anext(session)).data == b'\1\1'
    await session.send_bytes(b'\1')
    assert (await anext(session)).data == b'\0'*4
    await session.send_bytes(b'\1')
    init = (await anext(session)).data
    assert struct.unpack('>HH', init[:4]) == (64, 64)
    await session.send_bytes(b'\0'*4 + RFB_PIXEL_FORMAT_32BPP)
    return session, source, blocks


def request(incremental=False):
    return struct.pack('>BBHHHH', 3, incremental, 0, 0, 64, 64)


def test_source_requires_request_and_acknowledges_only_after_completed_send(monkeypatch):
    async def run():
        session, source, blocks = await connected(monkeypatch)
        try:
            await source.queue.put((blocks, 64, 64, 0))
            for _ in range(100):
                if session.frames:
                    break
                await asyncio.sleep(.01)
            assert session.frames == 1
            with pytest.raises(TimeoutError):
                await asyncio.wait_for(anext(session), .03)
            await session.send_bytes(request())
            message = (await asyncio.wait_for(anext(session), 1)).data
            assert struct.unpack('>BBHHHHHi', message[:16]) == (0, 0, 1, 0, 0, 64, 64, 0)
            assert message[18] > 180 and message[16] < 40
            stream = session.video.streams['browser']
            assert stream.inflight is not None and stream.pending
            await session.send_bytes(request(True))
            with pytest.raises(TimeoutError):
                await asyncio.wait_for(anext(session), .03)
            assert stream.inflight is None
            assert session.video.decoder.ledger.memory == 64*64*5
            await source.queue.put((blocks, 64, 64, 0))
            assert (await asyncio.wait_for(anext(session), 1)).data
        finally:
            await session.close()
        assert session.video.decoder.ledger.memory == 0
    asyncio.run(run())


def test_fragmented_requests_tight_negotiation_and_paired_input_release(monkeypatch):
    async def run():
        session, source, blocks = await connected(monkeypatch)
        try:
            await session.send_bytes(struct.pack('>BBHi', 2, 0, 1, 7))
            for byte in request():
                await session.send_bytes(bytes([byte]))
            await source.queue.put((blocks, 64, 64, 0))
            message = (await asyncio.wait_for(anext(session), 1)).data
            assert int.from_bytes(message[12:16], 'big', signed=True) == 7
            await session.send_bytes(struct.pack('>BBHI', 4, 1, 0, ord('a')))
            await session.send_bytes(struct.pack('>BBHH', 5, 1, 20, 30))
            assert [packet_command(p) for p in source.inputs] == [3, 5]
        finally:
            await session.close()
        assert [packet_command(p) for p in source.inputs] == [3, 5, 3, 5]
        assert not session.release_failed
    asyncio.run(run())


def test_repeated_preopen_requests_are_coalesced_not_fatal(monkeypatch):
    async def run():
        session, source, blocks = await connected(monkeypatch)
        try:
            for _ in range(64):
                await session.send_bytes(request())
            assert len(session._requests) == 1
            await source.queue.put((blocks, 64, 64, 0))
            message = (await asyncio.wait_for(anext(session), 1)).data
            assert message
        finally:
            await session.close()
    asyncio.run(run())


def test_read_only_input_is_discarded_before_codec(monkeypatch):
    async def run():
        session, source, blocks = await connected(monkeypatch, read_only=True)
        try:
            await session.send_bytes(struct.pack('>BBHI', 4, 1, 0, ord('a')))
            await session.send_bytes(struct.pack('>BBHH', 5, 1, 20, 30))
            assert session.input.stats.keys == session.input.stats.pointers == 0
        finally:
            await session.close()
        assert source.inputs == []
    asyncio.run(run())


@pytest.mark.parametrize('message', [b'\6'+b'\0'*7, b'\xff',
    struct.pack('>BBHHHH', 3, 2, 0, 0, 64, 64),
    struct.pack('>BBHHHH', 3, 0, 64, 0, 1, 1),
    struct.pack('>BBHH', 5, 0, 64, 0),
    b'\0'*20, b'\2\0\xff\xff'])
def test_invalid_browser_frames_fail_closed(monkeypatch, message):
    async def run():
        session, source, blocks = await connected(monkeypatch)
        try:
            with pytest.raises(ValueError):
                await session.send_bytes(message)
            assert not source.inputs
        finally:
            await session.close()
    asyncio.run(run())


def test_geometry_change_requests_browser_reload_without_reusing_buffer(monkeypatch):
    async def run():
        session, source, blocks = await connected(monkeypatch)
        try:
            await source.queue.put((blocks, 128, 64, 0))
            with pytest.raises(StopAsyncIteration):
                await asyncio.wait_for(anext(session), 1)
            assert session.reload_requested and session.geometry_after['width'] == 128
        finally:
            await session.close()
    asyncio.run(run())


def test_stalled_send_and_partial_send_cleanup(monkeypatch):
    async def run():
        session, source, blocks = await connected(monkeypatch)
        await session.send_bytes(request())
        await source.queue.put((blocks, 64, 64, 0))
        await asyncio.wait_for(anext(session), 1)
        queue = session.video.queues['browser']
        queue.clock = lambda: queue.oldest + queue.budget.output_age + 1
        with pytest.raises(VideoBudgetError, match='output_age'):
            await anext(session)
        await session.close()
        assert session.video.decoder.ledger.memory == 0
    asyncio.run(run())


def test_failed_key_release_is_reported(monkeypatch):
    async def run():
        session, source, blocks = await connected(monkeypatch)
        await session.send_bytes(struct.pack('>BBHI', 4, 1, 0, ord('a')))
        async def fail(data):
            raise OSError('synthetic')
        source.send_input = fail
        await session.close()
        assert session.release_failed and session.error == 'video_input_release_failed'
    asyncio.run(run())


def test_adapter_keeps_legacy_default_and_gates_v1_reconnection(monkeypatch):
    from kvmhub.adapters import huawei_ibmc_kvm_gateway as gateway
    from kvmhub.video.client_v2 import protocol_contract
    monkeypatch.setenv('KVMHUB_HUAWEI_VNC_PIN', 'ab'*32)
    info = dict(adapter='huawei-ibmc-kvm-gateway', target='https://192.0.2.10',
                video_lane='transcode-v1', video_binding='b'*64,
                video_contract=protocol_contract())
    class Transport(Source):
        framebuffer_width = framebuffer_height = 64
        connected = True
        ticket = object()
        username = 'synthetic-user'
        password = 'synthetic-password'
        def __init__(self, *args, **kwargs):
            super().__init__()
            self.closed_count = 0
        async def connect(self):
            order.append('connect')
        async def close(self):
            self.closed_count += 1
            return True
    order = []
    async def hook():
        order.append('permit')
    async def start_stub(self):
        order.append('decoder')
    monkeypatch.setattr(gateway, 'HuaweiKvmUpstream', Transport)
    monkeypatch.setattr(HuaweiV1RfbSession, 'start', start_stub)
    async def run():
        legacy = gateway.HuaweiIbmcKvmGatewayAdapter(
            dict(info, video_lane=''), networks=('192.0.2.0/24',))
        legacy.upstream = Transport()
        old = await legacy.connect(['binary'])
        assert isinstance(old, gateway.HuaweiKvmRfbSession)
        await legacy.close()
        adapter = gateway.HuaweiIbmcKvmGatewayAdapter(info, networks=('192.0.2.0/24',))
        adapter.upstream = Transport()
        with pytest.raises(Problem, match='pipeline_version_unavailable'):
            await adapter.connect(['binary'])
        adapter.video_before_resync = hook
        first = await adapter.connect(['binary'])
        assert isinstance(first, HuaweiV1RfbSession)
        await first.close()
        order.clear()
        second = await adapter.connect(['binary'])
        assert order == ['permit', 'connect', 'decoder']
        await adapter.close()
    asyncio.run(run())


def test_decoder_start_failure_never_returns_usable_browser_session(monkeypatch):
    async def run():
        decoder = ManagedDecoder(require_hard_cpu_limit=False)
        def fail():
            raise RuntimeError('synthetic startup failure')
        monkeypatch.setattr(decoder, 'start', fail)
        session = HuaweiV1RfbSession(Source(), 64, 64, before_resync=permit, decoder=decoder)
        with pytest.raises(RuntimeError):
            await session.start()
        assert not decoder.running and decoder.ledger.memory == 0
    asyncio.run(run())


def test_standard_client_raw_rgbx_matches_negotiated_channel_order():
    from kvmhub.video.encoding import encode_snapshot
    from kvmhub.video.framebuffer import Rect, Snapshot
    snapshot = Snapshot(1, 1, Rect(0, 0, 1, 1), b'\x0a\x1e\xdc\0')
    assert list(encode_snapshot(snapshot, tight=False))[0][16:] == b'\x0a\x1e\xdc\0'
    assert list(encode_snapshot(snapshot, tight=False, rgbx=True))[0][16:] == b'\xdc\x1e\x0a\0'


def test_input_rate_budget_ends_input_without_losing_release_state(monkeypatch):
    async def run():
        session, source, blocks = await connected(monkeypatch)
        try:
            session._input_count = 240
            with pytest.raises(VideoProtocolError, match='input_rate_budget'):
                await session.send_bytes(struct.pack('>BBHI', 4, 1, 0, ord('a')))
            assert source.inputs == []
        finally:
            await session.close()
    asyncio.run(run())
