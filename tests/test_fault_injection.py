"""M4: named fault scenarios against the synthetic BMC."""
from __future__ import annotations

import asyncio
import struct

from tests.support.fake_bmc import FakeBmc, opened


def rect_size(frame: bytes) -> tuple[int, int]:
    assert frame[0] == 0, "not a FramebufferUpdate"
    _, _, width, height = struct.unpack_from(">HHHH", frame, 4)
    return width, height


async def _collect_frames(upstream, wanted: int, timeout: float = 5.0) -> list[bytes]:
    frames: list[bytes] = []

    async def sink(data: bytes) -> None:
        frames.append(data)

    task = asyncio.create_task(upstream.relay(sink))
    deadline = asyncio.get_running_loop().time() + timeout
    while len(frames) < wanted:
        if task.done():
            break
        if asyncio.get_running_loop().time() >= deadline:
            break
        await asyncio.sleep(0.01)
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)
    return frames


async def test_s1_a_mid_stream_close_keeps_the_code_the_bmc_sent():
    server = await FakeBmc(send_updates=6, drop_after_frames=2, close_code=1011).start()
    try:
        upstream = await opened(server)
        delivered: list[bytes] = []

        async def sink(data: bytes) -> None:
            delivered.append(data)

        await upstream.relay(sink)
        assert len(delivered) == 2, "frames before the drop must still reach the browser"
        assert upstream.upstream_close_code == 1011
    finally:
        await upstream.close()
        await server.stop()


async def test_s1b_a_reset_is_recorded_as_1006_not_as_an_orderly_close():
    server = await FakeBmc(send_updates=4, drop_after_frames=1, abort=True).start()
    try:
        upstream = await opened(server)
        await upstream.relay(lambda data: asyncio.sleep(0))
        assert upstream.upstream_close_code == 1006, \
            "a reset must not be reported as a normal close"
    finally:
        await upstream.close()
        await server.stop()


async def test_s2_a_frozen_picture_is_not_a_lost_socket():
    server = await FakeBmc(send_updates=3, stall_after_frames=1, stall_seconds=0.4).start()
    try:
        upstream = await opened(server)
        frames: list[bytes] = []

        async def sink(data: bytes) -> None:
            frames.append(data)

        task = asyncio.create_task(upstream.relay(sink))
        await asyncio.sleep(0.15)
        assert upstream.stats.frames >= 1, "the first frame arrives before the stall"
        assert not task.done(), "a stall is not an end: the relay is still running"
        assert upstream.upstream_close_code is None
        await asyncio.sleep(0.6)
        assert upstream.stats.frames >= 3, "frames resume once the stall is over"
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
    finally:
        await upstream.close()
        await server.stop()


async def test_s3_a_resolution_change_is_visible_in_the_relayed_frames():
    server = await FakeBmc(send_updates=3, resize_after_frames=1, resize_to=(640, 480)).start()
    try:
        upstream = await opened(server)
        frames = await _collect_frames(upstream, 3)
        assert len(frames) >= 3
        assert rect_size(frames[0]) == (1024, 768)
        assert rect_size(frames[1]) == (640, 480)
        assert rect_size(frames[2]) == (640, 480)
        assert (upstream.stats.width, upstream.stats.height) == (1024, 768)
    finally:
        await upstream.close()
        await server.stop()
