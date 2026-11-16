"""M4: seeded, deterministic named fault scenarios S1-S5."""
from __future__ import annotations

import asyncio
import random
import struct
from dataclasses import dataclass

from tests.support.fake_bmc import FakeBmc, opened, parse_client_messages

SEED = 20261114
SHORT_HOLD_S = 0.001
LONG_HOLD_S = 0.200
SHORT_THRESHOLD_MS = 50.0
KEY_EVENT_TYPE = 4


def _key_event(keysym: int, down: bool) -> bytes:
    return struct.pack(">BBHI", KEY_EVENT_TYPE, int(down), 0, keysym)


class SequenceClock:
    def __init__(self, times):
        self._values = iter(times)
        self._last = 0.0

    def __call__(self):
        try:
            self._last = next(self._values)
        except StopIteration:
            pass
        return self._last


def _seed_timeline(seed: int, count: int):
    rng = random.Random(seed)
    kinds = [rng.choice(("short", "long")) for _ in range(count)]
    times: list[float] = []
    batch = bytearray()
    now = 0.0
    for index, kind in enumerate(kinds):
        keysym = 0x61 + index
        batch += _key_event(keysym, True) + _key_event(keysym, False)
        times.append(now)
        now += SHORT_HOLD_S if kind == "short" else LONG_HOLD_S
        times.append(now)
        now += 0.010
    return kinds, times, bytes(batch)


def rect_size(frame: bytes) -> tuple[int, int]:
    assert frame[0] == 0, "not a FramebufferUpdate"
    _, _, width, height = struct.unpack_from(">HHHH", frame, 4)
    return width, height


@dataclass
class Observation:
    frames: list[bytes]
    messages: list[tuple]
    close_code: int | None
    swallowed: int
    burst: bool
    width: int
    height: int


async def _wait_until(predicate, timeout: float = 2.0) -> bool:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        if predicate():
            return True
        await asyncio.sleep(0.005)
    return predicate()


async def _drive(server, *, batches=(), min_frames=None, expect_close=False,
                 timeline=None) -> Observation:
    await server.start()
    upstream = await opened(server)
    frames: list[bytes] = []

    async def sink(data: bytes) -> None:
        frames.append(data)

    task = asyncio.create_task(upstream.relay(sink))
    try:
        if min_frames is None:
            min_frames = server.send_updates
        await _wait_until(lambda: len(frames) >= min_frames or task.done())
        for batch in batches:
            await upstream.send_raw(batch)
        expected = 2 + sum(len(parse_client_messages(b)) for b in batches)
        await _wait_until(lambda: server.client_messages_seen >= expected
                          or server.burst_reset_triggered or task.done())
        if timeline is not None:
            await timeline(frames, upstream, task)
        if expect_close:
            await _wait_until(lambda: task.done())
            await asyncio.gather(task, return_exceptions=True)
        elif not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        return Observation(frames=list(frames), messages=list(server.client_messages),
                           close_code=upstream.upstream_close_code,
                           swallowed=server.swallowed_taps,
                           burst=server.burst_reset_triggered,
                           width=upstream.stats.width, height=upstream.stats.height)
    finally:
        if not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        await upstream.close()
        await server.stop()


async def test_s1_mid_stream_close_keeps_the_bmc_code():
    rng = random.Random(SEED)
    code = rng.choice([1011, 1012])
    obs = await _drive(FakeBmc(send_updates=4, drop_after_frames=2, close_code=code),
                       batches=(), min_frames=0, expect_close=True)
    assert obs.close_code == code
    assert len(obs.frames) == 2, "frames before the drop must still reach the browser"


async def test_s2_frozen_picture_keeps_the_session_open():
    rng = random.Random(SEED)
    stall = rng.choice([0.15, 0.2, 0.25])

    async def during_stall(frames, upstream, task):
        assert len(frames) >= 1, "the first frame arrives before the stall"
        assert not task.done(), "a stall is not an end"
        assert upstream.upstream_close_code is None
        await _wait_until(lambda: len(frames) >= 3)

    obs = await _drive(FakeBmc(send_updates=3, stall_after_frames=1,
                               stall_seconds=stall),
                       batches=(), min_frames=1, timeline=during_stall)
    assert len(obs.frames) >= 3, "frames resume once the stall is over"
    assert obs.close_code is None


async def test_s3_burst_reset_ends_the_session_with_1006():
    rng = random.Random(SEED)
    keys = [rng.randrange(0x61, 0x7b) for _ in range(3)]
    batch = b"".join(_key_event(k, True) for k in keys)
    times = [0.0, 0.01, 0.02, 0.03, 0.04]
    obs = await _drive(FakeBmc(send_updates=2, reset_on_burst=(3, 1000),
                               clock=SequenceClock(times)),
                       batches=[batch], expect_close=True)
    assert obs.burst is True
    assert obs.close_code == 1006, "the abort must not read as an orderly close"
    assert len(obs.frames) >= 2, "frames before the reset still reached the browser"


async def test_s4_short_taps_are_dropped_long_taps_survive():
    kinds, times, batch = _seed_timeline(SEED, 6)
    obs = await _drive(FakeBmc(send_updates=2, swallow_short_taps=SHORT_THRESHOLD_MS,
                               clock=SequenceClock(times)),
                       batches=[batch])
    short = kinds.count("short")
    long_keys = {0x61 + i for i, kind in enumerate(kinds) if kind == "long"}
    kept = [m for m in obs.messages if m[0] == "KeyEvent"]
    assert obs.swallowed == short, "exactly the short pairs are dropped"
    assert obs.burst is False and obs.close_code is None, "the session survives"
    assert len(kept) == 2 * len(long_keys), "each surviving tap keeps both events"
    assert {m[2] for m in kept} == long_keys


async def test_s5_resolution_change_keeps_handshake_geometry():
    rng = random.Random(SEED)
    resize_to = rng.choice([(640, 480), (800, 600), (1280, 720)])
    obs = await _drive(FakeBmc(send_updates=3, resize_after_frames=1,
                               resize_to=resize_to),
                       batches=(), min_frames=3)
    assert len(obs.frames) >= 3
    assert rect_size(obs.frames[0]) == (1024, 768)
    assert rect_size(obs.frames[1]) == resize_to
    assert rect_size(obs.frames[2]) == resize_to
    assert (obs.width, obs.height) == (1024, 768), "ServerInit is not re-read"
    assert obs.close_code is None


async def test_switches_off_leave_wire_bytes_unchanged():
    batch = (_key_event(0x61, True) + _key_event(0x61, False)
             + _key_event(0x62, True) + _key_event(0x62, False))
    baseline = await _drive(FakeBmc(send_updates=2, payload_bytes=48),
                            batches=[batch])
    inert = await _drive(FakeBmc(send_updates=2, payload_bytes=48,
                                 swallow_short_taps=0.0,
                                 reset_on_burst=(10 ** 6, 1)),
                         batches=[batch])
    assert inert.frames == baseline.frames, "relayed frames must be byte-identical"
    assert inert.messages == baseline.messages, "client messages must be unchanged"
    assert inert.swallowed == 0 and inert.burst is False
    keys = [m for m in baseline.messages if m[0] == "KeyEvent"]
    assert keys == [("KeyEvent", 1, 0x61), ("KeyEvent", 0, 0x61),
                    ("KeyEvent", 1, 0x62), ("KeyEvent", 0, 0x62)]


async def test_reset_on_burst_does_not_fire_outside_the_window():
    rng = random.Random(SEED)
    keys = [rng.randrange(0x61, 0x7b) for _ in range(3)]
    batch = b"".join(_key_event(k, True) for k in keys)
    times = [0.0, 0.2, 0.4, 0.6, 0.8]
    obs = await _drive(FakeBmc(send_updates=2, reset_on_burst=(3, 100),
                               clock=SequenceClock(times)),
                       batches=[batch])
    assert obs.burst is False
    assert obs.close_code is None
    assert len([m for m in obs.messages if m[0] == "KeyEvent"]) == 3


def test_seed_reproduces_the_same_timeline():
    first = _seed_timeline(SEED, 6)
    second = _seed_timeline(SEED, 6)
    other = _seed_timeline(SEED + 1, 6)
    assert first == second
    assert first != other
