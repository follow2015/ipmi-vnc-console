"""Decoder pipe I/O must not stall the Worker's event loop (review d40d012 R8)."""
from __future__ import annotations

import asyncio
import struct
import threading
import time
from types import SimpleNamespace

from kvmhub.video.runtime import ManagedDecoder


def test_adecode_runs_off_the_loop_and_keeps_the_ticker_alive():
    decoder = ManagedDecoder(require_hard_cpu_limit=False)
    decoder.epoch = 1
    decoder.needs_resync = False
    decoder.proc = SimpleNamespace(is_alive=lambda: True)
    worker_thread = {}

    def blocking_decode(stream):
        worker_thread["name"] = threading.current_thread().name
        time.sleep(0.15)
        return SimpleNamespace(epoch=1, payload=b"\x00\x00\x00\x00")

    decoder.decode_update = blocking_decode

    async def run():
        loop = asyncio.get_running_loop()
        ticks = []

        async def ticker():
            while True:
                ticks.append(loop.time())
                await asyncio.sleep(0.01)

        task = asyncio.create_task(ticker())
        await asyncio.sleep(0.02)
        answer = await decoder.adecode_update(b"update")
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        return answer, ticks

    answer, ticks = asyncio.run(run())
    assert answer.epoch == 1
    gaps = [later - earlier for earlier, later in zip(ticks, ticks[1:])]
    assert gaps and max(gaps) < 0.10
    assert worker_thread["name"] != threading.current_thread().name


def test_start_and_reset_also_run_off_the_loop():
    decoder = ManagedDecoder(require_hard_cpu_limit=False)
    threads = []

    def fake_start():
        threads.append(threading.current_thread().name)

    decoder.start = fake_start
    decoder.reset = lambda *args, **kwargs: 7

    assert asyncio.run(decoder.resync(4, 4)) == 7
    assert threads and all(name != threading.current_thread().name for name in threads)


def test_pipe_operations_are_serialised_per_decoder():
    decoder = ManagedDecoder(require_hard_cpu_limit=False)
    decoder.epoch = 1
    decoder.needs_resync = False
    decoder.proc = SimpleNamespace(is_alive=lambda: True)
    active = 0
    peak = 0

    def blocking_decode(stream):
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        time.sleep(0.03)
        active -= 1
        return SimpleNamespace(epoch=1, payload=b"")

    decoder.decode_update = blocking_decode
    decoder.reset = lambda *args, **kwargs: 1

    async def run():
        await asyncio.gather(
            decoder.adecode_update(b"one"),
            decoder.adecode_update(b"two"),
            decoder.resync(4, 4),
        )

    asyncio.run(run())
    assert peak == 1


def test_real_decode_update_path_keeps_the_loop_alive(monkeypatch):
    import kvmhub.video.runtime as runtime

    decoder = runtime.ManagedDecoder(require_hard_cpu_limit=False)
    decoder.epoch = 1
    decoder.needs_resync = False
    decoder.proc = SimpleNamespace(is_alive=lambda: True)
    decoder.conn = SimpleNamespace(close=lambda: None)
    monkeypatch.setattr(runtime, "send_frame", lambda conn, nonce, message: None)

    def slow_read(conn, nonce, timeout=None):
        time.sleep(0.12)
        return runtime.Message(1, 0, runtime.SIGNAL, struct.pack(">III", 0, 1, 1))

    monkeypatch.setattr(runtime, "read_frame", slow_read)

    async def run():
        loop = asyncio.get_running_loop()
        ticks = []

        async def ticker():
            while True:
                ticks.append(loop.time())
                await asyncio.sleep(0.01)

        task = asyncio.create_task(ticker())
        await asyncio.sleep(0.02)
        update = await decoder.adecode_update(b"update")
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        return update, ticks

    update, ticks = asyncio.run(run())
    assert update.epoch == 1
    gaps = [later - earlier for earlier, later in zip(ticks, ticks[1:])]
    assert gaps and max(gaps) < 0.10
