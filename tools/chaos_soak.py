#!/usr/bin/env python3
"""Randomized, bounded soak over the synthetic BMC -- never a real device."""
from __future__ import annotations

import argparse
import asyncio
import random
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tests.support.fake_bmc import FakeBmc, opened  # noqa: E402

FAULTS = ("burst", "swallow", "resize", "drop", "stall", "plain")
RESIZES = ((640, 480), (800, 600), (1280, 720))


def _configure(rng):
    kind = rng.choice(FAULTS)
    send_updates = rng.randint(2, 4)
    options = {"send_updates": send_updates}
    if kind == "burst":
        options["reset_on_burst"] = (rng.randint(2, 4), rng.randint(50, 1000))
    elif kind == "swallow":
        options["swallow_short_taps"] = float(rng.randint(1, 200))
    elif kind == "resize":
        options["resize_after_frames"] = 1
        options["resize_to"] = rng.choice(RESIZES)
    elif kind == "drop":
        options["drop_after_frames"] = rng.randint(1, send_updates)
        options["close_code"] = rng.choice([1011, 1012])
    elif kind == "stall":
        options["stall_after_frames"] = 1
        options["stall_seconds"] = 0.01
    return kind, options


async def _round(rng):
    kind, options = _configure(rng)
    server = await FakeBmc(**options).start()
    upstream = await opened(server)
    frames = 0

    async def sink(data: bytes) -> None:
        nonlocal frames
        frames += 1

    task = asyncio.create_task(upstream.relay(sink))
    errors = 0
    try:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + 1.0
        while frames < server.send_updates and not task.done():
            if loop.time() >= deadline:
                break
            await asyncio.sleep(0.005)
        if not task.done():
            try:
                for _ in range(rng.randint(1, 6)):
                    keysym = rng.randrange(0x61, 0x7B)
                    await upstream.send_key(keysym, True)
                    await upstream.send_key(keysym, False)
            except Exception:
                errors += 1
            await asyncio.sleep(0.01)
            if not task.done():
                task.cancel()
        await asyncio.gather(task, return_exceptions=True)
    finally:
        if not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        await upstream.close()
        await server.stop()
    return kind, frames, server.swallowed_taps, server.burst_reset_triggered, errors


async def soak(seed: int, seconds: float) -> dict:
    rng = random.Random(seed)
    counts = {name: 0 for name in FAULTS}
    total_frames = total_swallowed = total_bursts = total_errors = rounds = 0
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        kind, frames, swallowed, burst, errors = await _round(rng)
        rounds += 1
        counts[kind] += 1
        total_frames += frames
        total_swallowed += swallowed
        total_bursts += int(burst)
        total_errors += errors
    return {"rounds": rounds, "frames": total_frames, "swallowed": total_swallowed,
            "bursts": total_bursts, "errors": total_errors, "counts": counts}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Short randomized soak over the synthetic BMC")
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--seconds", type=float, default=2.0)
    args = parser.parse_args(argv)
    summary = asyncio.run(soak(args.seed, max(0.0, args.seconds)))
    print(f"chaos soak: seed={args.seed} seconds={args.seconds:.1f} "
          f"rounds={summary['rounds']} frames={summary['frames']} "
          f"bursts={summary['bursts']} swallowed={summary['swallowed']} "
          f"errors={summary['errors']}")
    print("scenarios: " + ", ".join(
        f"{k}={v}" for k, v in sorted(summary["counts"].items())))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
