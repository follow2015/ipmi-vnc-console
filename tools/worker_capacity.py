"""Multi-Worker registration and capacity probe."""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from kvmhub.platform.bus import AssemblyBus, BusError  # noqa: E402
from kvmhub.platform.redis_state import MemoryState, create_state  # noqa: E402

REGISTRATION_TTL = 60


async def run_probe(*, workers: int, sessions: int, capacity: int,
                    state=None, clock=time.time) -> dict:
    if workers < 1 or sessions < 1 or capacity < 1:
        raise ValueError("workers/sessions/capacity must be positive")
    state = state or MemoryState(clock=clock)
    bus = AssemblyBus(state, clock=clock)
    for index in range(workers):
        await bus.register_worker(f"w{index}", instance_id=f"i{index}",
                                  capacity=capacity, ttl=REGISTRATION_TTL)

    async def attempt(index: int) -> dict:
        try:
            chosen = await bus.choose_worker()
            sid = f"probe-{index}"
            if not await bus.claim_session(chosen["worker_id"], sid, REGISTRATION_TTL):
                return {"ok": False, "reason": "claim_race", "sid": sid}
            return {"ok": True, "worker": chosen["worker_id"], "sid": sid}
        except BusError as exc:
            return {"ok": False, "reason": exc.code, "sid": f"probe-{index}"}

    results = await asyncio.gather(*(attempt(i) for i in range(sessions)))
    granted = [item for item in results if item["ok"]]
    refused = [item for item in results if not item["ok"]]
    distribution = Counter(item["worker"] for item in granted)
    loads = {f"w{i}": await bus.worker_load(f"w{i}") for i in range(workers)}
    total_capacity = workers * capacity
    spread = (max(distribution.values()) - min(distribution.values())) if distribution else 0

    released = 0
    for item in granted[: max(1, len(granted) // 2)]:
        await bus.release_session(item["worker"], item["sid"])
        released += 1
    retry = await asyncio.gather(*(attempt(10_000 + i) for i in range(released)))
    retry_granted = sum(1 for item in retry if item["ok"])

    report = {
        "workers": workers, "capacity_per_worker": capacity,
        "total_capacity": total_capacity, "attempted": sessions,
        "granted": len(granted), "refused": len(refused),
        "refusal_reasons": dict(Counter(item["reason"] for item in refused)),
        "distribution": dict(sorted(distribution.items())),
        "final_loads": loads,
        "least_loaded_spread": spread,
        "released": released, "reclaim_granted": retry_granted,
        "bounded": all(load <= capacity for load in loads.values()),
        "no_oversubscription": len(granted) <= total_capacity,
        "no_unexplained_refusal": all(item["reason"] in
                                      ("worker_capacity_exhausted", "claim_race") for item in refused),
        "release_frees_slots": retry_granted == released,
    }
    await state.close()
    return report


async def ttl_probe(*, clock_box: dict, ttl: int = REGISTRATION_TTL) -> dict:
    state = MemoryState(clock=lambda: clock_box["now"])
    bus = AssemblyBus(state, clock=lambda: clock_box["now"])
    await bus.register_worker("w0", instance_id="i0", capacity=2, ttl=ttl)
    before = len(await bus.workers())
    clock_box["now"] += ttl + 1
    after = len(await bus.workers())
    await state.close()
    return {"before": before, "after": after, "expired": before == 1 and after == 0}


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--workers", type=int, default=4)
    p.add_argument("--sessions", type=int, default=40)
    p.add_argument("--capacity", type=int, default=3)
    p.add_argument("--redis-url", default="", help="use a real Redis instead of in-process state")
    p.add_argument("--out", help="also write the JSON report to this path")
    args = p.parse_args()
    state = create_state(args.redis_url) if args.redis_url else None
    report = asyncio.run(run_probe(workers=args.workers, sessions=args.sessions,
                                   capacity=args.capacity, state=state))
    clock_box = {"now": time.time()}
    report["ttl"] = asyncio.run(ttl_probe(clock_box=clock_box))
    report["assertions"] = {
        "bounded": report["bounded"],
        "no_oversubscription": report["no_oversubscription"],
        "no_unexplained_refusal": report["no_unexplained_refusal"],
        "release_frees_slots": report["release_frees_slots"],
        "ttl_expiry": report["ttl"]["expired"],
    }
    text = json.dumps(report, ensure_ascii=False, indent=1)
    print(text)
    if args.out:
        Path(args.out).write_text(text + "\n", encoding="utf-8")
    return 0 if all(report["assertions"].values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
