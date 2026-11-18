"""Limit-and-degradation drill: do refusals leave a clean state?"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from kvmhub.platform.bus import AssemblyBus  # noqa: E402
from kvmhub.platform.console import ConsolePlane  # noqa: E402
from kvmhub.platform.redis_state import MemoryState  # noqa: E402
from kvmhub.platform.services import PlatformError  # noqa: E402
from kvmhub.store import Store  # noqa: E402

KEY = b"k" * 32
TENANT = "drill-tenant"
USER = "local-admin"


def make_plane(root: Path, capacity: int):
    root.mkdir(parents=True, exist_ok=True)
    store = Store(str(root / "drill.sqlite"), KEY)
    store.seed_mock("127.0.0.1:5900", "0" * 64, "admin", "synthetic-password")
    state = MemoryState()
    bus = AssemblyBus(state)
    plane = ConsolePlane(
        store=store, private_key=Ed25519PrivateKey.generate(), bus=bus,
        accept_template="https://{worker_id}-{sid}.kvm.localhost:9443/_platform/accept")
    return store, state, bus, plane


def assembly(asset_id: str) -> dict:
    return {"asset_id": asset_id, "tenant_id": TENANT, "ready": True,
            "profile": {}, "plan": {}, "data_plane": {}, "checks": {},
            "credential_id": None}


def leftovers(store: Store) -> dict:
    return {
        "pending_sessions": store.db.execute(
            "SELECT COUNT(*) FROM session WHERE status='pending'").fetchone()[0],
        "asset_slots": store.db.execute("SELECT COUNT(*) FROM asset_slot").fetchone()[0],
    }


async def attempt(plane: ConsolePlane, asset_id: str, *, limit: int | None = None):
    try:
        opened = await plane.open(assembly(asset_id), user_id=USER, concurrent_limit=limit)
        return {"ok": True, "sid": opened["sid"]}, None
    except PlatformError as exc:
        return None, {"code": exc.code, "status": exc.status}


async def close(plane: ConsolePlane, sid: str) -> None:
    await plane.close_session(sid, user_id=USER, tenant_id=TENANT)


async def asset_exclusivity(root: Path) -> dict:
    store, state, bus, plane = make_plane(root, capacity=4)
    try:
        await bus.register_worker("w1", instance_id="i1", capacity=4)
        first, error = await attempt(plane, "mock-1")
        assert first and error is None, error
        again, error = await attempt(plane, "mock-1")
        assert again is None and error and error["code"] == "asset_busy", error
        second_code = error["code"]
        after_refusal = leftovers(store)
        await close(plane, first["sid"])
        reopened, error = await attempt(plane, "mock-1")
        assert reopened and error is None, error
        await close(plane, reopened["sid"])
        return {"first_granted": True, "second_code": second_code,
                "after_refusal": after_refusal, "recovered_after_close": True,
                "clean_refusal": after_refusal["pending_sessions"] == 1
                and after_refusal["asset_slots"] == 1}
    finally:
        plane.close()
        await state.close()


async def tenant_quota(root: Path) -> dict:
    store, state, bus, plane = make_plane(root, capacity=4)
    try:
        await bus.register_worker("w1", instance_id="i1", capacity=4)
        first, error = await attempt(plane, "mock-1", limit=1)
        assert first and error is None, error
        second, error = await attempt(plane, "mock-2", limit=1)
        assert second is None and error and error["code"] == "quota_exceeded", error
        second_code = error["code"]
        after_refusal = leftovers(store)
        quota_members = await bus.quota_members(TENANT)
        await close(plane, first["sid"])
        reopened, error = await attempt(plane, "mock-2", limit=1)
        assert reopened and error is None, error
        await close(plane, reopened["sid"])
        return {"first_granted": True, "second_code": second_code,
                "after_refusal": after_refusal, "quota_members_after_refusal": len(quota_members),
                "recovered_after_close": True,
                "clean_refusal": after_refusal["asset_slots"] == 1 and len(quota_members) == 1}
    finally:
        plane.close()
        await state.close()


async def worker_capacity(root: Path) -> dict:
    store, state, bus, plane = make_plane(root, capacity=1)
    try:
        await bus.register_worker("w1", instance_id="i1", capacity=1)
        first, error = await attempt(plane, "mock-1")
        assert first and error is None, error
        second, error = await attempt(plane, "mock-2")
        assert second is None and error and error["code"] == "worker_capacity_exhausted", error
        second_code = error["code"]
        after_refusal = leftovers(store)
        load = await bus.worker_load("w1")
        await close(plane, first["sid"])
        reopened, error = await attempt(plane, "mock-2")
        assert reopened and error is None, error
        await close(plane, reopened["sid"])
        return {"first_granted": True, "second_code": second_code,
                "after_refusal": after_refusal, "worker_load_after_refusal": load,
                "recovered_after_close": True,
                "clean_refusal": after_refusal["pending_sessions"] == 1
                and after_refusal["asset_slots"] == 1 and load == 1}
    finally:
        plane.close()
        await state.close()


async def run(root: Path | None = None) -> dict:
    root = root or Path(".local-limit-drill")
    root.mkdir(parents=True, exist_ok=True)
    stamp = time.time()
    scenarios = {
        "asset_exclusivity": await asset_exclusivity(root / "asset"),
        "tenant_quota": await tenant_quota(root / "quota"),
        "worker_capacity": await worker_capacity(root / "worker"),
    }
    assertions = {
        "asset_busy_is_clean": scenarios["asset_exclusivity"]["clean_refusal"],
        "quota_exceeded_is_clean": scenarios["tenant_quota"]["clean_refusal"],
        "worker_full_is_clean": scenarios["worker_capacity"]["clean_refusal"],
        "all_limits_recover": all(item["recovered_after_close"] for item in scenarios.values()),
    }
    return {"generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(stamp)),
            "backend": "sqlite (synthetic mock BMC, in-process state)",
            "scenarios": scenarios, "assertions": assertions,
            "all_green": all(assertions.values())}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", help="also write the report to this JSON path")
    args = parser.parse_args()
    report = asyncio.run(run())
    text = json.dumps(report, ensure_ascii=False, indent=1)
    print(text)
    if args.out:
        target = Path(args.out)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text + "\n", encoding="utf-8")
    return 0 if report["all_green"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
