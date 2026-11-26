"""A one-way floor under the control plane's wall clock."""
from __future__ import annotations

WATERMARK_ID = "platform"

REGRESSION_TOLERANCE = 30.0

FORWARD_JUMP_LIMIT = 24 * 3600.0


def evaluate(high_water: float | None, now: float,
             tolerance: float = REGRESSION_TOLERANCE,
             forward_limit: float = FORWARD_JUMP_LIMIT) -> dict:
    floor = float(high_water or 0.0)
    stamp = float(now)
    behind = max(floor - stamp, 0.0)
    forward = max(stamp - floor, 0.0)
    return {
        "high_water": floor,
        "behind": behind,
        "regressed": bool(floor) and behind > tolerance,
        "tolerance": float(tolerance),
        "forward": forward,
        "suspicious_forward": bool(floor) and forward > float(forward_limit),
        "forward_limit": float(forward_limit),
    }


def advance(high_water: float | None, now: float,
            *, forward_limit: float = FORWARD_JUMP_LIMIT) -> float:
    floor = float(high_water or 0.0)
    if floor and float(now) - floor > float(forward_limit):
        return floor
    return max(floor, float(now))
