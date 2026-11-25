"""A one-way floor under the control plane's wall clock."""
from __future__ import annotations

WATERMARK_ID = "platform"

REGRESSION_TOLERANCE = 300.0


def evaluate(high_water: float | None, now: float,
             tolerance: float = REGRESSION_TOLERANCE) -> dict:
    floor = float(high_water or 0.0)
    behind = max(floor - float(now), 0.0)
    return {
        "high_water": floor,
        "behind": behind,
        "regressed": bool(floor) and behind > tolerance,
        "tolerance": float(tolerance),
    }


def advance(high_water: float | None, now: float) -> float:
    floor = float(high_water or 0.0)
    return max(floor, float(now))
