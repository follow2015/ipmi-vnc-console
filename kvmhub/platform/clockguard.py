"""A one-way floor under the control plane's wall clock."""
from __future__ import annotations

WATERMARK_ID = "platform"

REGRESSION_TOLERANCE = 30.0

FORWARD_JUMP_LIMIT = 24 * 3600.0

CLOCK_DRIFT_TOLERANCE = 60.0


def evaluate(high_water: float | None, now: float,
             tolerance: float = REGRESSION_TOLERANCE,
             forward_limit: float = FORWARD_JUMP_LIMIT,
             *, monotonic: float | None = None,
             monotonic_anchor: float | None = None) -> dict:
    floor = float(high_water or 0.0)
    stamp = float(now)
    behind = max(floor - stamp, 0.0)
    forward = max(stamp - floor, 0.0)
    elapsed_monotonic = None
    if monotonic is not None and monotonic_anchor is not None:
        elapsed_monotonic = max(float(monotonic) - float(monotonic_anchor), 0.0)
    jump = bool(floor) and forward > float(forward_limit)
    if jump and elapsed_monotonic is not None:
        jump = elapsed_monotonic < forward - CLOCK_DRIFT_TOLERANCE
    return {
        "high_water": floor,
        "behind": behind,
        "regressed": bool(floor) and behind > tolerance,
        "tolerance": float(tolerance),
        "forward": forward,
        "suspicious_forward": jump,
        "forward_limit": float(forward_limit),
        "monotonic_elapsed": elapsed_monotonic,
    }


def advance(high_water: float | None, now: float,
            *, forward_limit: float = FORWARD_JUMP_LIMIT,
            suspicious: bool | None = None) -> float:
    floor = float(high_water or 0.0)
    if suspicious is None:
        suspicious = bool(floor) and float(now) - floor > float(forward_limit)
    if suspicious:
        return floor
    return max(floor, float(now))
