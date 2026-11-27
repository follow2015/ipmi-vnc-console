"""N2: the clock floor must survive an idle host without going blind."""
from __future__ import annotations

import time

import pytest

from kvmhub.platform import clockguard, services
from kvmhub.platform.db import init_schema, make_engine, session_factory, transaction
from kvmhub.platform.models import ClockWatermark


@pytest.fixture
def db(tmp_path):
    engine = make_engine(f"sqlite:///{tmp_path}/clock.db")
    init_schema(engine)
    factory = session_factory(engine)
    with transaction(factory) as session:
        yield session
    engine.dispose()


def _row(db):
    return db.get(ClockWatermark, clockguard.WATERMARK_ID)


def test_25_hours_of_idle_time_advances_the_floor():
    floor = 1_000_000.0
    after_idle = floor + 25 * 3600
    verdict = clockguard.evaluate(floor, after_idle,
                                  monotonic=1_000.0, monotonic_anchor=1_000.0 - 25 * 3600)
    assert verdict["suspicious_forward"] is False
    assert clockguard.advance(floor, after_idle, suspicious=False) == pytest.approx(after_idle)


def test_a_real_wall_jump_is_still_refused():
    floor = 1_000_000.0
    jumped = floor + 25 * 3600
    verdict = clockguard.evaluate(floor, jumped,
                                  monotonic=1_000.0, monotonic_anchor=990.0)
    assert verdict["suspicious_forward"] is True
    assert clockguard.advance(floor, jumped, suspicious=True) == pytest.approx(floor)


def test_observe_clock_records_the_monotonic_anchor_and_counts_jumps(db):
    services.observe_clock(db, now=1_000_000.0, monotonic=100.0)
    db.commit()
    assert _row(db).monotonic_anchor == pytest.approx(100.0)
    out = services.observe_clock(db, now=1_000_000.0 + 25 * 3600, monotonic=110.0)
    db.commit()
    assert out["suspicious_forward"] is True
    assert _row(db).high_water == pytest.approx(1_000_000.0)
    assert _row(db).suspicious_forward == 1
    out = services.observe_clock(db, now=1_000_120.0, monotonic=120.0)
    db.commit()
    assert out["regressed"] is False and out["suspicious_forward"] is False
    assert _row(db).high_water == pytest.approx(1_000_120.0)


def test_heartbeat_advances_the_floor_without_any_console_open(db):
    services.observe_clock(db, now=1_000_000.0, monotonic=1_000.0)
    db.commit()
    services.observe_clock(db, now=1_000_060.0, monotonic=1_060.0,
                           reason="heartbeat")
    db.commit()
    assert _row(db).high_water == pytest.approx(1_000_060.0)
    assert _row(db).suspicious_forward == 0


def test_clock_status_reports_the_counter_without_side_effects(db):
    services.observe_clock(db, now=1_000_000.0, monotonic=100.0)
    db.commit()
    services.observe_clock(db, now=1_000_000.0 + 25 * 3600, monotonic=110.0)
    db.commit()
    from kvmhub.platform.api import Platform
    p = Platform.__new__(Platform)
    p.factory = lambda: None
    p.factory = session_factory(db.get_bind())
    status = p.clock_status()
    assert status["suspicious_forward"] == 1
    assert status["high_water"] == pytest.approx(1_000_000.0)
