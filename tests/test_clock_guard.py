"""The clock floor: a rollback is refused, and never absorbed silently."""
from __future__ import annotations

import json
import time

import pytest

from kvmhub.platform import clockguard, connection, services
from kvmhub.platform.db import init_schema, make_engine, session_factory, transaction
from kvmhub.platform.models import Asset, AuditLog, ClockWatermark


@pytest.fixture
def db(tmp_path):
    engine = make_engine(f"sqlite:///{tmp_path}/clock.db")
    init_schema(engine)
    factory = session_factory(engine)
    with transaction(factory) as session:
        yield session
    engine.dispose()


def _row(db) -> ClockWatermark:
    return db.get(ClockWatermark, clockguard.WATERMARK_ID)


def test_forward_time_never_regresses():
    assert clockguard.evaluate(1_000.0, 1_001.0)["regressed"] is False


def test_small_step_back_is_tolerated_and_does_not_lower_the_floor():
    verdict = clockguard.evaluate(1_000.0, 930.0)
    assert verdict["regressed"] is False
    assert verdict["behind"] == pytest.approx(70.0)
    assert clockguard.advance(1_000.0, 930.0) == 1_000.0


def test_a_rollback_beyond_the_tolerance_is_a_regression():
    verdict = clockguard.evaluate(10_000.0, 10_000.0 - 301)
    assert verdict["regressed"] is True
    assert verdict["behind"] == pytest.approx(301.0)


def test_no_floor_yet_is_not_a_regression():
    assert clockguard.evaluate(0, 5.0)["regressed"] is False


def test_first_observation_creates_the_floor(db):
    out = services.observe_clock(db, now=1_700_000_000.0)
    db.commit()
    assert out["regressed"] is False
    assert _row(db).high_water == pytest.approx(1_700_000_000.0)


def test_time_moving_forward_advances_the_floor(db):
    services.observe_clock(db, now=1_000.0)
    db.commit()
    services.observe_clock(db, now=2_000.0)
    db.commit()
    assert _row(db).high_water == pytest.approx(2_000.0)


def test_a_step_back_inside_the_tolerance_leaves_the_floor_alone(db):
    services.observe_clock(db, now=10_000.0)
    db.commit()
    services.observe_clock(db, now=10_000.0 - 120)
    db.commit()
    assert _row(db).high_water == pytest.approx(10_000.0)
    assert _row(db).regressions == 0


def test_a_restored_clock_is_refused_audited_and_counted(db):
    services.observe_clock(db, now=10_000.0)
    db.commit()
    with pytest.raises(services.PlatformError) as exc:
        services.observe_clock(db, now=10_000.0 - 3_600, actor="admin",
                               reason="console_open")
    assert exc.value.code == "clock_regression"
    assert exc.value.status == 409
    assert _row(db).high_water == pytest.approx(10_000.0)
    assert _row(db).regressions == 1
    record = db.query(AuditLog).filter(AuditLog.action == "clock_regression").one()
    detail = json.loads(record.detail)
    assert detail["behind_seconds"] == pytest.approx(3_600.0)
    assert detail["reason"] == "console_open"


def test_one_rollback_refuses_attach_and_leaves_no_asset(db):
    services.observe_clock(db, now=time.time())
    db.commit()
    with pytest.raises(services.PlatformError) as exc:
        services.upsert_asset(db, name="rolled-back", address="192.0.2.9",
                              actor="test", now=time.time() - 7_200)
    assert exc.value.code == "clock_regression"
    db.rollback()
    assert db.query(Asset).count() == 0


def test_one_rollback_refuses_console_open_before_any_gate(db):
    services.observe_clock(db, now=time.time())
    db.commit()
    with pytest.raises(services.PlatformError) as exc:
        connection.assembly(db, asset_id="not-a-real-asset", user_id="u",
                            actor="test", now=time.time() - 7_200)
    assert exc.value.code == "clock_regression"
