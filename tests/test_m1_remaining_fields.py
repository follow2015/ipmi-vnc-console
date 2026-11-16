"""M1's last two end-evidence fields: exception class and time since last frame."""
import asyncio
import json
from types import SimpleNamespace

import pytest

from kvmhub.common import Problem
from kvmhub.passthrough import RfbPassthroughSession
from kvmhub.telemetry import SessionTelemetry, audit_evidence, upstream_shape


class _Relay:

    def __init__(self, *, exception_type=None, last_rx=None, now=100.0, close_code=1006):
        self._exception_type = exception_type
        self.upstream = SimpleNamespace(
            upstream_close_code=close_code,
            stats=SimpleNamespace(last_event_at=last_rx),
            clock=lambda: now)
        self.client_bytes = 10
        self.server_bytes = 20
        self.client_key_events = 1

    def as_dict(self):
        return {"client_bytes": 10, "server_bytes": 20,
                "exception_type": self._exception_type,
                "client_message_types": {"4": 1}, "peak_buffered_bytes": 64}


class _FailingUpstream:
    def __init__(self, exc):
        self.exc = exc
        self.upstream_close_code = None

    async def relay(self, on_bytes):
        raise self.exc


def _handshake():
    return SimpleNamespace(completed=False, shared=False)


def _session(exc):
    return RfbPassthroughSession(_FailingUpstream(exc), _handshake())



def test_audit_evidence_keeps_a_class_name_and_a_bounded_elapsed_time():
    out = audit_evidence({"exception_type": "ClientConnectorError",
                          "since_last_rx_s": 12.345, "duration_ms": 5})
    assert out["exception_type"] == "ClientConnectorError"
    assert out["since_last_rx_s"] == 12.3
    assert out["duration_ms"] == 5


@pytest.mark.parametrize("bad", [True, -1, "12.3", None, 86401, float("nan"), float("inf")])
def test_elapsed_time_rejects_everything_but_a_bounded_number(bad):
    assert "since_last_rx_s" not in audit_evidence({"since_last_rx_s": bad})


@pytest.mark.parametrize("bad", [
    True, 12, None, "", "has space", "a.b", "with/slash", "too-long" * 12,
    "Zx9Qv;DROP TABLE audit", "<script>",
])
def test_exception_field_accepts_only_a_plain_class_name(bad):
    assert "exception_type" not in audit_evidence({"exception_type": bad})


def test_audit_row_stays_bounded_with_the_new_fields():
    record = {"exception_type": "A" * 62, "since_last_rx_s": 1.0,
              "client_message_types": {str(k): k for k in range(256)}}
    out = audit_evidence(record)
    assert len(json.dumps(out, separators=(",", ":"))) <= 1024
    assert "exception_type" not in out



def test_shape_takes_the_exception_class_from_the_relay():
    shape = upstream_shape(_Relay(exception_type="ConnectionResetError"))
    assert shape["exception_type"] == "ConnectionResetError"


def test_shape_refuses_a_free_text_exception_description():
    assert upstream_shape(_Relay(exception_type="device says Zx9Qv"))["exception_type"] is None


def test_shape_computes_seconds_since_the_last_upstream_frame():
    shape = upstream_shape(_Relay(last_rx=91.5, now=100.0))
    assert shape["since_last_rx_s"] == 8.5


def test_no_received_frame_means_no_elapsed_time_instead_of_a_made_up_number():
    assert upstream_shape(_Relay(last_rx=0, now=100.0))["since_last_rx_s"] is None
    assert upstream_shape(_Relay(last_rx=None, now=100.0))["since_last_rx_s"] is None


def test_a_synthetic_relay_without_a_clock_does_not_invent_a_measurement():
    class Bare:
        def as_dict(self):
            return {}

    shape = upstream_shape(Bare())
    assert shape["since_last_rx_s"] is None
    assert shape["exception_type"] is None


def test_evidence_record_carries_both_fields_and_serialises():
    telemetry = SessionTelemetry()
    telemetry.note_connection(_Relay(exception_type="OSError", last_rx=90.0, now=100.0))
    record = telemetry.evidence(sid="s" * 32, reason="upstream_error", cleanup="pending")
    assert record["exception_type"] == "OSError"
    assert record["since_last_rx_s"] == 10.0
    assert json.loads(json.dumps(record))["exception_type"] == "OSError"



class SentinelError(Exception):
    pass


def test_relay_records_only_the_exception_class_not_its_message():
    session = _session(SentinelError("Zx9Qv device-10 host said no"))
    code = asyncio.run(session._relay_once())
    assert code == "SentinelError"
    shape = session.as_dict()
    assert shape["exception_type"] == "SentinelError"
    assert "Zx9Qv" not in json.dumps(shape)
    assert "device-10" not in json.dumps(shape)


def test_a_problem_is_recorded_with_its_class_not_its_payload():
    session = _session(Problem("upstream_unresponsive", 502))
    assert asyncio.run(session._relay_once()) == "upstream_unresponsive"
    assert session.as_dict()["exception_type"] == "Problem"


def test_an_orderly_upstream_close_has_no_exception_class():
    class _ClosingUpstream:
        upstream_close_code = 1000

        async def relay(self, on_bytes):
            return None

    session = RfbPassthroughSession(_ClosingUpstream(), _handshake())
    assert asyncio.run(session._relay_once()) == "upstream_closed"
    assert session.as_dict()["exception_type"] is None
