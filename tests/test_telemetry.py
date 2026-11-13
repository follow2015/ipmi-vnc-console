"""M1 minimum credible subset: the end record and its bounded store."""
import json
import time

from kvmhub.telemetry import EVIDENCE_KEEP, EvidenceLog, SessionTelemetry, mask_sid, upstream_shape


class _Relay:

    def __init__(self, close_code=None):
        self.client_bytes = 120
        self.server_bytes = 4096
        self.client_key_events = 7
        self.upstream = type("Transport", (), {"upstream_close_code": close_code})()

    def as_dict(self):
        return {"client_bytes": self.client_bytes, "server_bytes": self.server_bytes,
                "client_message_types": {3: 4, 4: 2, 25: 1},
                "denied": {"kind": 6, "length": 12}, "peak_buffered_bytes": 8192}


def test_reconnects_are_counted_after_the_first_connection():
    telemetry = SessionTelemetry()
    assert telemetry.connections == 0 and telemetry.reconnects == 0
    telemetry.note_connection()
    assert (telemetry.connections, telemetry.reconnects) == (1, 0)
    telemetry.note_connection()
    telemetry.note_connection()
    assert (telemetry.connections, telemetry.reconnects) == (3, 2)


def test_evidence_carries_shape_and_is_json_serialisable():
    telemetry = SessionTelemetry()
    telemetry.note_connection(_Relay(close_code=1006))
    record = telemetry.evidence(sid="c" * 32, reason="upstream_error", cleanup="pending")

    assert record["sid"] == "c" * 32, "the store keeps the full id; masking happens on the way out"
    assert record["end_reason"] == "upstream_error" and record["cleanup"] == "pending"
    assert record["upstream_close_code"] == 1006
    assert (record["client_bytes"], record["server_bytes"], record["key_events"]) == (120, 4096, 7)
    assert record["client_message_types"] == {"3": 4, "4": 2, "25": 1}
    assert record["client_message_summary"] == "3:4,4:2,25:1"
    assert record["denied"] == {"kind": 6, "length": 12}
    assert record["peak_buffered_bytes"] == 8192
    assert record["connections"] == 1 and record["reconnects"] == 0
    assert json.loads(json.dumps(record))["end_reason"] == "upstream_error"


def test_evidence_never_copies_a_payload_even_when_the_relay_offers_one():
    class Talking(_Relay):
        def as_dict(self):
            return dict(super().as_dict(), payload=b"password", last_key="a")

    telemetry = SessionTelemetry()
    telemetry.note_connection(Talking())
    record = telemetry.evidence(sid="d" * 32, reason="client_closed", cleanup="confirmed")
    serialised = json.dumps(record)
    assert "password" not in serialised and "last_key" not in serialised
    assert set(record) == {"sid", "started_at", "ended_at", "duration_ms", "end_reason",
                           "cleanup", "connections", "reconnects", "upstream_close_code",
                           "client_bytes", "server_bytes", "key_events", "client_message_types",
                           "client_message_summary", "denied", "peak_buffered_bytes",
                           "recoveries", "recovery_attempts", "recovery_last_error",
                           "recovery_latency_ms", "dropped_input"}


def test_a_relay_that_cannot_describe_itself_still_produces_a_record():
    telemetry = SessionTelemetry()
    telemetry.note_connection(object())
    record = telemetry.evidence(sid="e" * 32, reason="lease_expired", cleanup="confirmed")
    assert record["client_bytes"] == 0 and record["client_message_types"] == {}
    assert record["client_message_summary"] == "" and record["denied"] is None
    assert record["upstream_close_code"] is None


def test_a_relay_whose_description_raises_still_produces_a_record():
    class Exploding(_Relay):
        def as_dict(self):
            raise RuntimeError("half-closed socket cannot describe itself")

    telemetry = SessionTelemetry()
    telemetry.note_connection(Exploding())
    record = telemetry.evidence(sid="a" * 32, reason="upstream_error", cleanup="pending")
    assert record["end_reason"] == "upstream_error"
    assert record["client_message_types"] == {}
    assert record["client_bytes"] == 120


def test_close_code_is_read_from_the_transport_behind_the_relay():
    relay = _Relay(close_code=1006)
    assert upstream_shape(relay)["upstream_close_code"] == 1006
    socket = type("Socket", (), {"close_code": 1001})()
    assert upstream_shape(socket)["upstream_close_code"] == 1001
    assert upstream_shape(None)["upstream_close_code"] is None


def test_a_live_snapshot_has_no_close_code_and_reports_uptime():
    telemetry = SessionTelemetry()
    telemetry.note_connection(_Relay(close_code=1006))
    snapshot = telemetry.live(ws_open=1, opening=0, lease_remaining=12.34, closing=False)
    assert snapshot["state"] == "live" and snapshot["ws_open"] == 1
    assert snapshot["lease_remaining_s"] == 12.3
    assert snapshot["uptime_s"] >= 0
    assert "upstream_close_code" not in snapshot, "a running upstream has not closed"
    assert snapshot["client_message_summary"] == "3:4,4:2,25:1"
    assert telemetry.live(ws_open=0, opening=1, lease_remaining=-1, closing=True)["state"] == "closing"


def test_the_store_keeps_the_newest_records_and_masks_the_id():
    log = EvidenceLog(keep=3)
    for index in range(5):
        log.add({"sid": f"{index:032d}", "end_reason": f"r{index}"})
    recent = log.recent(2)
    assert [item["end_reason"] for item in recent] == ["r4", "r3"], "newest first"
    assert recent[0]["sid"] == mask_sid("0" * 31 + "4")
    assert recent[0]["sid"].endswith("…") and len(recent[0]["sid"]) < 32
    assert len(log) == 3 and log.keep == 3
    assert log.recent(1, mask=False)[0]["sid"] == "0" * 31 + "4"


def test_the_default_store_is_bounded():
    log = EvidenceLog()
    for index in range(EVIDENCE_KEEP + 5):
        log.add({"sid": str(index), "end_reason": "x"})
    assert len(log) == EVIDENCE_KEEP


def test_duration_is_measured_from_the_session_start():
    telemetry = SessionTelemetry(started_at=time.time() - 2.5)
    record = telemetry.evidence(sid="f" * 32, reason="client_closed", cleanup="confirmed")
    assert 2400 <= record["duration_ms"] <= 3500
    assert record["started_at"] and record["ended_at"]



class _Recovering(_Relay):

    def __init__(self):
        super().__init__(close_code=1011)
        self.recovery = type("State", (), {"state": "relaying"})()

    def as_dict(self):
        return dict(super().as_dict(), recoveries=2, recovery_attempts=3,
                    recovery_last_error="upstream_closed", recovery_latency_ms=650,
                    dropped_input=4)


def test_a_rebuilt_session_records_how_often_it_was_rebuilt():
    telemetry = SessionTelemetry()
    telemetry.note_connection(_Recovering())
    record = telemetry.evidence(sid="1" * 32, reason="upstream_error", cleanup="pending")
    assert (record["recoveries"], record["recovery_attempts"]) == (2, 3)
    assert record["recovery_last_error"] == "upstream_closed"
    assert record["recovery_latency_ms"] == 650
    assert record["dropped_input"] == 4


def test_a_relay_cannot_smuggle_text_through_the_recovery_error_field():
    class Hostile(_Relay):
        def as_dict(self):
            return dict(super().as_dict(), recovery_last_error="admin@192.0.2.24 // secret")

    record = SessionTelemetry()
    record.note_connection(Hostile())
    assert record.evidence(sid="2" * 32, reason="upstream_error",
                           cleanup="pending")["recovery_last_error"] is None


def test_a_recovery_in_flight_is_visible_in_the_live_snapshot():
    relay = _Recovering()
    relay.recovery = type("State", (), {"state": "recovering"})()
    telemetry = SessionTelemetry()
    telemetry.note_connection(relay)
    assert telemetry.live(ws_open=1, opening=0, lease_remaining=5, closing=False)["state"] == "recovering"


def test_a_relay_without_recovery_reports_no_recovery_fields():
    telemetry = SessionTelemetry()
    telemetry.note_connection(_Relay())
    snapshot = telemetry.live(ws_open=1, opening=0, lease_remaining=5, closing=False)
    assert snapshot["state"] == "live"
    assert snapshot["recoveries"] == 0 and snapshot["recovery_last_error"] is None
