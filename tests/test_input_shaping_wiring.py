"""M2 wiring: capability -> exchange -> adapter -> session, and the ending it causes."""
import asyncio
import json
from types import SimpleNamespace

import pytest

from kvmhub.adapters.passthrough import PassthroughAdapter
from kvmhub.common import PASSTHROUGH_ADAPTER_ID, Problem
from kvmhub.insyde_messages import build_key_event, build_pointer_event
from kvmhub.input_shaping import InputShapingConfig
from kvmhub.passthrough import (
    ClientMessageFramer, RfbPassthroughSession, client_message_profile,
)
from kvmhub.store import Store
from kvmhub.worker import upstream_end_reason

TARGET = "https://192.0.2.11"
FINGERPRINT = "ab" * 32


def store(tmp_path, *, targets=(TARGET,)):
    path = tmp_path / "shaping.sqlite"
    return Store(path, b"k" * 32, clock=lambda: 2_000_000_000.0,
                 passthrough_targets=targets)


def seeded(tmp_path, **overrides):
    db = store(tmp_path)
    db.seed_passthrough(target=TARGET, fingerprint=FINGERPRINT, username="u", password="p",
                        approver="tester")
    if overrides:
        db.db.execute("UPDATE adapter_capability SET input_shaping=? WHERE id=?",
                      (json.dumps(overrides), "supermicro-x10-passthrough"))
    return db


def exchange_body(db):
    row = db.allocate("real-1", "local-admin", "w1", "i1", "trace")
    claims = {"sid": row["id"], "sub": row["user_id"], "aid": row["asset_id"],
              "wid": row["worker_id"], "iid": row["instance_id"], "jti": row["jti"]}
    return db.exchange(claims, "trace")


class Sink:

    def __init__(self):
        self.sent: list[bytes] = []
        self.upstream_close_code = None

    async def send_raw(self, data):
        self.sent.append(bytes(data))


def running_session(cfg, sink=None):
    sink = sink or Sink()
    allowed, sizes = client_message_profile("RFB 055.008")
    session = RfbPassthroughSession(
        sink, SimpleNamespace(completed=True, shared=False),
        allowed_client_messages=allowed, message_sizes=sizes, input_shaping=cfg)
    return session, sink



def test_an_undeclared_capability_sends_no_policy_at_all(tmp_path):
    db = seeded(tmp_path)
    try:
        body = exchange_body(db)
        assert body["input_shaping"] is None
    finally:
        db.close()


def test_a_declared_policy_is_validated_at_registration_and_sent_verbatim(tmp_path):
    db = seeded(tmp_path, min_hold_ms=50, min_gap_ms=10, max_keys_per_s=50)
    try:
        body = exchange_body(db)
        assert body["input_shaping"] == {"min_hold_ms": 50, "min_gap_ms": 10,
                                         "max_keys_per_s": 50, "queue_limit": 256,
                                         "release_on_close": True}
    finally:
        db.close()


@pytest.mark.parametrize("bad", [
    {"min_hold_ms": 900}, {"max_keys_per_s": "fast"}, {"queue_limit": 1},
    {"unknown": 1},
])
def test_a_malformed_policy_is_refused_before_it_can_reach_a_console(tmp_path, bad):
    db = store(tmp_path)
    try:
        with pytest.raises(Problem) as caught:
            db.register_capability({"id": "x10", "vendor": "v", "model": "m",
                                    "adapter": PASSTHROUGH_ADAPTER_ID,
                                    "input_shaping": bad}, "albert")
        assert caught.value.code == "capability_incomplete"
    finally:
        db.close()



def adapter_info(**overrides):
    base = {"adapter": PASSTHROUGH_ADAPTER_ID, "target": TARGET, "fingerprint": FINGERPRINT}
    base.update(overrides)
    return base


def test_adapter_parses_the_policy_from_the_exchange():
    adapter = PassthroughAdapter(adapter_info(input_shaping={"min_hold_ms": 40}))
    assert adapter.input_shaping.min_hold_ms == 40
    assert adapter.input_shaping.enabled is True


def test_adapter_without_a_policy_keeps_the_relay_unchanged():
    adapter = PassthroughAdapter(adapter_info())
    assert adapter.input_shaping is None


def test_adapter_refuses_a_policy_the_store_should_have_rejected():
    with pytest.raises(Problem) as caught:
        PassthroughAdapter(adapter_info(input_shaping={"min_hold_ms": 10_000}))
    assert caught.value.code == "invalid_target_policy"



def test_a_declared_policy_installs_a_shaper_and_a_missing_one_does_not():
    session, _ = running_session(InputShapingConfig.parse({"min_hold_ms": 50}))
    assert session._shaper is not None
    plain, _ = running_session(None)
    assert plain._shaper is None


def test_a_short_tap_reaches_the_upstream_late_but_complete():
    async def scenario():
        session, sink = running_session(InputShapingConfig.parse({"min_hold_ms": 60}))
        down, up = build_key_event(0x61, True), build_key_event(0x61, False)
        await session.send_bytes(down)
        await session.send_bytes(up)
        assert sink.sent == [down]
        await asyncio.sleep(0.09)
        await session.close()
        assert sink.sent == [down, up]

    asyncio.run(scenario())


def test_closing_the_browser_releases_keys_still_held():
    async def scenario():
        session, sink = running_session(InputShapingConfig.parse({"min_hold_ms": 0,
                                                                  "release_on_close": True}))
        await session.send_bytes(build_key_event(0xE1, True))
        await session.close()
        assert sink.sent[-1] == build_key_event(0xE1, False)

    asyncio.run(scenario())


def test_closing_before_a_delayed_release_still_releases_the_upstream_key():
    async def scenario():
        session, sink = running_session(InputShapingConfig.parse({"min_hold_ms": 500}))
        down, up = build_key_event(0xE1, True), build_key_event(0xE1, False)
        await session.send_bytes(down + up)
        assert sink.sent == [down]
        await session.close()
        assert sink.sent == [down, up], "closing must not cancel the only key-up"
        await asyncio.sleep(0.01)
        assert sink.sent == [down, up]

    asyncio.run(scenario())


def test_an_overflowed_queue_ends_the_session_with_its_own_reason():
    async def scenario():
        session, _ = running_session(InputShapingConfig.parse(
            {"min_hold_ms": 0, "max_keys_per_s": 5, "queue_limit": 16}))
        for key in range(0x40, 0x60):
            await session.send_bytes(build_key_event(key, True))
            if session.closed:
                break
        assert session.closed
        assert session.error == "input_overflow"
        assert upstream_end_reason(session) == "input_overflow"

    asyncio.run(scenario())


def test_a_pointer_message_waits_behind_a_held_release():
    async def scenario():
        session, sink = running_session(InputShapingConfig.parse({"min_hold_ms": 60}))
        down, up = build_key_event(0x61, True), build_key_event(0x61, False)
        pointer = build_pointer_event(10, 20, 0)
        await session.send_bytes(down)
        await session.send_bytes(up)
        await session.send_bytes(pointer)
        assert sink.sent == [down]
        await asyncio.sleep(0.09)
        await session.close()
        assert sink.sent[:3] == [down, up, pointer]

    asyncio.run(scenario())



def test_without_a_policy_the_framer_output_is_byte_for_byte_the_old_one():
    data = (b"\x03\x00" + b"\x00" * 8 + b"\x07\x07\x80"
            + build_key_event(0x61, True) + build_pointer_event(1, 2, 3))
    allowed, sizes = client_message_profile("RFB 055.008")
    plain = ClientMessageFramer(allowed, sizes=sizes)
    assert plain.feed(data) == b"".join(
        ClientMessageFramer(allowed, sizes=sizes).feed_messages(data))


def test_a_coalesced_frame_is_shaped_message_by_message_not_as_one_blob():
    async def scenario():
        session, sink = running_session(InputShapingConfig.parse({"min_hold_ms": 60}))
        down, up = build_key_event(0x61, True), build_key_event(0x61, False)
        await session.send_bytes(down + up)
        assert sink.sent == [down]
        await asyncio.sleep(0.09)
        await session.close()
        assert sink.sent == [down, up]

    asyncio.run(scenario())


def test_the_experiment_fixture_can_declare_shaping_when_it_seeds(tmp_path):
    db = store(tmp_path)
    db.seed_passthrough(target=TARGET, fingerprint=FINGERPRINT, username="u", password="p",
                        approver="tester",
                        input_shaping={"min_hold_ms": 30, "max_keys_per_s": 50})
    body = exchange_body(db)
    assert body["input_shaping"] == {"min_hold_ms": 30, "min_gap_ms": 0,
                                     "max_keys_per_s": 50, "queue_limit": 256,
                                     "release_on_close": True}


def test_seeding_an_illegal_policy_fails_loudly(tmp_path):
    db = store(tmp_path)
    with pytest.raises(Problem) as caught:
        db.seed_passthrough(target=TARGET, fingerprint=FINGERPRINT, username="u", password="p",
                            approver="tester", input_shaping={"min_hold_ms": -1})
    assert caught.value.code == "capability_incomplete"



def test_a_declared_logout_path_reaches_the_exchange(tmp_path):
    db = seeded(tmp_path)
    db.db.execute("UPDATE adapter_capability SET logout_path=? WHERE id=?",
                  ("/cgi/does-not-exist.cgi", "supermicro-x10-passthrough"))
    try:
        assert exchange_body(db)["logout_path"] == "/cgi/does-not-exist.cgi"
    finally:
        db.close()


def test_an_undeclared_logout_path_stays_none_in_the_exchange(tmp_path):
    db = seeded(tmp_path)
    try:
        assert exchange_body(db)["logout_path"] is None
    finally:
        db.close()


def test_a_logout_path_with_dot_segments_is_refused_at_registration(tmp_path):
    db = store(tmp_path)
    try:
        with pytest.raises(Problem) as caught:
            db.seed_passthrough(target=TARGET, fingerprint=FINGERPRINT, username="u",
                                password="p", approver="tester",
                                logout_path="/cgi/../../etc/passwd")
        assert caught.value.code == "capability_incomplete"
    finally:
        db.close()



def test_a_declared_logout_path_reaches_the_exchange(tmp_path):
    db = seeded(tmp_path)
    db.db.execute("UPDATE adapter_capability SET logout_path=? WHERE id=?",
                  ("/cgi/does-not-exist.cgi", "supermicro-x10-passthrough"))
    try:
        assert exchange_body(db)["logout_path"] == "/cgi/does-not-exist.cgi"
    finally:
        db.close()


def test_an_undeclared_logout_path_stays_none_in_the_exchange(tmp_path):
    db = seeded(tmp_path)
    try:
        assert exchange_body(db)["logout_path"] is None
    finally:
        db.close()


def test_a_logout_path_with_dot_segments_is_refused_at_registration(tmp_path):
    db = store(tmp_path)
    try:
        with pytest.raises(Problem) as caught:
            db.seed_passthrough(target=TARGET, fingerprint=FINGERPRINT, username="u",
                                password="p", approver="tester",
                                logout_path="/cgi/../../etc/passwd")
        assert caught.value.code == "capability_incomplete"
    finally:
        db.close()
