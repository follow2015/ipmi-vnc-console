"""M2: shaping promises are all about ordering, timing and never losing a release."""
import pytest

from kvmhub.input_shaping import InputOverflow, InputShaper, InputShapingConfig
from kvmhub.insyde_messages import build_key_event, build_pointer_event


class Clock:
    def __init__(self, start=100.0):
        self.now = start

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


def cfg(**overrides):
    raw = {"min_hold_ms": 50, **overrides}
    return InputShapingConfig.parse(raw)


def shaper(**overrides):
    clock = Clock()
    return InputShaper(cfg(**overrides), clock=clock), clock



def test_an_undeclared_policy_leaves_the_gateway_byte_for_byte_unchanged():
    assert InputShapingConfig.parse(None) is None
    assert InputShapingConfig.parse({}) is None
    assert InputShapingConfig.parse("") is None
    assert InputShapingConfig.parse({"queue_limit": 256}).enabled is True
    assert InputShapingConfig.parse({"min_hold_ms": 50}).enabled is True


def test_a_declared_but_all_zero_policy_does_not_enable_shaping():
    config = InputShapingConfig.parse({"min_hold_ms": 0, "min_gap_ms": 0,
                                      "max_keys_per_s": 0, "release_on_close": False})
    assert config.enabled is False


@pytest.mark.parametrize("bad", [
    {"min_hold_ms": 501}, {"min_gap_ms": -1}, {"max_keys_per_s": 201},
    {"queue_limit": 15}, {"queue_limit": 1025}, {"min_hold_ms": "50"},
    {"min_hold_ms": True}, {"release_on_close": "yes"}, {"unknown": 1},
    "not json", "[1,2]", 7,
])
def test_a_malformed_policy_is_refused_not_clamped(bad):
    with pytest.raises(ValueError):
        InputShapingConfig.parse(bad)


def test_json_string_and_dict_are_equivalent():
    assert InputShapingConfig.parse('{"min_hold_ms": 20}') == \
        InputShapingConfig.parse({"min_hold_ms": 20})



def test_a_short_tap_waits_for_min_hold_without_losing_the_release():
    shp, clock = shaper(min_hold_ms=50, min_gap_ms=0)
    down, up = build_key_event(0x61, True), build_key_event(0x61, False)
    assert shp.feed(down) == [down]
    clock.advance(0.001)
    assert shp.feed(up) == []
    assert shp.pending == 1
    assert shp.next_due() == pytest.approx(100.05)
    clock.advance(0.048)
    assert shp.drain() == []
    clock.advance(0.002)
    assert shp.drain() == [up]


def test_a_long_tap_is_not_delayed():
    shp, clock = shaper(min_hold_ms=50, min_gap_ms=0)
    down, up = build_key_event(0x61, True), build_key_event(0x61, False)
    assert shp.feed(down) == [down]
    clock.advance(0.2)
    assert shp.feed(up) == [up]


def test_non_key_messages_never_overtake_a_waiting_release():
    shp, clock = shaper(min_hold_ms=50, min_gap_ms=0)
    down, up = build_key_event(0x61, True), build_key_event(0x61, False)
    pointer = build_pointer_event(10, 20, 0)
    shp.feed(down)
    clock.advance(0.001)
    assert shp.feed(up) == []
    assert shp.feed(pointer) == []
    clock.advance(0.05)
    assert shp.drain() == [up, pointer]


def test_an_unrecognised_message_is_forwarded_verbatim():
    shp, _ = shaper(min_hold_ms=50, min_gap_ms=0)
    raw = b"\x19"
    assert shp.feed(raw) == [raw]



@pytest.mark.parametrize("kwargs,minimum_gap", [
    ({"min_hold_ms": 0, "min_gap_ms": 20}, 0.020),
    ({"min_hold_ms": 0, "min_gap_ms": 0, "max_keys_per_s": 50}, 0.020),
    ({"min_hold_ms": 0, "min_gap_ms": 5, "max_keys_per_s": 50}, 0.020),
])
def test_a_burst_is_spaced_not_dropped(kwargs, minimum_gap):
    shp, clock = shaper(**kwargs)
    events = [build_key_event(0x61 + i, i % 2 == 0) for i in range(20)]
    sent = []
    for event in events:
        sent.extend(shp.feed(event))
        clock.advance(0.001)
    due = [item.message for item in shp._queue]
    assert len(sent) + len(due) == len(events)
    for step in range(1, 800):
        clock.advance(0.001)
        sent.extend(shp.drain())
        if not shp.pending:
            break
    assert sent == events
    assert shp.next_due() is None


def test_due_times_are_monotonic_under_a_burst():
    shp, clock = shaper(min_hold_ms=0, min_gap_ms=0, max_keys_per_s=100)
    for i in range(10):
        shp.feed(build_key_event(0x61 + i, True))
    times = [item.due_at for item in shp._queue]
    assert times == sorted(times)
    assert all(b - a >= 0.01 - 1e-9 for a, b in zip(times, times[1:]))


def test_overflow_ends_the_session_rather_than_losing_a_release():
    shp, _ = shaper(min_hold_ms=0, min_gap_ms=0, max_keys_per_s=10, queue_limit=16)
    for i in range(16):
        shp.feed(build_key_event(0x61 + i, True))
    assert shp.pending == 15
    shp.feed(build_key_event(0x70, True))
    assert shp.pending == 16
    with pytest.raises(InputOverflow):
        shp.feed(build_key_event(0x61, False))
    assert shp.pending == 16



def test_closing_releases_every_key_still_held():
    shp, _ = shaper(min_hold_ms=0, min_gap_ms=0)
    shp.feed(build_key_event(0x61, True))
    shp.feed(build_key_event(0xE1, True))
    shp.feed(build_key_event(0x61, False))
    assert shp.pressed_keys == frozenset({0xE1})
    assert shp.release_all() == [build_key_event(0xE1, False)]
    assert shp.release_all() == []


def test_release_on_close_can_be_switched_off():
    shp, _ = shaper(min_hold_ms=0, min_gap_ms=0, release_on_close=False)
    shp.feed(build_key_event(0x61, True))
    assert shp.release_all() == []
