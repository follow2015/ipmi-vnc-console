"""M2.0: the layout is a measurement, so round-trips and refusals are the test."""
import pytest

from kvmhub.insyde_messages import (
    KEY_EVENT_SIZE, MAX_UINT16, MAX_UINT32, POINTER_EVENT_SIZE,
    InsydeKeyEvent, InsydePointerEvent, build_key_event, build_pointer_event,
    is_key_release, parse_key_event, parse_pointer_event,
)

CAPTURED_LEFTSHIFT = bytes.fromhex("04 00 01 00 00 00 00 00 e1") + b"\x00" * 9


@pytest.mark.parametrize("key,down", [
    (0, False), (1, True), (0xE1, True), (0xFFE1, False), (MAX_UINT32, True),
    (0x1234ABCD, False),
])
def test_key_event_round_trips(key, down):
    raw = build_key_event(key, down)
    assert len(raw) == KEY_EVENT_SIZE
    assert parse_key_event(raw) == InsydeKeyEvent(down=down, key=key)
    assert parse_key_event(raw).to_bytes() == raw


@pytest.mark.parametrize("x,y,mask", [
    (0, 0, 0), (100, 200, 1), (MAX_UINT16, MAX_UINT16, 255), (1920, 1080, 4),
])
def test_pointer_event_round_trips(x, y, mask):
    raw = build_pointer_event(x, y, mask)
    assert len(raw) == POINTER_EVENT_SIZE
    assert parse_pointer_event(raw) == InsydePointerEvent(mask=mask, x=x, y=y)
    assert parse_pointer_event(raw).to_bytes() == raw


def test_the_captured_leftshift_press_decodes_as_a_big_endian_hid_code():
    event = parse_key_event(CAPTURED_LEFTSHIFT)
    assert event == InsydeKeyEvent(down=True, key=0xE1)
    assert is_key_release(CAPTURED_LEFTSHIFT) is False


def test_the_captured_release_differs_only_in_the_down_byte():
    release = CAPTURED_LEFTSHIFT[:2] + b"\x00" + CAPTURED_LEFTSHIFT[3:]
    assert is_key_release(release) is True
    assert parse_key_event(release).key == 0xE1


@pytest.mark.parametrize("raw", [
    b"", b"\x04" * 8, b"\x04" * 19, None, "not bytes", 17,
    b"\x05" + b"\x00" * 17,
    CAPTURED_LEFTSHIFT[:1] + b"\x01" + CAPTURED_LEFTSHIFT[2:],
    CAPTURED_LEFTSHIFT[:3] + b"\x01\x00" + CAPTURED_LEFTSHIFT[5:],
    CAPTURED_LEFTSHIFT[:9] + b"\x01" + b"\x00" * 8,
    CAPTURED_LEFTSHIFT[:2] + b"\x02" + CAPTURED_LEFTSHIFT[3:],
])
def test_a_key_message_with_unknown_shape_is_not_parsed(raw):
    assert parse_key_event(raw) is None
    if isinstance(raw, (bytes, bytearray)):
        assert is_key_release(raw) is False


@pytest.mark.parametrize("raw", [
    b"", b"\x05" * 6, b"\x05" * 19, None,
    b"\x04" + b"\x00" * 17,
    b"\x05\x01\x00\x00\x64\x00\xc8" + b"\x00" * 11,
    b"\x05\x00\x00\x00\x64\x00\xc8\x01" + b"\x00" * 10,
])
def test_a_pointer_message_with_unknown_shape_is_not_parsed(raw):
    assert parse_pointer_event(raw) is None


def test_bytearray_and_memoryview_are_accepted_but_strings_are_not():
    assert parse_key_event(bytearray(CAPTURED_LEFTSHIFT)) is not None
    assert parse_key_event(memoryview(CAPTURED_LEFTSHIFT)) is not None
    assert parse_key_event(CAPTURED_LEFTSHIFT.decode("latin1")) is None


@pytest.mark.parametrize("key,down", [
    (-1, True), (MAX_UINT32 + 1, True), (True, True), ("a", True),
    (1, 1), (1, "yes"),
])
def test_build_key_event_refuses_invalid_arguments(key, down):
    with pytest.raises(ValueError):
        build_key_event(key, down)


@pytest.mark.parametrize("x,y,mask", [
    (-1, 0, 0), (MAX_UINT16 + 1, 0, 0), (0, 0, 256), (0, 0, True), (0, 0, "1"),
])
def test_build_pointer_event_refuses_invalid_arguments(x, y, mask):
    with pytest.raises(ValueError):
        build_pointer_event(x, y, mask)


def test_standard_rfb_shapes_are_not_mistaken_for_insyde_events():
    standard_key = b"\x04\x01\x00\x00\x00\x00\x00\x41"
    standard_pointer = b"\x05\x00\x00\x64\x00\xc8"
    assert parse_key_event(standard_key) is None
    assert parse_pointer_event(standard_pointer) is None
    assert is_key_release(standard_key) is False
