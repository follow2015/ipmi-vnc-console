"""The paste-to-KVM helper must emit frames the gateway already accepts."""
from __future__ import annotations

import json

from kvmhub import insyde_messages, passthrough, worker
from kvmhub.platform import text_input


def test_keymap_document_is_json_serialisable_and_matches_the_planner():
    doc = text_input.keymap_document()
    encoded = json.dumps(doc, ensure_ascii=False)
    assert json.loads(encoded) == doc
    for char, level in doc["reliability"].items():
        assert level == text_input.reliability(char), repr(char)
    assert doc["known_broken"]["|"].find("↔") >= 0
    assert doc["left_shift"] == 0xE1
    assert doc["max_chars"] == text_input._MAX_CHARS


def test_every_mappable_character_has_a_hid_usage():
    doc = text_input.keymap_document()
    for char, level in doc["reliability"].items():
        if level in ("verified", "unverified", "known_broken"):
            if char in doc["shifted"]:
                assert doc["shifted"][char] in doc["plain"]
            elif char.isupper():
                assert char.lower() in doc["plain"]
            else:
                assert char in doc["plain"], repr(char)


def test_injected_frames_are_accepted_by_the_gateway_parser():
    allowed, sizes = passthrough.client_message_profile("RFB 003.008")
    assert 4 in allowed and sizes[4] == 18
    assert 6 not in allowed
    plan = text_input.plan_text("init=/bin/bash\nA")
    frames = [frame for frame, _ in text_input.frame_stream(plan)]
    assert frames
    for frame in frames:
        assert len(frame) == 18
        parsed = insyde_messages.parse_key_event(frame)
        assert parsed is not None, "gateway would refuse this frame"
    assert sum(1 for f in frames if f[2] == 1) == sum(1 for f in frames if f[2] == 0)
    expected = insyde_messages.build_key_event(plan.strokes[0].usage, True)
    assert frames[0] == expected


def test_real_console_page_has_the_input_box_and_loads_the_keymap():
    assert 'id="paste-text"' in worker.REAL_CONSOLE_HTML
    assert 'id="paste-preview"' in worker.REAL_CONSOLE_HTML
    assert 'id="paste-send"' in worker.REAL_CONSOLE_HTML
    assert 'id="paste-stop"' in worker.REAL_CONSOLE_HTML
    assert "ClientCutText" not in worker.REAL_CONSOLE_HTML
    js = worker.REAL_CONSOLE_JS
    assert "/_platform/keymap" in js
    assert "pasteFrame" in js and "sock.send" in js
    assert "pasteAbort" in js
    assert js.count("new RFB(") == 1


def test_worker_serves_the_keymap_route_from_the_single_source():
    source = worker.__file__
    with open(source, encoding="utf-8") as handle:
        text = handle.read()
    assert 'request.path == "/_platform/keymap"' in text
    assert "web.json_response(keymap_document())" in text
    assert "from .platform.text_input import keymap_document" in text
