"""Huawei iBMC private KVM gateway adapter tests (no real BMC)."""
from __future__ import annotations

import asyncio
import hashlib
import json
import random
import struct
from pathlib import Path

import pytest

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from kvmhub import huawei_kvm_protocol as P
from kvmhub.huawei_kvm_input import BrowserInputTranslator, packet_command
from kvmhub.huawei_kvm_jpeg import jpeg_header
from kvmhub.huawei_kvm_upstream import (KvmTicket, parse_jnlp, tls_der_matches_pin,
                                        valid_pin)
from kvmhub.adapters.huawei_ibmc_kvm_gateway import (
    HuaweiIbmcKvmGatewayAdapter, HuaweiKvmRfbSession, _rgb_to_pixels)
from kvmhub.common import HUAWEI_IBMC_KVM_GATEWAY_ID, Problem
from kvmhub.rfb_server import (build_raw_fbu_from_bgrx32,
                               build_raw_framebuffer_update_32bpp,
                               rgb24_to_bgrx32, to_rfb_bgr32)
from kvmhub.worker import make_adapter

ROOT = Path(__file__).resolve().parents[1]
CAPTURED_FRAMES = ROOT / "docs/implementation/evidence/huawei-ibmc-234-private-ws-frames-20261121.json"

INFO = dict(
    adapter=HUAWEI_IBMC_KVM_GATEWAY_ID,
    target="https://192.0.2.234",
    asset_id="a",
)

TEST_PIN = "ab" * 32


@pytest.fixture(autouse=True)
def _pin_env(monkeypatch):
    monkeypatch.setenv("KVMHUB_HUAWEI_VNC_PIN", TEST_PIN)
    monkeypatch.setenv("KVMHUB_BMC_ALLOWED_NETWORKS", "192.0.2.0/24")



def test_tls_der_matches_pin_positive_and_negative():
    der = b"\x30\x82\x03\x00fake-certificate-der"
    pin = hashlib.sha256(der).hexdigest()
    assert tls_der_matches_pin(der, pin) is True
    assert tls_der_matches_pin(der, "00" * 32) is False
    assert tls_der_matches_pin(None, pin) is False
    assert tls_der_matches_pin(b"", pin) is False
    assert tls_der_matches_pin(der, "not-a-pin") is False


def test_valid_pin_rules():
    assert valid_pin(TEST_PIN) is True
    assert valid_pin("AB" * 32) is False
    assert valid_pin("ab" * 31 + "zz") is False
    assert valid_pin("") is False
    assert valid_pin("ab" * 31) is False


def test_gateway_fails_closed_when_pin_unconfigured(monkeypatch):
    monkeypatch.delenv("KVMHUB_HUAWEI_VNC_PIN", raising=False)
    with pytest.raises(Problem) as exc:
        HuaweiIbmcKvmGatewayAdapter(dict(INFO))
    assert exc.value.code == "bmc_cert_pin_unconfigured"


def test_gateway_accepts_valid_pin_and_stores_it():
    adapter = HuaweiIbmcKvmGatewayAdapter(dict(INFO))
    assert adapter.tls_pin == TEST_PIN



def test_make_packet_layout():
    pkt = P.make_packet(0x6229EA4E, bytes((P.C_CMD_GET_SUITE, 0)))
    assert pkt[:3] == b"\xfe\xf6\x00"
    assert pkt[3] == 4
    assert pkt[4:8] == bytes.fromhex("62 29 ea 4e")
    assert pkt[8:10] == b"\x00\x00"
    assert pkt[10:] == bytes((0x42, 0))


def test_parse_messages_handles_partial_and_multiple():
    a = bytes.fromhex("fe f6 00 04 00 00 43 01")
    b = bytes.fromhex("fe f6 00 04 00 00 08 03")
    buf = bytearray(a + b[:7])
    frames, rest = P.parse_messages(buf)
    assert frames == [bytes((0x43, 0x01))]
    assert rest == b[:7]


def test_connect_packet_is_plaintext_five_bytes():
    pkt = P.connect_packet(1)
    assert pkt[10:] == bytes((0x06, 0, 0, 1, 1))
    assert P.C_CMD_CONNECT not in P.FORBIDDEN_COMMANDS
    for power in (0x20, 0x21, 0x22, 0x23, 0x25, 0x33):
        assert power in P.FORBIDDEN_COMMANDS


def test_keyboard_packet_matches_vendor_encryption():
    tag = 0x6229EA4E
    pkt = P.keyboard_packet(tag, 0x02, 0x04)
    assert pkt[:10] == P.SYNC + bytes((20,)) + struct.pack(">I", tag) + b"\x00\x00"
    assert pkt[10] == P.C_CMD_KEYBOARD and pkt[11] == 0
    key = bytearray((1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8))
    key[0:4] = struct.pack(">I", tag)
    decryptor = Cipher(algorithms.AES(bytes(key)), modes.CBC(b"\x00" * 16)).decryptor()
    plain = decryptor.update(pkt[12:28]) + decryptor.finalize()
    assert plain == bytes((0x02, 0, 0x04, 0, 0, 0, 0, 0)) + b"\x00" * 8


def test_translator_standard_key_and_modifiers():
    tr = BrowserInputTranslator(1, 720, 400)
    packets = tr.feed(struct.pack(">BBHI", 4, 1, 0, ord("a")))
    packets += tr.feed(struct.pack(">BBHI", 4, 0, 0, ord("a")))
    packets += tr.feed(struct.pack(">BBHI", 4, 1, 0, ord("A")))
    packets += tr.feed(struct.pack(">BBHI", 4, 0, 0, ord("A")))
    assert len(packets) == 4
    assert all(packet_command(p) == P.C_CMD_KEYBOARD for p in packets)
    assert all(p[11] == 0 for p in packets)
    key = bytearray((1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8))
    key[0:4] = struct.pack(">I", 1)
    def decoded(packet):
        dec = Cipher(algorithms.AES(bytes(key)), modes.CBC(b"\x00" * 16)).decryptor()
        plain = dec.update(packet[12:28]) + dec.finalize()
        return plain[0], plain[2]

    assert [decoded(p) for p in packets] == [(0, 4), (0, 0), (0x02, 4), (0, 0)]
    assert tr.stats.keys == 4

    ctrl_down = tr.feed(struct.pack(">BBHI", 4, 1, 0, 0xFFE3))[0]
    ctrl_key = tr.feed(struct.pack(">BBHI", 4, 1, 0, ord("c")))[0]
    ctrl_up = tr.feed(struct.pack(">BBHI", 4, 0, 0, 0xFFE3))[0]
    assert decoded(ctrl_down) == (0x01, 0)
    assert decoded(ctrl_key) == (0x01, 6)
    assert decoded(ctrl_up) == (0, 0)
    assert tr.modifiers == 0


def test_translator_pointer_maps_rfb_buttons_and_coordinates():
    tr = BrowserInputTranslator(1, 720, 400)
    packet = tr.feed(struct.pack(">BBHH", 5, 0x01, 360, 200))[0]
    assert packet_command(packet) == P.C_CMD_MOUSE
    assert packet[11] == 0
    assert packet[12] == 0x01
    assert int.from_bytes(packet[13:15], "big") == 1500
    assert int.from_bytes(packet[15:17], "big") == 1500
    pkt2 = tr.feed(struct.pack(">BBHH", 5, 0x06, 719, 399))[0]
    assert pkt2[11] == 0 and pkt2[12] == 0x06
    assert int.from_bytes(pkt2[13:15], "big") == 2995
    assert int.from_bytes(pkt2[15:17], "big") == 2992


def test_translator_ignores_rfb_control_messages():
    tr = BrowserInputTranslator(1, 16, 16)
    control = bytes(20) + struct.pack(">BBH", 2, 0, 0) + struct.pack(">BBHHHH", 3, 0, 0, 0, 16, 16)
    assert tr.feed(control) == []
    assert tr.stats.ignored >= 3


def test_parse_suite_picks_hmac3():
    payload = bytes((0x43, 0, 2,
                     1, 0, 0, 0x13, 0x88,
                     3, 0, 0, 0x27, 0x10))
    assert P.parse_suite(payload) == (3, 10000)


def test_jnlp_ticket_parsing():
    xml = '''<jnlp><applet-desc>
      <param name="verifyValue" value="2142998960"/>
      <param name="decrykey" value="ab"*32/>
      <param name="compress" value="0"/>
      <param name="port" value="2198"/>
      <param name="IPA" value="192.0.2.234"/>
      <param name="verifyValueExt" value="cafe"/>
    </applet-desc></jnlp>'''
    t = parse_jnlp(xml, "192.0.2.234")
    assert t.verify_id == 2142998960 and t.port == 2198 and t.compress == 0



def test_decode_real_captured_frame_shows_nonblack_pixels():
    raw = json.loads(CAPTURED_FRAMES.read_text(encoding="utf-8"))
    buf = bytearray()
    payloads = []
    for msg in raw:
        buf.extend(bytes(msg))
        frames, buf = P.parse_messages(buf)
        payloads.extend(frames)
    asm = P.ImageAssembler()
    complete = None
    for p in payloads:
        if p and p[0] == P.H_CMD_IMAGE and len(p) >= 19:
            done = asm.feed(p)
            if done is not None:
                complete = done
    assert complete is not None
    complete, w, h, q = complete
    bgr = P.decode_blocks(complete, w, h, q, jpeg_header(q))
    assert len(bgr) == w * h * 3
    pixels = _rgb_to_pixels(bgr)
    lit = sum(1 for px in pixels[::64] if (px & 0xFFFFFF) > 0x303030)
    assert lit > 0, "decoded frame must contain non-black text pixels"


def _captured_complete_frames():
    raw = json.loads(CAPTURED_FRAMES.read_text(encoding="utf-8"))
    buf = bytearray()
    payloads = []
    for msg in raw:
        buf.extend(bytes(msg))
        frames, buf = P.parse_messages(buf)
        payloads.extend(frames)
    asm = P.ImageAssembler()
    done = []
    for p in payloads:
        if p and p[0] == P.H_CMD_IMAGE and len(p) >= 19:
            result = asm.feed(p)
            if result is not None:
                done.append(result)
    return done


def test_incremental_decode_keeps_canvas_across_frames():
    frames = _captured_complete_frames()
    assert len(frames) > 10
    dec = P.HuaweiFrameDecoder()
    lit_counts = []
    for stream, w, h, q in frames[:20]:
        bgr = dec.decode(stream, w, h, q, jpeg_header(q))
        lit = sum(1 for i in range(0, len(bgr), 3 * 64)
                  if bgr[i] + bgr[i + 1] + bgr[i + 2] > 60)
        lit_counts.append(lit)
    assert min(lit_counts) > 5, f"frame collapsed to black: {lit_counts}"
    assert dec.frames == 20
    assert dec.blocks, "persistent per-block cache must be populated"


def test_persistent_decode_recovers_left_edge_text():
    frames = _captured_complete_frames()
    dec = P.HuaweiFrameDecoder()
    bgr = None
    for stream, w, h, q in frames:
        bgr = dec.decode(stream, w, h, q, jpeg_header(q))
    assert bgr is not None
    first_x = None
    for x in range(0, 720):
        if any(bgr[(y * 720 + x) * 3] + bgr[(y * 720 + x) * 3 + 1]
               + bgr[(y * 720 + x) * 3 + 2] > 60 for y in range(0, 40)):
            first_x = x
            break
    assert first_x is not None and first_x < 32, f"left edge missing, first_x={first_x}"


def test_decode_failure_is_counted_not_silently_swallowed(monkeypatch):
    frames = _captured_complete_frames()
    dec2 = P.HuaweiFrameDecoder()
    for stream, w, h, q in frames[:5]:
        dec2.decode(stream, w, h, q, jpeg_header(q))
    assert dec2.decoded_blocks > 0
    assert dec2.failed_blocks == 0

    monkeypatch.setattr(P, "_decode_jpeg_block", lambda blob: None)
    dec = P.HuaweiFrameDecoder()
    block = bytes([0x40, 0x00, 0x04]) + b"\xde\xad\xbe\xef"
    out = dec.decode(block, 720, 400, 4, jpeg_header(4))
    assert len(out) == 720 * 400 * 3
    assert dec.failed_blocks == 1
    assert dec.decoded_blocks == 0


def test_vectorized_fbu_is_byte_identical_to_per_pixel_path():
    frames = _captured_complete_frames()
    dec = P.HuaweiFrameDecoder()
    bgr = None
    for stream, w, h, q in frames[:20]:
        bgr = dec.decode(stream, w, h, q, jpeg_header(q))
    assert bgr is not None

    legacy_bytes = to_rfb_bgr32(_rgb_to_pixels(bgr))
    fast_bytes = rgb24_to_bgrx32(bgr, w, h)
    assert fast_bytes == legacy_bytes

    legacy_fbu = build_raw_framebuffer_update_32bpp(_rgb_to_pixels(bgr), w, h)
    fast_fbu = build_raw_fbu_from_bgrx32(fast_bytes, w, h)
    assert fast_fbu == legacy_fbu
    assert len(fast_fbu) == 25


@pytest.mark.parametrize("w,h", [
    (1, 1),
    (64, 1),
    (63, 17),
    (65, 33),
    (16, 16),
    (17, 5),
    (128, 50),
])
def test_vectorized_fbu_equivalence_across_geometries(w, h):
    rng = random.Random(w * 1000 + h)
    rgb = bytes(rng.randrange(256) for _ in range(w * h * 3))

    legacy_bytes = to_rfb_bgr32(_rgb_to_pixels(rgb))
    fast_bytes = rgb24_to_bgrx32(rgb, w, h)
    assert fast_bytes == legacy_bytes

    legacy_fbu = build_raw_framebuffer_update_32bpp(_rgb_to_pixels(rgb), w, h)
    fast_fbu = build_raw_fbu_from_bgrx32(fast_bytes, w, h)
    assert fast_fbu == legacy_fbu
    assert len(fast_fbu) == (h + 15) // 16


@pytest.mark.parametrize("fn,args", [
    (rgb24_to_bgrx32, (b"\x00" * 12, 3, 2)),
    (build_raw_fbu_from_bgrx32, (b"\x00" * 12, 3, 2)),
])
def test_vectorized_fbu_rejects_size_mismatch(fn, args):
    with pytest.raises(ValueError):
        fn(*args)



def test_factory_routes_gateway(monkeypatch):
    monkeypatch.setenv("KVMHUB_BMC_ALLOWED_NETWORKS", "192.0.2.0/24")
    a = make_adapter(dict(INFO))
    assert isinstance(a, HuaweiIbmcKvmGatewayAdapter)


def test_adapter_rejects_unsafe_target():
    with pytest.raises(Problem):
        HuaweiIbmcKvmGatewayAdapter(dict(INFO, target="https://u:p@192.0.2.234/x"))


def test_adapter_enforces_controlled_network():
    nets = (__import__("ipaddress").ip_network("192.0.2.0/24"),)
    a = HuaweiIbmcKvmGatewayAdapter(dict(INFO), networks=nets)
    assert a.host == "192.0.2.234"
    with pytest.raises(Problem):
        HuaweiIbmcKvmGatewayAdapter(dict(INFO, target="https://8.8.8.8"), networks=nets)



class _FakeUpstream:
    def __init__(self):
        self.sent = []
        self.connected = True
        self.tag_id = 1
        self.ticket = KvmTicket(1, "00" * 32, 2198, 0, "", "192.0.2.234")
        self.framebuffer_width = 16
        self.framebuffer_height = 16

    async def frames(self):
        yield b"", 16, 16, 1
        raise StopAsyncIteration

    async def send_input(self, data):
        self.sent.append(data)

    async def close(self):
        self.connected = False
        return True


def test_session_handshake_then_relays_fbu():
    up = _FakeUpstream()

    async def run():
        s = HuaweiKvmRfbSession(up, 16, 16)
        await s.start()
        greeting = await asyncio.wait_for(anext(s), 2)
        assert bytes(greeting.data).startswith(b"RFB 003.008")
        await s.send_bytes(b"RFB 003.008\n")
        await s.send_bytes(bytes((1,)))
        await s.send_bytes(bytes((1,)))
        assert s.handshake.completed
        for _ in range(4):
            try:
                await asyncio.wait_for(anext(s), 2)
            except StopAsyncIteration:
                break
        await asyncio.sleep(0.2)
        assert s.frames >= 1
        await s.send_bytes(struct.pack(">BBHI", 4, 1, 0, ord("a")))
        await s.send_bytes(struct.pack(">BBHH", 5, 0x01, 8, 8))
        assert len(up.sent) == 2
        assert packet_command(up.sent[0]) == P.C_CMD_KEYBOARD
        assert packet_command(up.sent[1]) == P.C_CMD_MOUSE
        assert s.input.stats.forwarded == 2
        await s.close()

    asyncio.run(run())
