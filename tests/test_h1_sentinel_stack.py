"""H1: a whole relayed session must never leak what was typed."""
import asyncio
import json
import logging

import pytest

from kvmhub.ast2100_protocol import client_protocol_version, framebuffer_update_request
from kvmhub.insyde_messages import build_key_event
from kvmhub.passthrough import (
    INSYDE_CLIENT_MESSAGES, INSYDE_MESSAGE_SIZES, BrowserHandshake, RfbPassthroughSession,
)
from kvmhub.recovery import RecoveryPolicy
from kvmhub.rfb_upstream import RfbUpstream, set_encodings
from kvmhub.telemetry import SessionTelemetry, audit_evidence
from tests.support.fake_bmc import FakeBmc, config_for

SENTINEL = "Zx9Qv"
AUTH_REPLY = b"A" * 48


async def open_session(server):
    upstream = RfbUpstream(config_for(server, handshake_timeout=5, request_timeout=5))
    await upstream.login("operator", password=server.password)
    await upstream.open(request_frames=False)
    version = client_protocol_version(upstream.protocol_version)
    session = RfbPassthroughSession(
        upstream, BrowserHandshake(upstream.server_init_raw, version=version),
        allowed_client_messages=INSYDE_CLIENT_MESSAGES,
        message_sizes=INSYDE_MESSAGE_SIZES, recovery=RecoveryPolicy())
    await session.start()
    await session.send_bytes(b"RFB 055.008\n" + bytes([16]) + AUTH_REPLY + b"\x01"
                             + set_encodings()
                             + framebuffer_update_request(False, 0, 0, 1024, 768))
    return upstream, session


async def type_sentinel(session):
    for character in SENTINEL:
        await session.send_bytes(build_key_event(ord(character), True))
        await session.send_bytes(build_key_event(ord(character), False))


def test_the_whole_session_never_writes_the_typed_text_anywhere(caplog):
    async def scenario():
        server = FakeBmc(send_updates=2)
        await server.start()
        upstream = None
        session = None
        try:
            upstream, session = await open_session(server)
            with caplog.at_level(logging.DEBUG):
                await type_sentinel(session)
                await asyncio.sleep(0.05)
                telemetry = SessionTelemetry()
                telemetry.note_connection(session)
                record = telemetry.evidence(sid="s" * 32, reason="client_closed",
                                            cleanup="confirmed")
                durable = audit_evidence(record)
                shape = session.as_dict()
            return shape, record, durable
        finally:
            if session is not None:
                await session.close()
            if upstream is not None:
                await upstream.close()
            await server.stop()

    shape, record, durable = asyncio.run(scenario())
    everything = json.dumps([shape, record, durable], default=str) + caplog.text
    assert SENTINEL not in everything
    assert SENTINEL.encode().hex() not in everything.lower().replace(" ", "")
    assert shape["client_message_types"]["4"] == 2 * len(SENTINEL)


def test_a_denied_message_records_only_its_shape_not_its_payload():
    async def scenario():
        server = FakeBmc()
        await server.start()
        try:
            upstream, session = await open_session(server)
            await session.send_bytes(bytes([90]) + SENTINEL.encode())
            return session.as_dict()
        finally:
            await session.close()
            await upstream.close()
            await server.stop()

    shape = asyncio.run(scenario())
    assert shape["denied"] == {"kind": 90, "length": 1 + len(SENTINEL)}
    assert SENTINEL not in json.dumps(shape)


def test_the_end_evidence_records_the_error_class_but_not_its_message():
    async def scenario():
        server = FakeBmc(drop_after_frames=1, close_code=1011)
        await server.start()
        try:
            upstream, session = await open_session(server)
            await type_sentinel(session)
            await asyncio.sleep(0.1)
            telemetry = SessionTelemetry()
            telemetry.note_connection(session)
            return telemetry.evidence(sid="e" * 32, reason="upstream_error",
                                      cleanup="pending")
        finally:
            await session.close()
            await upstream.close()
            await server.stop()

    record = asyncio.run(scenario())
    assert SENTINEL not in json.dumps(record, default=str)
    assert record["exception_type"] in (None, "Problem")
    assert record["client_message_types"]["4"] == 2 * len(SENTINEL)
