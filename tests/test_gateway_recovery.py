"""M3 stage 1: the gateway rebuilds the BMC console without losing the session."""
import asyncio
import struct

import pytest

from kvmhub.ast2100_protocol import client_protocol_version, framebuffer_update_request
from kvmhub.common import Problem
from kvmhub.passthrough import INSYDE_CLIENT_MESSAGES, INSYDE_MESSAGE_SIZES, BrowserHandshake, RfbPassthroughSession
from kvmhub.recovery import RecoveryPolicy, RecoveryState, retryable
from kvmhub.rfb_upstream import RfbUpstream, set_encodings
from tests.support.fake_bmc import SERVER_INIT, FakeBmc, config_for

AUTH_REPLY = b"A" * 48


def other_server_init(width=640, height=480):
    return struct.pack(">HH", width, height) + SERVER_INIT[4:]


def browser_hello(version=b"RFB 055.008\n"):
    return version + bytes([16]) + AUTH_REPLY + b"\x01"


async def session_on(server, policy):
    upstream = RfbUpstream(config_for(server, handshake_timeout=5, request_timeout=5))
    await upstream.login("operator", password=server.password)
    await upstream.open(request_frames=False)
    version = client_protocol_version(upstream.protocol_version)
    session = RfbPassthroughSession(
        upstream, BrowserHandshake(upstream.server_init_raw, version=version),
        allowed_client_messages=INSYDE_CLIENT_MESSAGES,
        message_sizes=INSYDE_MESSAGE_SIZES, recovery=policy)
    await session.start()
    return upstream, session, version


async def complete_browser_side(session, version, width=1024, height=768):
    await session.send_bytes(browser_hello(version))
    await session.send_bytes(set_encodings()
                             + framebuffer_update_request(False, 0, 0, width, height))


def saw_last_frame(messages):
    return any(message.endswith(b"\x04" * 4) for message in messages)


async def read_until(session, predicate, *, limit=40, timeout=6.0):
    seen = []
    deadline = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < deadline:
        try:
            seen.append((await asyncio.wait_for(session.__anext__(), timeout)).data)
        except (StopAsyncIteration, asyncio.TimeoutError):
            break
        if predicate(seen):
            break
    return seen


@pytest.fixture
async def server():
    bmc = await FakeBmc(drop_after_frames=2, close_code=1011, send_updates=4,
                        payload_bytes=4, drop_connections=1).start()
    try:
        yield bmc
    finally:
        await bmc.stop()


async def test_a_dropped_console_is_rebuilt_and_frames_resume(server):
    policy = RecoveryPolicy(attempts=1, first_delay=0.05, deadline=10)
    upstream, session, version = await session_on(server, policy)
    await complete_browser_side(session, version)

    seen = await read_until(session, saw_last_frame)

    assert saw_last_frame(seen), f"no frame from the rebuilt console: {seen[-3:]!r}"
    assert server.console_opens == 2, "exactly one rebuild, not a reconnect storm"
    assert session.recovery.recoveries == 1
    assert session.recovery.state == "relaying"
    assert session.recovery.last_latency_ms is not None
    assert not session.closed, "the browser stream must survive the rebuild"
    await session.close()
    await upstream.close()


async def test_the_rebuild_is_bounded_by_the_session_budget(server):
    server.drop_connections = 99
    policy = RecoveryPolicy(attempts=1, first_delay=0.02, max_total=2, deadline=10)
    upstream, session, version = await session_on(server, policy)
    await complete_browser_side(session, version)

    await read_until(session, lambda messages: False)
    assert session.closed is False
    assert session.recovery.recoveries == 2, "the budget, not the attempts, is the limit"
    assert server.console_opens == 3, "initial console plus two rebuilds"
    assert session.error in ("upstream_closed", "upstream_unavailable")
    await session.close()
    await upstream.close()


async def test_an_unreachable_bmc_exhausts_the_attempts_and_ends(server):
    policy = RecoveryPolicy(attempts=2, first_delay=0.02, deadline=10)
    upstream, session, version = await session_on(server, policy)
    await complete_browser_side(session, version)
    calls = []

    async def unreachable(**kwargs):
        calls.append(kwargs)
        raise Problem("upstream_unavailable", 502)

    upstream.reopen = unreachable
    await read_until(session, lambda messages: False)

    assert len(calls) == 2, "attempts is the cap per episode"
    assert session.recovery.state == "given_up"
    assert session.recovery.last_error == "upstream_unavailable"
    assert session.error == "upstream_unavailable"
    await session.close()
    await upstream.close()


async def test_a_dead_web_session_is_not_reopened(server):
    policy = RecoveryPolicy(attempts=3, first_delay=0.02, deadline=10)
    upstream, session, version = await session_on(server, policy)
    await complete_browser_side(session, version)
    calls = []

    async def gone(**kwargs):
        calls.append(kwargs)
        raise Problem("bmc_auth_failed", 502)

    upstream.reopen = gone
    await read_until(session, lambda messages: False)

    assert len(calls) == 1, "one attempt is enough to learn the session is gone"
    assert session.recovery.state == "given_up"
    assert session.recovery.last_error == "bmc_auth_failed"
    await session.close()
    await upstream.close()


async def test_a_changed_framebuffer_ends_the_session_instead_of_growing(server):
    server.server_init_after = other_server_init()
    policy = RecoveryPolicy(attempts=2, first_delay=0.02, deadline=10)
    upstream, session, version = await session_on(server, policy)
    await complete_browser_side(session, version)

    await read_until(session, lambda messages: False)
    assert session.recovery.state == "given_up"
    assert session.recovery.last_error == "upstream_changed"
    assert session.error == "upstream_changed"
    assert server.console_opens == 2
    await session.close()
    await upstream.close()


async def test_a_console_that_handshakes_but_never_draws_is_not_a_recovery(server):
    policy = RecoveryPolicy(attempts=1, first_delay=0.02, frame_timeout=0.4, deadline=10)
    upstream, session, version = await session_on(server, policy)
    await complete_browser_side(session, version)
    server.silent = True

    await read_until(session, lambda messages: False, timeout=8)
    assert session.recovery.state == "given_up"
    assert session.recovery.last_error == "upstream_silent"
    assert session.error == "upstream_silent"
    assert server.console_opens == 2
    await session.close()
    await upstream.close()


async def test_input_during_a_rebuild_is_dropped_not_fatal(server):
    policy = RecoveryPolicy(attempts=1, first_delay=0.25, deadline=10)
    upstream, session, version = await session_on(server, policy)
    await complete_browser_side(session, version)

    for _ in range(200):
        if session.recovery.state == "recovering":
            break
        await asyncio.sleep(0.01)
    assert session.recovery.state == "recovering"
    key = b"\x04\x01\x00\x00\x00\x00\x00\x00\xff\xe1" + b"\x00" * 9
    await session.send_bytes(key)
    assert session.recovery.dropped_input == 1
    assert session.error is None, "a keystroke during a rebuild is not an upstream fault"

    seen = await read_until(session, saw_last_frame)
    assert saw_last_frame(seen), "the rebuild still completed after the dropped key"
    assert session.recovery.recoveries == 1
    await session.close()
    await upstream.close()



def test_reopen_is_the_default_and_cheap():
    policy = RecoveryPolicy()
    assert policy.attempts == 2 and policy.max_total == 3
    assert [policy.delay(n) for n in (1, 2, 3)] == [0.4, 0.8, 1.6]
    assert policy.delay(9) == policy.max_delay


def test_the_backoff_is_capped():
    assert RecoveryPolicy(first_delay=1.0, max_delay=1.5).delay(5) == 1.5


@pytest.mark.parametrize("code", ["bmc_auth_failed", "upstream_frame_too_large",
                                  "upstream_budget_exceeded", "upstream_invalid_response",
                                  "client_message_denied"])
def test_failures_another_socket_would_repeat_are_not_retried(code):
    assert retryable(code) is False


@pytest.mark.parametrize("code", ["upstream_unavailable", "upstream_unresponsive",
                                  "upstream_handshake_failed", "upstream_closed", None])
def test_link_failures_are_retried(code):
    assert retryable(code) is True


def test_the_console_ceiling_is_not_retried():
    assert retryable("upstream_closed", 12592) is False
    assert retryable("upstream_closed", 1011) is True


def test_the_session_budget_stops_a_console_that_keeps_dropping():
    state = RecoveryState(RecoveryPolicy(attempts=3, max_total=2))
    assert state.may_try("upstream_closed") is True
    state.begin()
    state.succeed(650)
    state.begin()
    state.succeed(700)
    assert state.may_try("upstream_closed") is False
    assert state.counters()["recoveries"] == 2


def test_a_disabled_policy_never_tries():
    assert RecoveryState(RecoveryPolicy(attempts=0)).may_try("upstream_closed") is False


def test_config_values_are_clamped_and_never_raise():
    policy = RecoveryPolicy.from_config({
        "upstream_recovery_attempts": 99,
        "upstream_recovery_max_total": -3,
        "upstream_recovery_delay_seconds": "not-a-number",
        "upstream_recovery_deadline_seconds": 1e9,
    })
    assert policy.attempts == 5, "capped at the documented maximum"
    assert policy.max_total == 0
    assert policy.first_delay == RecoveryPolicy.first_delay
    assert policy.deadline == 60.0
    assert RecoveryPolicy.from_config({}) == RecoveryPolicy()
