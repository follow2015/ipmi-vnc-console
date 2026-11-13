"""Upstream recovery primitives: drop the socket, keep the login, reopen."""
from __future__ import annotations

import asyncio

import pytest

from kvmhub.common import Problem
from kvmhub.rfb_upstream import RfbUpstream
from tests.support.fake_bmc import TICKET, FakeBmc, config_for, opened


async def _until(predicate, timeout: float = 2.0) -> bool:
    deadline = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < deadline:
        if predicate():
            return True
        await asyncio.sleep(0.01)
    return False


@pytest.fixture
async def fake_bmc():
    server = await FakeBmc().start()
    try:
        yield server
    finally:
        await server.stop()


async def test_dropping_the_socket_keeps_the_login(fake_bmc):
    upstream = await opened(fake_bmc)
    try:
        assert await upstream.read_ticket() == TICKET
        await upstream.drop_websocket()

        assert upstream.server_init is None and upstream.pending == b""
        assert upstream.upstream_close_code is None
        assert fake_bmc.logged_out is False, "dropping a socket must not log out"
        assert await upstream.read_ticket() == TICKET
    finally:
        await upstream.close()


async def test_reopen_restores_the_picture_without_relogging_in(fake_bmc):
    upstream = await opened(fake_bmc)
    try:
        await upstream.wait_frames(1)
        before = upstream.stats.frames
        await upstream.drop_websocket()
        await upstream.reopen()
        assert upstream.stats.frames >= before
        assert await upstream.wait_frames(1) == 1
    finally:
        await upstream.close()


async def test_reopen_resends_the_client_half_of_the_handshake(fake_bmc):
    upstream = await opened(fake_bmc)
    try:
        def counts() -> tuple[int, int]:
            encodings = sum(1 for m in fake_bmc.client_messages if m[0] == "SetEncodings")
            requests = sum(1 for m in fake_bmc.client_messages if m[0] == "FBURequest")
            return encodings, requests

        assert await _until(lambda: counts() == (1, 1)), "baseline: one handshake"
        await upstream.reopen()
        assert await _until(lambda: counts() == (2, 2)), (
            "reopen must repeat SetEncodings and a FramebufferUpdateRequest: "
            f"the browser does not, and saw {counts()}")
    finally:
        await upstream.close()


async def test_reopen_without_a_login_is_auth_failed(fake_bmc):
    upstream = RfbUpstream(config_for(fake_bmc))
    with pytest.raises(Problem) as caught:
        await upstream.reopen()
    assert caught.value.code == "bmc_auth_failed"
    await upstream.close()


async def test_reopen_reports_a_dead_web_session_as_auth_failed(fake_bmc):
    upstream = await opened(fake_bmc)
    try:
        fake_bmc.bootstrap_redirect = True
        with pytest.raises(Problem) as caught:
            await upstream.reopen()
        assert caught.value.code == "bmc_auth_failed"
    finally:
        await upstream.close()


async def test_http_survives_two_open_console_sockets(fake_bmc):
    upstream = RfbUpstream(config_for(fake_bmc, request_timeout=1.0, handshake_timeout=3))
    try:
        await upstream.login("operator", password=fake_bmc.password)
        await upstream.open()
        await upstream.open()
        assert await upstream.read_ticket() == TICKET
    finally:
        await upstream.close()


async def test_logout_status_is_recorded_when_the_bmc_refuses(fake_bmc):
    upstream = await opened(fake_bmc, logout_path="/cgi/not-there")
    assert await upstream.close() == "failed"
    assert upstream.last_logout_status == 404


async def test_logout_status_is_recorded_on_success(fake_bmc):
    upstream = await opened(fake_bmc)
    assert await upstream.close() == "ok"
    assert upstream.last_logout_status == 204
