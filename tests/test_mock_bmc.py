"""I-5: the synthetic BMC must not 'confirm' a logout it never issued."""
import aiohttp
from aiohttp.test_utils import TestServer

from kvmhub.mock_bmc import create_mock


async def test_logout_requires_a_token_issued_by_login():
    app = create_mock("u", "p")
    async with TestServer(app) as server:
        async with aiohttp.ClientSession() as client:
            forged = await client.delete(server.make_url("/session"), headers={"X-Mock-Session": "forged"})
            assert forged.status == 401
            login = await client.post(server.make_url("/session"), json={"username": "u", "password": "p"})
            assert login.status == 201
            token = (await login.json())["token"]
            ok = await client.delete(server.make_url("/session"), headers={"X-Mock-Session": token})
            assert ok.status == 204
            replay = await client.delete(server.make_url("/session"), headers={"X-Mock-Session": token})
            assert replay.status == 401
