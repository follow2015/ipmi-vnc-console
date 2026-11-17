"""Shared state that survives more than one process."""
from __future__ import annotations

import asyncio
import contextlib
import json
import time
from collections.abc import AsyncIterator
from typing import Any, Protocol

SESSION_PREFIX = "kvmhub:session:"
LEASE_PREFIX = "kvmhub:lease:"
WORKER_PREFIX = "kvmhub:worker:"
REVOCATION_CHANNEL = "kvmhub:revoke"
QUOTA_PREFIX = "kvmhub:quota:"

QUOTA_TOLERANCE_MS = 5000


def quota_key(tenant_id: str) -> str:
    return f"{QUOTA_PREFIX}{tenant_id}:concurrent"


class State(Protocol):
    async def put_session(self, digest: str, payload: dict, ttl: int) -> None: ...
    async def get_session(self, digest: str) -> dict | None: ...
    async def drop_session(self, digest: str) -> None: ...
    async def touch_lease(self, session_id: str, ttl: int) -> None: ...
    async def lease_alive(self, session_id: str) -> bool: ...
    async def drop_lease(self, session_id: str) -> None: ...
    async def register_worker(self, worker_id: str, payload: dict, ttl: int) -> None: ...
    async def workers(self) -> dict[str, dict]: ...
    async def publish_revoke(self, session_id: str) -> None: ...
    async def put(self, key: str, value: dict, ttl: int) -> None: ...
    async def get(self, key: str) -> dict | None: ...
    async def take(self, key: str) -> dict | None: ...
    async def claim_worker(self, key: str, drain_key: str, prefix: str, payload: dict, ttl: int, capacity: int) -> bool: ...
    async def delete(self, key: str) -> None: ...
    async def setnx(self, key: str, value: dict, ttl: int) -> bool: ...
    async def keys(self, prefix: str) -> list[str]: ...
    async def reserve_quota(self, key: str, member: str, limit: int | None, ttl: int) -> bool: ...
    async def release_quota(self, key: str, member: str) -> None: ...
    async def quota_usage(self, key: str) -> int: ...
    async def quota_members(self, key: str) -> list[str]: ...
    async def subscribe_revocations(self) -> AsyncIterator[str]: ...
    async def close(self) -> None: ...


def _decode(raw: Any) -> dict | None:
    if raw is None:
        return None
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8")
    try:
        value = json.loads(raw)
    except (ValueError, TypeError):
        return None
    return value if isinstance(value, dict) else None


class MemoryState:

    def __init__(self, clock=time.time):
        self._clock = clock
        self._values: dict[str, tuple[float, str]] = {}
        self._listeners: list[str] = []
        self._zsets: dict[str, dict[str, float]] = {}
        self._revocations: asyncio.Queue[str] | None = None

    async def _set(self, key: str, value: dict, ttl: int) -> None:
        self._values[key] = (self._clock() + ttl, json.dumps(value, separators=(",", ":")))

    async def _get(self, key: str) -> dict | None:
        item = self._values.get(key)
        if item is None:
            return None
        expires, raw = item
        if expires <= self._clock():
            self._values.pop(key, None)
            return None
        return _decode(raw)

    async def put_session(self, digest: str, payload: dict, ttl: int) -> None:
        await self._set(SESSION_PREFIX + digest, payload, ttl)

    async def get_session(self, digest: str) -> dict | None:
        return await self._get(SESSION_PREFIX + digest)

    async def drop_session(self, digest: str) -> None:
        self._values.pop(SESSION_PREFIX + digest, None)

    async def touch_lease(self, session_id: str, ttl: int) -> None:
        await self._set(LEASE_PREFIX + session_id, {"at": self._clock()}, ttl)

    async def lease_alive(self, session_id: str) -> bool:
        return await self._get(LEASE_PREFIX + session_id) is not None

    async def drop_lease(self, session_id: str) -> None:
        self._values.pop(LEASE_PREFIX + session_id, None)

    async def register_worker(self, worker_id: str, payload: dict, ttl: int) -> None:
        await self._set(WORKER_PREFIX + worker_id, payload, ttl)

    async def workers(self) -> dict[str, dict]:
        out = {}
        for key, (expires, raw) in list(self._values.items()):
            if not key.startswith(WORKER_PREFIX) or expires <= self._clock():
                continue
            value = _decode(raw)
            if value is not None:
                out[key[len(WORKER_PREFIX):]] = value
        return out

    async def publish_revoke(self, session_id: str) -> None:
        self._listeners.append(session_id)
        if self._revocations is None:
            self._revocations = asyncio.Queue()
        self._revocations.put_nowait(session_id)

    async def drain_revocations(self) -> list[str]:
        items, self._listeners = self._listeners, []
        return items

    async def subscribe_revocations(self) -> AsyncIterator[str]:
        if self._revocations is None:
            self._revocations = asyncio.Queue()
        while True:
            try:
                yield await asyncio.wait_for(self._revocations.get(), timeout=1.0)
            except (asyncio.TimeoutError, TimeoutError):
                continue

    async def put(self, key: str, value: dict, ttl: int) -> None:
        await self._set(key, value, ttl)

    async def get(self, key: str) -> dict | None:
        return await self._get(key)

    async def delete(self, key: str) -> None:
        self._values.pop(key, None)

    async def take(self, key: str) -> dict | None:
        item = self._values.pop(key, None)
        return _decode(item[1]) if item and item[0] > self._clock() else None

    async def claim_worker(self, key: str, drain_key: str, prefix: str, payload: dict, ttl: int, capacity: int) -> bool:
        now = self._clock()
        live = lambda name: name in self._values and self._values[name][0] > now
        if live(drain_key) or live(key):
            return False
        if sum(name.startswith(prefix) and expiry > now for name, (expiry, _) in self._values.items()) >= capacity:
            return False
        self._values[key] = (now + ttl, json.dumps(payload, separators=(",", ":")))
        return True

    async def setnx(self, key: str, value: dict, ttl: int) -> bool:
        existing = await self._get(key)
        if existing is not None:
            return False
        await self._set(key, value, ttl)
        return True

    async def keys(self, prefix: str) -> list[str]:
        now = self._clock()
        found = [key for key, (expires, _) in list(self._values.items())
                 if key.startswith(prefix) and expires > now]
        found += [key for key, members in list(self._zsets.items())
                  if key.startswith(prefix) and self._prune(key, now)]
        return found

    def _prune(self, key: str, now: float) -> dict[str, float]:
        members = self._zsets.get(key)
        if members is None:
            return {}
        for member, expires in list(members.items()):
            if expires <= now - QUOTA_TOLERANCE_MS / 1000:
                members.pop(member, None)
        return members

    async def reserve_quota(self, key: str, member: str, limit: int | None, ttl: int) -> bool:
        now = self._clock()
        members = self._prune(key, now)
        if limit is not None and limit > 0 and len(members) >= limit:
            return False
        members[member] = now + max(1, int(ttl))
        self._zsets[key] = members
        return True

    async def release_quota(self, key: str, member: str) -> None:
        members = self._zsets.get(key)
        if members is not None:
            members.pop(member, None)
            if not members:
                self._zsets.pop(key, None)

    async def quota_usage(self, key: str) -> int:
        return len(self._prune(key, self._clock()))

    async def quota_members(self, key: str) -> list[str]:
        return list(self._prune(key, self._clock()).keys())

    async def close(self) -> None:
        self._values.clear()
        self._zsets.clear()


class RedisState:
    def __init__(self, url: str):
        import redis.asyncio as aioredis
        self._url = url
        self._client = aioredis.from_url(url, decode_responses=True,
                                         socket_connect_timeout=3, socket_timeout=3)
        self._subscriber = None

    async def put_session(self, digest: str, payload: dict, ttl: int) -> None:
        await self._client.set(SESSION_PREFIX + digest,
                               json.dumps(payload, separators=(",", ":")), ex=ttl)

    async def get_session(self, digest: str) -> dict | None:
        return _decode(await self._client.get(SESSION_PREFIX + digest))

    async def drop_session(self, digest: str) -> None:
        await self._client.delete(SESSION_PREFIX + digest)

    async def touch_lease(self, session_id: str, ttl: int) -> None:
        await self._client.set(LEASE_PREFIX + session_id, str(time.time()), ex=ttl)

    async def lease_alive(self, session_id: str) -> bool:
        return bool(await self._client.exists(LEASE_PREFIX + session_id))

    async def drop_lease(self, session_id: str) -> None:
        await self._client.delete(LEASE_PREFIX + session_id)

    async def register_worker(self, worker_id: str, payload: dict, ttl: int) -> None:
        await self._client.set(WORKER_PREFIX + worker_id,
                               json.dumps(payload, separators=(",", ":")), ex=ttl)

    async def workers(self) -> dict[str, dict]:
        out: dict[str, dict] = {}
        async for key in self._client.scan_iter(match=WORKER_PREFIX + "*"):
            value = _decode(await self._client.get(key))
            if value is not None:
                out[key[len(WORKER_PREFIX):]] = value
        return out

    async def publish_revoke(self, session_id: str) -> None:
        await self._client.publish(REVOCATION_CHANNEL, session_id)

    async def put(self, key: str, value: dict, ttl: int) -> None:
        await self._client.set(key, json.dumps(value, separators=(",", ":")), ex=ttl)

    async def get(self, key: str) -> dict | None:
        return _decode(await self._client.get(key))

    async def delete(self, key: str) -> None:
        await self._client.delete(key)

    async def take(self, key: str) -> dict | None:
        return _decode(await self._client.getdel(key))

    async def claim_worker(self, key: str, drain_key: str, prefix: str, payload: dict, ttl: int, capacity: int) -> bool:
        script = """
        if redis.call('EXISTS', KEYS[2]) == 1 or redis.call('EXISTS', KEYS[1]) == 1 then return 0 end
        local count = 0
        for _, key in ipairs(redis.call('KEYS', ARGV[1] .. '*')) do
            if redis.call('EXISTS', key) == 1 then count = count + 1 end
        end
        if count >= tonumber(ARGV[2]) then return 0 end
        redis.call('SET', KEYS[1], ARGV[3], 'EX', ARGV[4])
        return 1
        """
        return bool(await self._client.eval(script, 2, key, drain_key, prefix, capacity,
                                            json.dumps(payload, separators=(",", ":")), ttl))

    async def setnx(self, key: str, value: dict, ttl: int) -> bool:
        return bool(await self._client.set(key, json.dumps(value, separators=(",", ":")),
                                          ex=ttl, nx=True))

    async def keys(self, prefix: str) -> list[str]:
        return [key async for key in self._client.scan_iter(match=prefix + "*")]

    _RESERVE_SCRIPT = """
    local now = redis.call('TIME')
    local now_ms = tonumber(now[1]) * 1000 + math.floor(tonumber(now[2]) / 1000)
    redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now_ms - tonumber(ARGV[4]))
    local limit = tonumber(ARGV[2])
    if limit > 0 and redis.call('ZCARD', KEYS[1]) >= limit then return 0 end
    redis.call('ZADD', KEYS[1], now_ms + tonumber(ARGV[3]) * 1000, ARGV[1])
    local last = redis.call('ZREVRANGE', KEYS[1], 0, 0, 'WITHSCORES')
    redis.call('PEXPIREAT', KEYS[1], math.ceil(tonumber(last[2]) + tonumber(ARGV[4])))
    return 1
    """

    _USAGE_SCRIPT = """
    local now = redis.call('TIME')
    local now_ms = tonumber(now[1]) * 1000 + math.floor(tonumber(now[2]) / 1000)
    redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now_ms - tonumber(ARGV[1]))
    return redis.call('ZCARD', KEYS[1])
    """

    async def reserve_quota(self, key: str, member: str, limit: int | None, ttl: int) -> bool:
        granted = await self._client.eval(self._RESERVE_SCRIPT, 1, key, member,
                                          int(limit or 0), max(1, int(ttl)),
                                          QUOTA_TOLERANCE_MS)
        return bool(granted)

    async def release_quota(self, key: str, member: str) -> None:
        await self._client.zrem(key, member)

    async def quota_usage(self, key: str) -> int:
        return int(await self._client.eval(self._USAGE_SCRIPT, 1, key, QUOTA_TOLERANCE_MS))

    async def quota_members(self, key: str) -> list[str]:
        return [str(member) for member in await self._client.zrange(key, 0, -1)]

    def _subscription_client(self):
        if self._subscriber is None:
            import redis.asyncio as aioredis
            self._subscriber = aioredis.from_url(self._url, decode_responses=True,
                                                 socket_connect_timeout=3,
                                                 socket_timeout=None)
        return self._subscriber

    async def subscribe_revocations(self) -> AsyncIterator[str]:
        pubsub = self._subscription_client().pubsub(ignore_subscribe_messages=True)
        await pubsub.subscribe(REVOCATION_CHANNEL)
        try:
            async for message in pubsub.listen():
                if message.get("type") != "message":
                    continue
                data = message.get("data")
                if isinstance(data, bytes):
                    data = data.decode("utf-8", "replace")
                if data:
                    yield str(data)
        finally:
            with contextlib.suppress(Exception):
                await pubsub.unsubscribe(REVOCATION_CHANNEL)
            with contextlib.suppress(Exception):
                await pubsub.aclose()

    async def ping(self) -> bool:
        return bool(await self._client.ping())

    async def close(self) -> None:
        if self._subscriber is not None:
            await self._subscriber.aclose()
            self._subscriber = None
        await self._client.aclose()


def create_state(url: str) -> State:
    return RedisState(url) if url else MemoryState()
