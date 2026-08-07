"""Redis wrapper: JSON get/set with TTL, plus pub/sub publish.

Centralizes all Redis access so callers (REST routes, the WebSocket
handler, the ingestion loop) never touch a raw `redis.asyncio` client
directly -- serialization and connection lifecycle live in one place.
"""
import json
from typing import Any

import redis.asyncio as redis

from app.settings import get_settings

_client: redis.Redis | None = None


def get_redis() -> redis.Redis:
    global _client
    if _client is None:
        _client = redis.from_url(get_settings().REDIS_URL, decode_responses=True)
    return _client


async def get_json(key: str) -> Any | None:
    raw = await get_redis().get(key)
    return json.loads(raw) if raw is not None else None


async def set_json(key: str, value: Any, ttl_seconds: int) -> None:
    await get_redis().set(key, json.dumps(value, default=str), ex=ttl_seconds)


async def publish(channel: str, payload: dict) -> None:
    await get_redis().publish(channel, json.dumps(payload, default=str))


async def close() -> None:
    global _client
    if _client is not None:
        await _client.aclose()
    _client = None
