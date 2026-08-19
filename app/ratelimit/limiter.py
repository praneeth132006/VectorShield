"""Sliding-window rate limiting with escalating penalties (OWASP LLM04).

Redis when REDIS_URL is set -- correct across many workers and pods. Otherwise an
in-process window so the gateway still runs with zero infrastructure. The
in-memory backend is per-process and is not a substitute for Redis in production.
"""

from __future__ import annotations

import asyncio
import logging
import time
from abc import ABC, abstractmethod
from collections import defaultdict, deque
from dataclasses import dataclass

from app.config import settings

logger = logging.getLogger(__name__)

WINDOW_SECONDS = 60


@dataclass(slots=True)
class RateLimitResult:
    allowed: bool
    remaining: int
    limit: int
    retry_after: int
    # warn -> throttle -> block, based on how far past the limit the client is.
    penalty: str = "none"


def _penalty(count: int, limit: int) -> str:
    if count <= limit * 0.8:
        return "none"
    if count <= limit:
        return "warn"
    if count <= limit * 2:
        return "throttle"
    return "block"


class RateLimitBackend(ABC):
    name: str

    @abstractmethod
    async def hit(self, key: str, limit: int) -> RateLimitResult: ...

    async def start(self) -> None: ...

    async def stop(self) -> None: ...


class MemoryBackend(RateLimitBackend):
    name = "memory"

    def __init__(self) -> None:
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = asyncio.Lock()

    async def hit(self, key: str, limit: int) -> RateLimitResult:
        now = time.monotonic()
        async with self._lock:
            window = self._hits[key]
            cutoff = now - WINDOW_SECONDS
            while window and window[0] < cutoff:
                window.popleft()
            window.append(now)
            count = len(window)
            oldest = window[0]
        retry_after = max(1, int(WINDOW_SECONDS - (now - oldest))) if count > limit else 0
        return RateLimitResult(
            allowed=count <= limit,
            remaining=max(0, limit - count),
            limit=limit,
            retry_after=retry_after,
            penalty=_penalty(count, limit),
        )


class RedisBackend(RateLimitBackend):
    name = "redis"

    def __init__(self, url: str) -> None:
        self._url = url
        self._redis = None

    async def start(self) -> None:
        import redis.asyncio as aioredis

        self._redis = aioredis.from_url(self._url, decode_responses=True)
        await self._redis.ping()

    async def stop(self) -> None:
        if self._redis is not None:
            await self._redis.aclose()
            self._redis = None

    async def hit(self, key: str, limit: int) -> RateLimitResult:
        assert self._redis is not None, "Redis backend not started"
        now = time.time()
        redis_key = f"vs:rl:{key}"
        cutoff = now - WINDOW_SECONDS

        pipe = self._redis.pipeline()
        pipe.zremrangebyscore(redis_key, 0, cutoff)
        pipe.zadd(redis_key, {f"{now}:{id(pipe)}": now})
        pipe.zcard(redis_key)
        pipe.expire(redis_key, WINDOW_SECONDS + 1)
        _, _, count, _ = await pipe.execute()

        return RateLimitResult(
            allowed=count <= limit,
            remaining=max(0, limit - int(count)),
            limit=limit,
            retry_after=WINDOW_SECONDS if count > limit else 0,
            penalty=_penalty(int(count), limit),
        )


class RateLimiter:
    """Front door for the app; hides which backend is active."""

    def __init__(self) -> None:
        self._backend: RateLimitBackend = MemoryBackend()

    @property
    def backend_name(self) -> str:
        return self._backend.name

    async def start(self) -> None:
        if not settings.redis_url:
            logger.info("rate limiter: in-memory backend (set REDIS_URL for multi-worker)")
            return
        backend = RedisBackend(settings.redis_url)
        try:
            await backend.start()
        except Exception:
            logger.exception("Redis unavailable; falling back to in-memory rate limiting")
            self._backend = MemoryBackend()
            return
        self._backend = backend
        logger.info("rate limiter: redis backend")

    async def stop(self) -> None:
        await self._backend.stop()

    async def check(self, key: str, limit: int) -> RateLimitResult:
        try:
            return await self._backend.hit(key, limit)
        except Exception:
            # Never let the limiter take the gateway down.
            logger.exception("rate limit check failed; allowing request")
            return RateLimitResult(True, limit, limit, 0)


limiter = RateLimiter()
