"""Sliding-window rate limiting with escalating penalties (OWASP LLM04).

Redis when REDIS_URL is set -- correct across many workers and pods. Otherwise an
in-process window so the gateway still runs with zero infrastructure. The
in-memory backend is per-process and is not a substitute for Redis in production.
"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
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

    @abstractmethod
    async def consume(self, key: str, amount: int, limit: int) -> RateLimitResult:
        """Charge `amount` units against a weighted sliding window.

        Request counting asks "how many?"; a token budget asks "how much?", so
        each entry carries a cost instead of counting as one. Used for tokens,
        where a single request can be worth ten thousand of them.
        """

    async def start(self) -> None: ...

    async def stop(self) -> None: ...


class MemoryBackend(RateLimitBackend):
    name = "memory"

    def __init__(self) -> None:
        self._hits: dict[str, deque[tuple[float, int]]] = defaultdict(deque)
        self._lock = asyncio.Lock()

    async def _charge(self, key: str, amount: int, limit: int) -> RateLimitResult:
        now = time.monotonic()
        async with self._lock:
            window = self._hits[key]
            cutoff = now - WINDOW_SECONDS
            while window and window[0][0] < cutoff:
                window.popleft()
            window.append((now, amount))
            count = sum(cost for _, cost in window)
            oldest = window[0][0]
        retry_after = max(1, int(WINDOW_SECONDS - (now - oldest))) if count > limit else 0
        return RateLimitResult(
            allowed=count <= limit,
            remaining=max(0, limit - count),
            limit=limit,
            retry_after=retry_after,
            penalty=_penalty(count, limit),
        )

    async def hit(self, key: str, limit: int) -> RateLimitResult:
        return await self._charge(key, 1, limit)

    async def consume(self, key: str, amount: int, limit: int) -> RateLimitResult:
        return await self._charge(key, max(0, amount), limit)


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
        pipe.zadd(redis_key, {f"{now}:{uuid.uuid4().hex}": now})
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

    async def consume(self, key: str, amount: int, limit: int) -> RateLimitResult:
        """Weighted window in Redis.

        Each entry carries its cost in the member name, so summing the window
        means reading it rather than calling ZCARD. The window holds at most
        one entry per request per minute, so that read stays small -- and it
        keeps the whole operation in one round trip without a Lua script.
        """
        assert self._redis is not None, "Redis backend not started"
        amount = max(0, amount)
        now = time.time()
        redis_key = f"vs:tb:{key}"

        pipe = self._redis.pipeline()
        pipe.zremrangebyscore(redis_key, 0, now - WINDOW_SECONDS)
        pipe.zadd(redis_key, {f"{amount}:{now}:{uuid.uuid4().hex}": now})
        pipe.zrange(redis_key, 0, -1)
        pipe.expire(redis_key, WINDOW_SECONDS + 1)
        _, _, members, _ = await pipe.execute()

        count = 0
        for member in members:
            head, _, _ = str(member).partition(":")
            try:
                count += int(head)
            except ValueError:  # an entry written by an older format
                continue

        return RateLimitResult(
            allowed=count <= limit,
            remaining=max(0, limit - count),
            limit=limit,
            retry_after=WINDOW_SECONDS if count > limit else 0,
            penalty=_penalty(count, limit),
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

    async def check_tokens(self, key: str, amount: int, limit: int) -> RateLimitResult:
        """Charge a token cost against the per-minute budget (LLM04).

        Called twice per request: once before the upstream call with the
        estimated prompt cost, and once after with the correction from the
        provider's own usage figures. Charging zero is a no-op, so a
        reconciliation that finds the estimate was generous costs nothing.
        """
        if amount <= 0:
            return RateLimitResult(True, limit, limit, 0)
        try:
            return await self._backend.consume(f"tok:{key}", amount, limit)
        except Exception:
            logger.exception("token budget check failed; allowing request")
            return RateLimitResult(True, limit, limit, 0)


limiter = RateLimiter()
