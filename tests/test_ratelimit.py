"""OWASP LLM04: rate limiting with escalating penalties."""

from __future__ import annotations

import httpx
import pytest

from app.ratelimit.limiter import MemoryBackend, _penalty


async def test_window_allows_up_to_the_limit_then_denies() -> None:
    backend = MemoryBackend()
    results = [await backend.hit("client-a", limit=3) for _ in range(4)]
    assert [r.allowed for r in results] == [True, True, True, False]
    assert results[2].remaining == 0
    assert results[3].retry_after > 0


async def test_clients_are_limited_independently() -> None:
    backend = MemoryBackend()
    for _ in range(3):
        await backend.hit("client-a", limit=3)
    other = await backend.hit("client-b", limit=3)
    assert other.allowed is True
    assert other.remaining == 2


@pytest.mark.parametrize(
    ("count", "limit", "expected"),
    [(1, 10, "none"), (9, 10, "warn"), (15, 10, "throttle"), (40, 10, "block")],
)
def test_penalties_escalate(count: int, limit: int, expected: str) -> None:
    assert _penalty(count, limit) == expected


async def test_gateway_returns_429_with_retry_after(
    client: httpx.AsyncClient, tenant: dict
) -> None:
    """A tenant capped at 2 rpm gets a clean 429, not an upstream call."""
    resp = await client.post(
        "/admin/tenants",
        headers={"X-Admin-Token": "test-admin-token"},
        json={"name": "chatty-client", "rate_limit_rpm": 2},
    )
    key = resp.json()["api_key"]
    headers = {"Authorization": f"Bearer {key}"}
    payload = {"messages": [{"role": "user", "content": "hi"}]}

    codes = [
        (await client.post("/v1/chat/completions", headers=headers, json=payload)).status_code
        for _ in range(3)
    ]
    assert codes == [200, 200, 429]

    limited = await client.post("/v1/chat/completions", headers=headers, json=payload)
    assert limited.status_code == 429
    assert int(limited.headers["Retry-After"]) > 0
    assert limited.headers["X-VectorShield-Penalty"] in {"throttle", "block"}
