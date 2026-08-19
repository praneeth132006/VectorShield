"""Test fixtures: a real gateway wired to a fake upstream model."""

from __future__ import annotations

import os
import tempfile
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

import pytest

_TMP = Path(tempfile.mkdtemp(prefix="vectorshield-tests-"))

# Configure before app import: settings are read once at module load.
os.environ.update(
    DATABASE_URL=f"sqlite+aiosqlite:///{_TMP / 'test.db'}",
    REDIS_URL="",
    BOOTSTRAP_API_KEY="",
    ADMIN_TOKEN="test-admin-token",
    STORE_CONTENT="false",
    RATE_LIMIT_REQUESTS_PER_MINUTE="1000",
    LOG_LEVEL="WARNING",
)

import httpx  # noqa: E402
from httpx import ASGITransport  # noqa: E402

from app.config import settings  # noqa: E402
from app.models.schemas import (  # noqa: E402
    ChatCompletionChoice,
    ChatCompletionRequest,
    ChatCompletionResponse,
    ChatMessage,
    Usage,
)
from app.proxy.llm_client import PROVIDERS, LLMProvider, UpstreamResult  # noqa: E402


class MockProvider(LLMProvider):
    """Records what the gateway actually forwarded, and replies with a script."""

    name = "mock"

    def __init__(self) -> None:
        self.reply = "Hello from the mock model."
        self.last_request: ChatCompletionRequest | None = None
        self.calls = 0

    @property
    def default_model(self) -> str:
        return "mock-model"

    async def complete(
        self, request: ChatCompletionRequest, client: httpx.AsyncClient
    ) -> UpstreamResult:
        self.calls += 1
        self.last_request = request
        return UpstreamResult(
            ChatCompletionResponse(
                id="chatcmpl-mock",
                created=0,
                model=request.model or self.default_model,
                choices=[
                    ChatCompletionChoice(
                        message=ChatMessage(role="assistant", content=self.reply)
                    )
                ],
                usage=Usage(prompt_tokens=7, completion_tokens=5, total_tokens=12),
            ),
            latency_ms=1.0,
        )

    async def health(self, client: httpx.AsyncClient) -> str:
        return "ok"


@pytest.fixture
def mock_provider() -> MockProvider:
    provider = MockProvider()
    PROVIDERS["mock"] = provider
    settings.default_provider = "mock"  # type: ignore[assignment]
    return provider


@pytest.fixture
async def client(mock_provider: MockProvider) -> AsyncIterator[httpx.AsyncClient]:
    from app.main import app

    async with _lifespan():
        async with httpx.AsyncClient(
            transport=ASGITransport(app=app), base_url="http://gateway"
        ) as ac:
            yield ac


@asynccontextmanager
async def _lifespan() -> AsyncIterator[None]:
    """Run the same startup/shutdown work the app's lifespan does."""
    from app.db.session import dispose_db, init_db
    from app.proxy.llm_client import pool
    from app.ratelimit.limiter import limiter

    await init_db()
    await pool.start()
    await limiter.start()
    try:
        yield
    finally:
        await limiter.stop()
        await pool.stop()
        await dispose_db()


@pytest.fixture
async def tenant(client: httpx.AsyncClient) -> dict:
    resp = await client.post(
        "/admin/tenants",
        headers={"X-Admin-Token": "test-admin-token"},
        json={
            "name": "acme-support-bot",
            "system_prompt": "You are Acme's support bot. Only discuss Acme products.",
        },
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


@pytest.fixture
def auth(tenant: dict) -> dict[str, str]:
    return {"Authorization": f"Bearer {tenant['api_key']}"}
