"""Phase 0: the gateway is a real, authenticated, logging proxy."""

from __future__ import annotations

import httpx
import pytest
from sqlalchemy import select

from app.audit import sha256
from app.db.models import RequestLog
from app.db.session import get_sessionmaker
from tests.conftest import MockProvider


async def test_health_reports_backends(client: httpx.AsyncClient) -> None:
    body = (await client.get("/health")).json()
    assert body["status"] in {"ok", "degraded"}
    assert body["rate_limit_backend"] == "memory"
    assert body["database"] == "ok"


async def test_api_key_required(client: httpx.AsyncClient) -> None:
    resp = await client.post(
        "/v1/chat/completions",
        json={"messages": [{"role": "user", "content": "hi"}]},
    )
    assert resp.status_code == 401


async def test_invalid_api_key_rejected(client: httpx.AsyncClient) -> None:
    resp = await client.post(
        "/v1/chat/completions",
        headers={"Authorization": "Bearer vs_not_a_real_key"},
        json={"messages": [{"role": "user", "content": "hi"}]},
    )
    assert resp.status_code == 401


async def test_openai_surface_returns_openai_shape(
    client: httpx.AsyncClient, auth: dict, mock_provider: MockProvider
) -> None:
    resp = await client.post(
        "/v1/chat/completions",
        headers=auth,
        json={"messages": [{"role": "user", "content": "What is your return policy?"}]},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["object"] == "chat.completion"
    assert body["choices"][0]["message"]["content"] == mock_provider.reply
    assert body["usage"]["total_tokens"] == 12
    assert mock_provider.calls == 1


async def test_native_surface_returns_security_report(
    client: httpx.AsyncClient, auth: dict
) -> None:
    resp = await client.post(
        "/v1/gateway/chat",
        headers=auth,
        json={"messages": [{"role": "user", "content": "hello"}]},
    )
    assert resp.status_code == 200, resp.text
    security = resp.json()["security"]
    assert security["inbound"]["decision"] == "allow"
    assert security["provider"] == "mock"
    assert security["overhead_ms"] >= 0
    assert security["request_id"]


async def test_x_api_key_header_also_works(client: httpx.AsyncClient, tenant: dict) -> None:
    resp = await client.post(
        "/v1/gateway/chat",
        headers={"X-API-Key": tenant["api_key"]},
        json={"messages": [{"role": "user", "content": "hello"}]},
    )
    assert resp.status_code == 200


async def test_streaming_is_refused_not_silently_ignored(
    client: httpx.AsyncClient, auth: dict
) -> None:
    resp = await client.post(
        "/v1/chat/completions",
        headers=auth,
        json={"messages": [{"role": "user", "content": "hi"}], "stream": True},
    )
    assert resp.status_code == 400
    assert "inspected" in resp.json()["detail"]


async def test_dry_run_skips_upstream(
    client: httpx.AsyncClient, auth: dict, mock_provider: MockProvider
) -> None:
    resp = await client.post(
        "/v1/gateway/chat",
        headers=auth,
        json={"messages": [{"role": "user", "content": "hi"}], "dry_run": True},
    )
    assert resp.status_code == 200
    assert resp.json()["completion"] is None
    assert mock_provider.calls == 0


async def test_unknown_provider_is_a_client_error(
    client: httpx.AsyncClient, auth: dict
) -> None:
    resp = await client.post(
        "/v1/gateway/chat",
        headers=auth,
        json={"messages": [{"role": "user", "content": "hi"}], "provider": "hal9000"},
    )
    assert resp.status_code == 400
    assert "Unknown provider" in resp.json()["error"]["message"]


@pytest.mark.parametrize("route", ["/v1/chat/completions", "/v1/gateway/chat"])
async def test_every_request_is_logged_with_hash_not_content(
    client: httpx.AsyncClient, auth: dict, route: str
) -> None:
    prompt = f"a unique probe for {route}"
    resp = await client.post(
        route, headers=auth, json={"messages": [{"role": "user", "content": prompt}]}
    )
    assert resp.status_code == 200

    async with get_sessionmaker()() as session:
        row = await session.scalar(
            select(RequestLog).where(RequestLog.prompt_hash == sha256(prompt))
        )
    assert row is not None
    assert row.route == route
    assert row.decision == "allow"
    # STORE_CONTENT is false, so raw text must not be persisted.
    assert row.prompt_text is None
    assert row.response_text is None
    assert row.overhead_ms >= 0
