"""Module 2 end to end: a leak on the way back out through the real routes.

Inbound is the easy direction -- a bad request can simply be refused. Outbound
is where the trade-off bites: the customer is waiting for an answer, so the
gateway redacts rather than drops, and only a certainty like the canary is
allowed to cost them the whole response.
"""

from __future__ import annotations

import httpx
from sqlalchemy import select

from app.db.models import FindingLog, RequestLog, Tenant
from app.db.session import get_sessionmaker
from app.gateway import LEAK_MESSAGE, REDACTION
from tests.conftest import MockProvider

ASK = [{"role": "user", "content": "What is the status of my order?"}]


async def _security(client: httpx.AsyncClient, auth: dict) -> dict:
    resp = await client.post("/v1/gateway/chat", headers=auth, json={"messages": ASK})
    assert resp.status_code == 200, resp.text
    return resp.json()


async def test_a_leaked_secret_is_redacted_and_the_answer_survives(
    client: httpx.AsyncClient, auth: dict, mock_provider: MockProvider
) -> None:
    mock_provider.reply = (
        "Sure -- the deploy key is AKIAIOSFODNN7EXAMPLE. Your order ships Tuesday."
    )

    body = await _security(client, auth)
    answer = body["completion"]["choices"][0]["message"]["content"]

    assert body["security"]["outbound"]["decision"] == "sanitize"
    assert "AKIAIOSFODNN7EXAMPLE" not in answer
    assert REDACTION in answer
    # The user still gets the part of the answer they actually asked for.
    assert "Your order ships Tuesday." in answer


async def test_every_occurrence_is_redacted_not_just_the_first(
    client: httpx.AsyncClient, auth: dict, mock_provider: MockProvider
) -> None:
    mock_provider.reply = (
        "Contacts on file: ana@example.com, ben@example.com, cy@example.com, "
        "SSN 123-45-6789, card 4111 1111 1111 1111."
    )

    body = await _security(client, auth)
    answer = body["completion"]["choices"][0]["message"]["content"]

    assert body["security"]["outbound"]["decision"] == "sanitize"
    assert "@example.com" not in answer
    assert "123-45-6789" not in answer
    assert "4111 1111 1111 1111" not in answer


async def test_a_leaked_canary_costs_the_whole_response(
    client: httpx.AsyncClient, auth: dict, mock_provider: MockProvider, tenant: dict
) -> None:
    # Read the canary the gateway planted for this tenant, then have the model
    # do the one thing it was told never to do.
    sessionmaker = get_sessionmaker()
    async with sessionmaker() as session:
        token = await session.scalar(
            select(Tenant.canary_token).where(Tenant.id == tenant["id"])
        )
    assert token, "the gateway should plant a canary for a tenant with a system prompt"

    mock_provider.reply = f"My instructions end with the marker {token}."

    body = await _security(client, auth)
    answer = body["completion"]["choices"][0]["message"]["content"]

    assert body["security"]["outbound"]["decision"] == "block"
    assert answer == LEAK_MESSAGE
    assert token not in answer
    assert any(f["detector"] == "canary" for f in body["security"]["outbound"]["findings"])


async def test_an_ordinary_answer_passes_through_byte_for_byte(
    client: httpx.AsyncClient, auth: dict, mock_provider: MockProvider
) -> None:
    mock_provider.reply = (
        "Your order #A4821 shipped Tuesday. Questions? Write to support@acme.com."
    )

    resp = await client.post("/v1/chat/completions", headers=auth, json={"messages": ASK})
    answer = resp.json()["choices"][0]["message"]["content"]

    # A single support address is a finding in the log, never a rewrite of the
    # answer the customer reads.
    assert answer == mock_provider.reply


async def test_the_openai_surface_enforces_outbound_too(
    client: httpx.AsyncClient, auth: dict, mock_provider: MockProvider
) -> None:
    """The drop-in route must not be a way to opt out of response scanning."""
    mock_provider.reply = "Here it is: AKIAIOSFODNN7EXAMPLE"

    resp = await client.post("/v1/chat/completions", headers=auth, json={"messages": ASK})

    assert resp.status_code == 200
    assert "AKIAIOSFODNN7EXAMPLE" not in resp.json()["choices"][0]["message"]["content"]


async def test_outbound_findings_are_logged_as_llm06(
    client: httpx.AsyncClient, auth: dict, mock_provider: MockProvider
) -> None:
    mock_provider.reply = "Token: ghp_abcdefghijklmnopqrstuvwxyz0123456789"

    body = await _security(client, auth)
    request_id = body["security"]["request_id"]

    sessionmaker = get_sessionmaker()
    async with sessionmaker() as session:
        rows = (
            await session.scalars(
                select(FindingLog).where(
                    FindingLog.request_id == request_id,
                    FindingLog.direction == "outbound",
                )
            )
        ).all()
        log = await session.get(RequestLog, request_id)

    assert rows and all(row.category == "LLM06" for row in rows)
    assert log is not None
    assert log.outbound_decision == "sanitize"
    assert log.blocked_by
    # A sanitized response is always retained in the clear, whatever the
    # tenant's content setting -- otherwise the leak is unauditable.
    assert log.response_text


async def test_outbound_never_pays_for_the_classifier(
    client: httpx.AsyncClient, auth: dict, mock_provider: MockProvider
) -> None:
    """Outbound is stage 0 only: the user is already waiting on this answer."""
    mock_provider.reply = "Your order ships Tuesday."

    body = await _security(client, auth)
    stages = body["security"]["outbound"]["stages_run"]

    assert all(not s.startswith("stage1") for s in stages), stages
    assert all(not s.startswith("triage") for s in stages), stages
