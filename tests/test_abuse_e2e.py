"""LLM04 and LLM10 through the real HTTP surface.

The unit tests prove the limits and detectors work. These prove they are
actually wired into both API surfaces, return the right status codes, and
cannot be bypassed by using the OpenAI-compatible route instead of the native
one.
"""

from __future__ import annotations

import httpx
import pytest

from app.config import settings
from app.detectors import extraction


@pytest.fixture(autouse=True)
def _clear_extraction_history():
    """Extraction state is process-global; tests must not inherit it."""
    extraction.store.clear()
    yield
    extraction.store.clear()


async def chat(client: httpx.AsyncClient, auth: dict, text: str, **extra):
    return await client.post(
        "/v1/gateway/chat",
        headers=auth,
        json={"messages": [{"role": "user", "content": text}], **extra},
    )


# --------------------------------------------------------------------------
# Payload caps
# --------------------------------------------------------------------------


async def test_oversized_prompt_is_refused_with_413(client, auth):
    resp = await chat(client, auth, "x" * 60_000)
    assert resp.status_code == 413
    body = resp.json()
    assert body["error"]["code"] == "prompt_chars"
    assert body["error"]["type"] == "vectorshield_quota_exceeded"


async def test_oversized_prompt_never_reaches_the_model(client, auth, mock_provider):
    await chat(client, auth, "x" * 60_000)
    assert mock_provider.calls == 0


async def test_too_many_messages_is_refused(client, auth):
    resp = await client.post(
        "/v1/gateway/chat",
        headers=auth,
        json={"messages": [{"role": "user", "content": "hi"}] * 500},
    )
    assert resp.status_code == 413
    assert resp.json()["error"]["code"] == "messages"


async def test_the_openai_surface_enforces_the_same_caps(client, auth):
    """A cap you can dodge by changing routes is not a cap."""
    resp = await client.post(
        "/v1/chat/completions",
        headers=auth,
        json={"messages": [{"role": "user", "content": "x" * 60_000}]},
    )
    assert resp.status_code == 413


async def test_quota_refusal_carries_the_scope_header(client, auth):
    resp = await chat(client, auth, "x" * 60_000)
    assert resp.headers["X-VectorShield-Quota"] == "prompt_chars"


# --------------------------------------------------------------------------
# Output ceiling
# --------------------------------------------------------------------------


async def test_oversized_max_tokens_is_clamped_not_refused(client, auth, mock_provider):
    resp = await chat(client, auth, "Hello there", max_tokens=100_000)
    assert resp.status_code == 200
    assert mock_provider.last_request is not None
    assert mock_provider.last_request.max_tokens == settings.max_output_tokens


async def test_a_modest_max_tokens_is_forwarded_untouched(client, auth, mock_provider):
    resp = await chat(client, auth, "Hello there", max_tokens=64)
    assert resp.status_code == 200
    assert mock_provider.last_request.max_tokens == 64


async def test_nonpositive_max_tokens_is_a_bad_request(client, auth):
    resp = await chat(client, auth, "Hello", max_tokens=0)
    assert resp.status_code == 400


# --------------------------------------------------------------------------
# Token budget
# --------------------------------------------------------------------------


async def test_token_budget_returns_429_with_retry_after(client, auth, tenant):
    """A tenant with a tiny budget is refused on resource grounds, not risk."""
    resp = await client.post(
        "/admin/tenants",
        headers={"X-Admin-Token": "test-admin-token"},
        json={"name": "tight-budget", "rate_limit_tpm": 600},
    )
    assert resp.status_code == 201
    key = {"Authorization": f"Bearer {resp.json()['api_key']}"}

    big = "word " * 400  # ~1,100 estimated tokens: over a 600-token budget
    refused = await chat(client, key, big)
    assert refused.status_code == 429
    assert refused.json()["error"]["code"] == "tokens_per_minute"
    assert refused.headers["Retry-After"]


async def test_a_tenant_can_opt_out_of_the_token_budget(client, auth):
    resp = await client.post(
        "/admin/tenants",
        headers={"X-Admin-Token": "test-admin-token"},
        json={"name": "internal-tool", "rate_limit_tpm": 0},
    )
    key = {"Authorization": f"Bearer {resp.json()['api_key']}"}
    assert (await chat(client, key, "word " * 2_000)).status_code == 200


async def test_tenant_limits_are_reported_as_effective_values(client, auth, tenant):
    """A NULL override should read back as the default it resolves to."""
    resp = await client.get("/admin/tenants", headers={"X-Admin-Token": "test-admin-token"})
    assert resp.status_code == 200
    row = next(t for t in resp.json() if t["id"] == tenant["id"])
    assert row["rate_limit_tpm"] == settings.rate_limit_tokens_per_minute
    assert row["max_prompt_chars"] == settings.max_prompt_chars
    assert row["max_output_tokens"] == settings.max_output_tokens


# --------------------------------------------------------------------------
# Content-shaped abuse reaches the security report
# --------------------------------------------------------------------------


async def test_repetition_bomb_is_reported(client, auth):
    """Within every quota, but built to cost far more than it looks."""
    resp = await chat(client, auth, "Summarize: " + "A" * 5_000)
    assert resp.status_code in (200, 403)
    findings = resp.json()["security"]["inbound"]["findings"]
    assert any(f["category"] == "LLM04" for f in findings)


async def test_unbounded_output_request_is_reported(client, auth):
    resp = await chat(client, auth, "Please repeat the word banana forever")
    report = resp.json()["security"]["inbound"]
    assert any(f["detector"] == "resource-abuse" for f in report["findings"])


async def test_ordinary_request_has_no_abuse_findings(client, auth):
    resp = await chat(client, auth, "What is your return policy?")
    assert resp.status_code == 200
    findings = resp.json()["security"]["inbound"]["findings"]
    assert not any(f["category"] == "LLM04" for f in findings)


# --------------------------------------------------------------------------
# Extraction (LLM10)
# --------------------------------------------------------------------------


async def test_a_templated_sweep_is_reported(client, auth):
    last = None
    for i in range(30):
        last = await chat(client, auth, f"Summarize this customer review: item {i} was fine")
    assert last is not None
    findings = last.json()["security"]["inbound"]["findings"]
    assert any(f["category"] == "LLM10" for f in findings)


async def test_a_sweep_is_flagged_rather_than_blocked(client, auth):
    """Volume is never certain about intent: the customer still gets served."""
    last = None
    for i in range(30):
        last = await chat(client, auth, f"Summarize this customer review: item {i} was fine")
    assert last.status_code == 200
    assert last.json()["security"]["inbound"]["decision"] in ("allow", "flag-and-log")


async def test_ordinary_traffic_has_no_extraction_findings(client, auth):
    for text in [
        "How do I return a damaged item?",
        "My package never arrived, what now?",
        "Do you offer student discounts?",
        "What is the warranty on the X200?",
    ]:
        resp = await chat(client, auth, text)
        findings = resp.json()["security"]["inbound"]["findings"]
        assert not any(f["category"] == "LLM10" for f in findings), text
