"""Hard resource limits: payload caps, request rate, token budgets (LLM04)."""

from __future__ import annotations

import pytest

from app.config import settings
from app.models.schemas import ChatMessage
from app.policy.keys import Policy
from app.ratelimit import quota
from app.ratelimit.limiter import MemoryBackend, RateLimiter
from app.ratelimit.tokens import estimate_messages, estimate_tokens


def policy(**overrides) -> Policy:
    base = {
        "tenant_id": "t1",
        "tenant_name": "t1",
        "fail_mode": "open",
        "block_threshold": 0.85,
        "flag_threshold": 0.45,
        "rate_limit_rpm": 1_000,
        "store_content": False,
        "system_prompt": None,
        "canary_token": None,
        "rate_limit_tpm": None,
        "max_prompt_chars": None,
        "max_output_tokens": None,
    }
    base.update(overrides)
    return Policy(**base)


def msgs(*texts: str) -> list[ChatMessage]:
    return [ChatMessage(role="user", content=t) for t in texts]


@pytest.fixture(autouse=True)
def _fresh_limiter(monkeypatch):
    """Each test gets its own window, so order cannot leak between them."""
    fresh = RateLimiter()
    fresh._backend = MemoryBackend()
    monkeypatch.setattr(quota, "limiter", fresh)
    return fresh


# --------------------------------------------------------------------------
# Token estimation
# --------------------------------------------------------------------------


def test_empty_text_costs_nothing():
    assert estimate_tokens("") == 0


def test_any_non_empty_text_costs_at_least_one_token():
    """Otherwise a budget could be walked through one character at a time."""
    assert estimate_tokens("a") >= 1


def test_estimate_is_within_a_sane_range_for_prose():
    text = "The quick brown fox jumps over the lazy dog. " * 20
    estimate = estimate_tokens(text)
    # ~180 words; real tokenizers land around 200-240 tokens.
    assert 150 <= estimate <= 350, estimate


def test_estimate_errs_high_rather_than_low():
    """A budget that under-charges is a budget an attacker can walk through."""
    words = 100
    text = " ".join(["developer"] * words)
    # "developer" is ~3 tokens; a chars/4 estimate must not come in under the
    # word count itself.
    assert estimate_tokens(text) >= words


def test_cjk_is_charged_per_character():
    """CJK has no whitespace and tokenizes far denser than Latin script."""
    latin = estimate_tokens("a" * 60)
    cjk = estimate_tokens("请" * 60)
    assert cjk > latin


def test_message_framing_is_charged():
    assert estimate_messages([("user", "hi")]) > estimate_tokens("hi")


def test_message_estimate_sums_the_conversation():
    one = estimate_messages([("user", "hello there friend")])
    two = estimate_messages([("user", "hello there friend")] * 2)
    assert two > one


# --------------------------------------------------------------------------
# Payload caps
# --------------------------------------------------------------------------


async def test_oversized_prompt_is_refused_with_413():
    with pytest.raises(quota.QuotaExceeded) as exc:
        await quota.enforce(msgs("x" * 60_000), policy(), key="k")
    assert exc.value.status_code == 413
    assert exc.value.scope == "prompt_chars"


async def test_prompt_cap_counts_the_whole_conversation():
    """A cap on one message is no cap at all if you can send a hundred."""
    chunk = "x" * 5_000
    with pytest.raises(quota.QuotaExceeded) as exc:
        await quota.enforce(msgs(*([chunk] * 20)), policy(), key="k")
    assert exc.value.scope == "prompt_chars"


async def test_too_many_messages_is_refused():
    with pytest.raises(quota.QuotaExceeded) as exc:
        await quota.enforce(msgs(*(["hi"] * 500)), policy(), key="k")
    assert exc.value.status_code == 413
    assert exc.value.scope == "messages"


async def test_tenant_can_raise_its_own_prompt_cap():
    grant = await quota.enforce(
        msgs("x" * 60_000), policy(max_prompt_chars=100_000, rate_limit_tpm=0), key="k"
    )
    assert grant.estimated_tokens > 0


async def test_zero_means_no_limit():
    """An operator can lift a cap for a trusted internal tool."""
    grant = await quota.enforce(
        msgs("x" * 200_000), policy(max_prompt_chars=0, rate_limit_tpm=0), key="k"
    )
    assert grant.estimated_tokens > 0


# --------------------------------------------------------------------------
# Output ceiling
# --------------------------------------------------------------------------


async def test_output_request_is_clamped_not_refused():
    """The request is legitimate; the operator's cost ceiling is not its fault."""
    grant = await quota.enforce(
        msgs("hello"), policy(max_output_tokens=256), key="k", requested_max_tokens=100_000
    )
    assert grant.max_output_tokens == 256
    assert grant.notes and "clamped" in grant.notes[0]


async def test_output_request_under_the_ceiling_is_untouched():
    grant = await quota.enforce(
        msgs("hello"), policy(max_output_tokens=4_096), key="k", requested_max_tokens=100
    )
    assert grant.max_output_tokens == 100
    assert grant.notes == []


async def test_nonpositive_max_tokens_is_a_bad_request():
    with pytest.raises(quota.QuotaExceeded) as exc:
        await quota.enforce(msgs("hi"), policy(), key="k", requested_max_tokens=0)
    assert exc.value.status_code == 400


# --------------------------------------------------------------------------
# Token budget
# --------------------------------------------------------------------------


async def test_token_budget_refuses_when_spent():
    # ~3,200 estimated tokens per request, so one fits in the window and two
    # do not.
    p = policy(rate_limit_tpm=5_000)
    big = "word " * 2_000
    await quota.enforce(msgs(big), p, key="k")
    with pytest.raises(quota.QuotaExceeded) as exc:
        await quota.enforce(msgs(big), p, key="k")
    assert exc.value.status_code == 429
    assert exc.value.scope == "tokens_per_minute"
    assert exc.value.retry_after > 0


async def test_token_budget_is_per_key():
    p = policy(rate_limit_tpm=5_000)
    big = "word " * 2_000
    await quota.enforce(msgs(big), p, key="tenant-a")
    # A different tenant must not inherit the first one's spend.
    await quota.enforce(msgs(big), p, key="tenant-b")


async def test_the_reservation_does_not_bind_tighter_than_the_rate_limit():
    """Reserving the full output ceiling would throttle honest traffic.

    At the shipped defaults that mistake caps a tenant near 9 requests a
    minute while the request limit advertises 60. Ordinary short requests must
    clear a full minute of the advertised rate without the budget biting.

    The shipped defaults are used explicitly rather than the settings values,
    because the test environment raises the request limit for convenience and
    would otherwise not be testing the ratio this guards.
    """
    shipped_rpm, shipped_tpm = 60, 40_000
    assert settings.max_output_tokens >= 4_096  # the ceiling this avoids reserving
    p = policy(rate_limit_rpm=shipped_rpm, rate_limit_tpm=shipped_tpm)
    for _ in range(shipped_rpm):
        await quota.enforce(msgs("What are your store hours?"), p, key="k")


async def test_explicit_large_max_tokens_is_reserved_in_full():
    """A client that asks for 4,000 tokens may well use them."""
    p = policy(rate_limit_tpm=10_000)
    grant = await quota.enforce(msgs("hi"), p, key="k", requested_max_tokens=4_000)
    assert grant.estimated_tokens > 4_000


async def test_reconcile_charges_only_the_shortfall():
    p = policy(rate_limit_tpm=100_000)
    grant = await quota.enforce(msgs("hi"), p, key="k")
    charged = await quota.reconcile(grant, prompt_tokens=10, completion_tokens=5_000)
    assert charged == 5_010 - grant.estimated_tokens
    assert charged > 0


async def test_reconcile_refunds_nothing_when_the_estimate_was_generous():
    """Refunding would let a client probe the estimator."""
    p = policy(rate_limit_tpm=100_000)
    grant = await quota.enforce(msgs("hi"), p, key="k")
    assert await quota.reconcile(grant, prompt_tokens=1, completion_tokens=1) == 0


async def test_reconcile_is_a_noop_without_a_budget():
    grant = await quota.enforce(msgs("hi"), policy(rate_limit_tpm=0), key="k")
    assert await quota.reconcile(grant, 1, 999_999) == 0


async def test_an_overshooting_reply_is_caught_on_the_next_request():
    """The documented trade: one request may overshoot, then the window bites."""
    p = policy(rate_limit_tpm=5_000)
    grant = await quota.enforce(msgs("hi"), p, key="k")
    await quota.reconcile(grant, prompt_tokens=10, completion_tokens=50_000)
    with pytest.raises(quota.QuotaExceeded):
        await quota.enforce(msgs("hi"), p, key="k")


# --------------------------------------------------------------------------
# Request rate
# --------------------------------------------------------------------------


async def test_request_rate_limit_still_applies():
    p = policy(rate_limit_rpm=3, rate_limit_tpm=0)
    for _ in range(3):
        await quota.enforce(msgs("hi"), p, key="k")
    with pytest.raises(quota.QuotaExceeded) as exc:
        await quota.enforce(msgs("hi"), p, key="k")
    assert exc.value.scope == "requests_per_minute"
    assert exc.value.status_code == 429


async def test_quota_error_carries_usable_headers():
    p = policy(rate_limit_rpm=1, rate_limit_tpm=0)
    await quota.enforce(msgs("hi"), p, key="k")
    with pytest.raises(quota.QuotaExceeded) as exc:
        await quota.enforce(msgs("hi"), p, key="k")
    headers = exc.value.headers()
    assert headers["Retry-After"]
    assert headers["X-VectorShield-Quota"] == "requests_per_minute"
    assert headers["X-RateLimit-Limit"] == "1"


# --------------------------------------------------------------------------
# Weighted window backend
# --------------------------------------------------------------------------


async def test_memory_backend_weights_by_amount():
    backend = MemoryBackend()
    assert (await backend.consume("k", 60, 100)).allowed
    assert not (await backend.consume("k", 60, 100)).allowed


async def test_memory_backend_counting_and_weighting_are_separate_windows():
    backend = MemoryBackend()
    for _ in range(5):
        await backend.hit("k", 10)
    # Counting 5 hits must not have spent a 100-unit weighted budget.
    assert (await backend.consume("k", 90, 100)).allowed


async def test_zero_cost_charge_is_free():
    fresh = RateLimiter()
    fresh._backend = MemoryBackend()
    assert (await fresh.check_tokens("k", 0, 10)).allowed
