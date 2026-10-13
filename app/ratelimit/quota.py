"""Hard resource limits (OWASP LLM04).

This is the enforcement half of LLM04, and it is deliberately not a detector.
A detector reports an opinion and the Decision Engine weighs it; there is no
opinion in "this request is 90,000 characters" or "this key has spent its
minute's tokens". Those are facts with a fixed answer, so they are checked
here, before any detector or upstream call runs, and they refuse outright.

Three gates, cheapest first:

  shape     Payload caps -- prompt size, message count, requested output.
            Rejected with 413 (or 400 for an impossible `max_tokens`), because
            the client sent something it should not have, and no amount of
            waiting makes it acceptable.
  rate      Requests per minute per key. 429.
  budget    Tokens per minute per key. 429.

The ordering matters: a 90,000-character prompt should not be tokenized,
inspected, and scored before being refused for its size.

Token budgets are charged twice. Before the call the gateway charges its
estimate, which is what makes the limit enforceable at all -- there is no real
count until the model has answered. After the call `reconcile` charges the
difference between the estimate and the provider's reported usage, so the
window converges on the truth within one request. The estimate errs high, so
reconciliation usually refunds nothing and the window is simply correct.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.config import settings
from app.models.schemas import ChatMessage
from app.policy.keys import Policy
from app.ratelimit.limiter import limiter
from app.ratelimit.tokens import estimate_messages, estimate_tokens


class QuotaExceeded(Exception):
    """A hard limit refused the request. Carries everything the 4xx needs."""

    def __init__(
        self,
        *,
        scope: str,
        message: str,
        status_code: int,
        limit: int,
        observed: int,
        retry_after: int = 0,
        penalty: str = "none",
    ) -> None:
        super().__init__(message)
        self.scope = scope
        self.message = message
        self.status_code = status_code
        self.limit = limit
        self.observed = observed
        self.retry_after = retry_after
        self.penalty = penalty

    def headers(self) -> dict[str, str]:
        headers = {
            "X-VectorShield-Quota": self.scope,
            "X-RateLimit-Limit": str(self.limit),
        }
        if self.retry_after:
            headers["Retry-After"] = str(self.retry_after)
            headers["X-RateLimit-Remaining"] = "0"
        if self.penalty != "none":
            headers["X-VectorShield-Penalty"] = self.penalty
        return headers


@dataclass(slots=True)
class QuotaGrant:
    """What the quota layer charged, so the gateway can reconcile later."""

    key: str
    estimated_tokens: int
    token_limit: int
    # Output ceiling to clamp the upstream request to, when the client asked
    # for more than the tenant allows (or asked for nothing at all).
    max_output_tokens: int
    requests_remaining: int = 0
    tokens_remaining: int = 0
    penalty: str = "none"
    notes: list[str] = field(default_factory=list)


def _effective(value: int | None, default: int) -> int:
    """Tenant override, else the global default. 0 means "no limit"."""
    return default if value is None else value


def enforce_shape(messages: list[ChatMessage], policy: Policy) -> None:
    """Payload caps. Refused before anything expensive touches the request."""
    max_chars = _effective(policy.max_prompt_chars, settings.max_prompt_chars)
    max_messages = settings.max_messages

    if max_messages and len(messages) > max_messages:
        raise QuotaExceeded(
            scope="messages",
            message=(
                f"Conversation has {len(messages)} messages, "
                f"which is over the {max_messages}-message limit."
            ),
            status_code=413,
            limit=max_messages,
            observed=len(messages),
        )

    total = sum(len(m.text()) for m in messages)
    if max_chars and total > max_chars:
        raise QuotaExceeded(
            scope="prompt_chars",
            message=(
                f"Prompt is {total:,} characters, which is over the "
                f"{max_chars:,}-character limit."
            ),
            status_code=413,
            limit=max_chars,
            observed=total,
        )


def resolve_output_ceiling(requested: int | None, policy: Policy) -> tuple[int, list[str]]:
    """The `max_tokens` the upstream call will actually be made with.

    A client asking for more than the tenant allows is clamped rather than
    refused: it gets a shorter answer, not an error, because the request is
    otherwise legitimate and an operator's cost ceiling is not the caller's
    fault. Asking for a negative or zero count is a malformed request.
    """
    ceiling = _effective(policy.max_output_tokens, settings.max_output_tokens)
    if requested is None:
        return ceiling, []
    if requested <= 0:
        raise QuotaExceeded(
            scope="max_tokens",
            message="max_tokens must be a positive integer.",
            status_code=400,
            limit=ceiling,
            observed=requested,
        )
    if ceiling and requested > ceiling:
        return ceiling, [
            f"max_tokens clamped from {requested:,} to the tenant ceiling of {ceiling:,}"
        ]
    return requested, []


async def enforce(
    messages: list[ChatMessage],
    policy: Policy,
    *,
    key: str,
    requested_max_tokens: int | None = None,
) -> QuotaGrant:
    """Run every hard limit. Raises QuotaExceeded, or returns what it charged."""
    enforce_shape(messages, policy)
    ceiling, notes = resolve_output_ceiling(requested_max_tokens, policy)

    # --- requests per minute ---------------------------------------------
    rate = await limiter.check(key, policy.rate_limit_rpm)
    if not rate.allowed:
        raise QuotaExceeded(
            scope="requests_per_minute",
            message=(
                f"Rate limit exceeded ({rate.limit} requests/min). "
                f"Penalty level: {rate.penalty}."
            ),
            status_code=429,
            limit=rate.limit,
            observed=rate.limit - rate.remaining,
            retry_after=rate.retry_after or 60,
            penalty=rate.penalty,
        )

    # --- tokens per minute -----------------------------------------------
    # Charged up front: the prompt, which is known exactly, plus a reservation
    # for the reply, which is not.
    #
    # The reservation is what the client asked for when it named a max_tokens,
    # since a client that asks for 4,000 tokens may well use them. When it
    # named nothing, reserving the ceiling would be wrong -- it would make the
    # token budget bind several times tighter than the request limit beside it
    # for replies that are typically a fraction of the ceiling -- so the
    # expected cost is reserved instead and `reconcile` charges whatever the
    # reply actually cost. A single request can therefore overshoot the budget
    # by its own length, once, before the window catches up. That is the
    # deliberate trade: the alternative throttles honest traffic at a fifth of
    # its advertised rate to prevent one request's worth of overshoot.
    token_limit = _effective(policy.rate_limit_tpm, settings.rate_limit_tokens_per_minute)
    expected = settings.expected_completion_tokens
    reservation = (
        min(requested_max_tokens, ceiling)
        if requested_max_tokens
        else min(expected, ceiling or expected)
    )
    estimated = estimate_messages([(m.role, m.text()) for m in messages]) + reservation

    budget = await limiter.check_tokens(key, estimated, token_limit) if token_limit else None
    if budget is not None and not budget.allowed:
        raise QuotaExceeded(
            scope="tokens_per_minute",
            message=(
                f"Token budget exceeded ({budget.limit:,} tokens/min). "
                f"This request was estimated at {estimated:,} tokens."
            ),
            status_code=429,
            limit=budget.limit,
            observed=budget.limit - budget.remaining,
            retry_after=budget.retry_after or 60,
            penalty=budget.penalty,
        )

    return QuotaGrant(
        key=key,
        estimated_tokens=estimated,
        token_limit=token_limit,
        max_output_tokens=ceiling,
        requests_remaining=rate.remaining,
        tokens_remaining=budget.remaining if budget else 0,
        penalty=rate.penalty,
        notes=notes,
    )


async def reconcile(grant: QuotaGrant, prompt_tokens: int, completion_tokens: int) -> int:
    """Correct the window with the provider's real usage.

    Only ever charges the shortfall. If the estimate was generous -- which it
    is designed to be -- nothing is charged and nothing is refunded: refunding
    would let a client probe the estimator by alternating cheap and expensive
    requests, and the error is small enough that eating it is the safer bias.
    """
    if not grant.token_limit:
        return 0
    actual = prompt_tokens + completion_tokens
    shortfall = actual - grant.estimated_tokens
    if shortfall <= 0:
        return 0
    await limiter.check_tokens(grant.key, shortfall, grant.token_limit)
    return shortfall


def estimate_response_tokens(text: str) -> int:
    """Fallback when a provider returns no usage block (Ollama sometimes)."""
    return estimate_tokens(text)
