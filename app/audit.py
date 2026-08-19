"""Request logging.

Every request is logged regardless of decision. Content is hashed by default;
raw text is kept only when the tenant opts in, or when the request was blocked
so that real attacks stay triageable.
"""

from __future__ import annotations

import hashlib
import logging

from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import FindingLog, RequestLog
from app.models.schemas import Decision, Verdict
from app.policy.keys import Policy

logger = logging.getLogger(__name__)

MAX_STORED_CHARS = 8_000


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _retain(text: str, policy: Policy, verdict: Verdict | None) -> str | None:
    """Decide whether this text is persisted in the clear."""
    if not text:
        return None
    always = verdict is not None and verdict.decision in (
        Decision.BLOCK,
        Decision.SANITIZE,
    )
    if policy.store_content or always:
        return text[:MAX_STORED_CHARS]
    return None


async def log_request(
    session: AsyncSession,
    *,
    request_id: str,
    policy: Policy,
    client_ip: str | None,
    route: str,
    provider: str,
    model: str,
    prompt_text: str,
    response_text: str | None,
    inbound: Verdict,
    outbound: Verdict | None,
    prompt_tokens: int = 0,
    completion_tokens: int = 0,
    total_latency_ms: float = 0.0,
    upstream_latency_ms: float | None = None,
    overhead_ms: float = 0.0,
    status_code: int = 200,
    blocked_by: str | None = None,
) -> None:
    row = RequestLog(
        id=request_id,
        tenant_id=policy.tenant_id,
        client_ip=client_ip,
        route=route,
        provider=provider,
        model=model,
        prompt_hash=sha256(prompt_text),
        response_hash=sha256(response_text) if response_text else None,
        prompt_text=_retain(prompt_text, policy, inbound),
        response_text=_retain(response_text or "", policy, outbound),
        decision=inbound.decision.value,
        risk_score=inbound.risk_score,
        outbound_decision=outbound.decision.value if outbound else None,
        outbound_risk_score=outbound.risk_score if outbound else None,
        blocked_by=blocked_by,
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        total_latency_ms=total_latency_ms,
        upstream_latency_ms=upstream_latency_ms,
        overhead_ms=overhead_ms,
        status_code=status_code,
    )
    session.add(row)

    for verdict in (v for v in (inbound, outbound) if v is not None):
        for finding in verdict.findings:
            session.add(
                FindingLog(
                    request_id=request_id,
                    detector=finding.detector,
                    category=finding.category.value,
                    severity=finding.severity.value,
                    direction=finding.direction.value,
                    confidence=finding.confidence,
                    message=finding.message,
                    evidence=(finding.evidence or "")[:1000] or None,
                )
            )

    try:
        await session.commit()
    except Exception:
        # Logging must never fail the user's request.
        await session.rollback()
        logger.exception("failed to persist request log %s", request_id)
