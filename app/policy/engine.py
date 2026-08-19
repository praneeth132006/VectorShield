"""The Decision Engine: findings in, one of four decisions out."""

from __future__ import annotations

from app.models.schemas import Decision, Direction, Finding, Severity, Verdict
from app.policy.keys import Policy

# Severity acts as a multiplier on a detector's confidence, so a low-severity
# hit at high confidence never outweighs a critical one.
_SEVERITY_WEIGHT: dict[Severity, float] = {
    Severity.INFO: 0.15,
    Severity.LOW: 0.35,
    Severity.MEDIUM: 0.6,
    Severity.HIGH: 0.85,
    Severity.CRITICAL: 1.0,
}


def score(findings: list[Finding]) -> float:
    """Combine findings with noisy-OR: independent weak signals accumulate,
    but the score never exceeds 1.0 and one detector cannot dominate alone."""
    residual = 1.0
    for f in findings:
        weighted = f.confidence * _SEVERITY_WEIGHT[f.severity]
        residual *= 1.0 - min(max(weighted, 0.0), 1.0)
    return round(1.0 - residual, 4)


def decide(
    findings: list[Finding],
    policy: Policy,
    direction: Direction = Direction.INBOUND,
    *,
    stages_run: list[str] | None = None,
    latency_ms: float = 0.0,
) -> Verdict:
    risk = score(findings)
    stages_run = stages_run or []

    if not findings:
        return Verdict(
            decision=Decision.ALLOW,
            risk_score=0.0,
            findings=[],
            reason="no findings",
            stages_run=stages_run,
            latency_ms=latency_ms,
        )

    top = max(findings, key=lambda f: f.confidence * _SEVERITY_WEIGHT[f.severity])
    reason = f"{top.detector}: {top.message}"

    if risk >= policy.block_threshold:
        decision = Decision.BLOCK
    elif risk >= policy.flag_threshold:
        # The fail mode only governs this ambiguous middle band. "open" keeps
        # real users working and leaves a logged trail; "closed" trades false
        # positives for tighter containment.
        if policy.fail_mode == "closed":
            decision = Decision.BLOCK
            reason = f"{reason} (blocked by fail-closed policy)"
        elif direction is Direction.OUTBOUND:
            # A suspected leak is redacted rather than dropped: the user still
            # gets an answer, minus the secret.
            decision = Decision.SANITIZE
        else:
            decision = Decision.FLAG
    else:
        decision = Decision.ALLOW

    return Verdict(
        decision=decision,
        risk_score=risk,
        findings=findings,
        reason=reason,
        stages_run=stages_run,
        latency_ms=latency_ms,
    )
