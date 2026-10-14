"""Small helpers shared by the detectors."""

from __future__ import annotations

from app.models.schemas import Direction, Finding, OwaspCategory, Severity


def make_finding(
    *,
    detector: str,
    message: str,
    confidence: float,
    severity: Severity,
    category: OwaspCategory = OwaspCategory.LLM01_PROMPT_INJECTION,
    direction: Direction = Direction.INBOUND,
    evidence: str | None = None,
) -> Finding:
    """Single place that constructs a Finding.

    If your real `Finding` model has extra required fields, add them here once
    instead of in every detector.
    """
    return Finding(
        detector=detector,
        category=category,
        message=message,
        confidence=confidence,
        severity=severity,
        direction=direction,
        evidence=evidence,
    )
