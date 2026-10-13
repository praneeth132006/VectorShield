"""Stage 0 outbound canary-leak detector (OWASP LLM06).

Looks for the tenant's canary token in the model's response. Matching is
tolerant: case-insensitive, and separators (spaces, hyphens, punctuation) may
appear between any two characters, so "vs - canary - ab12..." is still caught.

The finding is HIGH @ 0.80 -> score 0.68, which lands in the flag band: open
tenants get SANITIZE (the matched span is redacted by `sanitize_response`),
fail-closed tenants get BLOCK. Use CRITICAL @ >=0.85 to block every leak instead.

Not implemented: system-prompt overlap detection, PII/API-key detection.
"""

from __future__ import annotations

import re
from typing import ClassVar

from app.detectors._util import make_finding
from app.detectors.base import Detector, InspectionContext
from app.models.schemas import Direction, Finding, OwaspCategory, Severity

_MIN_TOKEN_CHARS = 8


def canary_pattern(token: str) -> re.Pattern[str] | None:
    chars = [c for c in token if c.isalnum()]
    if len(chars) < _MIN_TOKEN_CHARS:
        return None
    return re.compile(r"[\W_]*".join(re.escape(c) for c in chars), re.IGNORECASE)


class CanaryLeakDetector(Detector):
    name: ClassVar[str] = "canary_leak"
    stage: ClassVar[int] = 0
    directions: ClassVar[tuple[Direction, ...]] = (Direction.OUTBOUND,)

    def applies_to(self, ctx: InspectionContext) -> bool:
        return bool(ctx.canary_token) and super().applies_to(ctx)

    async def inspect(self, ctx: InspectionContext) -> list[Finding]:
        if not ctx.canary_token:
            return []
        pattern = canary_pattern(ctx.canary_token)
        if pattern is None:
            return []
        match = pattern.search(ctx.text)
        if not match:
            return []
        return [
            make_finding(
                detector=self.name,
                category=OwaspCategory.LLM06_INFO_DISCLOSURE,
                direction=Direction.OUTBOUND,
                message="canary token appeared in the response (system prompt leak)",
                confidence=0.80,
                severity=Severity.HIGH,
                evidence=match.group(0),
            )
        ]
