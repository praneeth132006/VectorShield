"""Staged detection pipeline.

Stage 0 runs on every request and must stay in the microsecond range. Stages 1+
run only when stage 0 leaves the request in the ambiguous band -- that escalation
rule is what keeps the classifier off the hot path.
"""

from __future__ import annotations

import asyncio
import logging
import time

from app.detectors.base import Detector, InspectionContext
from app.detectors.triage import triage
from app.models.schemas import Direction, Finding, Verdict
from app.policy.engine import decide, score
from app.policy.keys import Policy

logger = logging.getLogger(__name__)


class DetectionPipeline:
    def __init__(self, detectors: list[Detector] | None = None) -> None:
        self._detectors: list[Detector] = list(detectors or [])

    def register(self, detector: Detector) -> None:
        self._detectors.append(detector)
        self._detectors.sort(key=lambda d: d.stage)

    @property
    def detectors(self) -> list[Detector]:
        return list(self._detectors)

    def _stage(self, stage: int, ctx: InspectionContext) -> list[Detector]:
        return [d for d in self._detectors if d.stage == stage and d.applies_to(ctx)]

    async def warmup(self) -> None:
        for d in self._detectors:
            try:
                await d.warmup()
            except Exception:  # a detector must never take the gateway down
                logger.exception("warmup failed for detector %s", d.name)

    async def _run(self, detectors: list[Detector], ctx: InspectionContext) -> list[Finding]:
        if not detectors:
            return []
        results = await asyncio.gather(
            *(d.inspect(ctx) for d in detectors), return_exceptions=True
        )
        findings: list[Finding] = []
        for detector, result in zip(detectors, results, strict=True):
            if isinstance(result, BaseException):
                # Fail-open per detector: one broken rule cannot break the proxy.
                logger.exception("detector %s raised", detector.name, exc_info=result)
                continue
            findings.extend(result)
        return findings

    async def inspect(
        self, ctx: InspectionContext, policy: Policy, max_stage: int = 2
    ) -> Verdict:
        started = time.perf_counter()
        findings: list[Finding] = []
        stages_run: list[str] = []

        for stage in range(0, max_stage + 1):
            detectors = self._stage(stage, ctx)
            if not detectors:
                continue
            stages_run.append(f"stage{stage}:" + ",".join(d.name for d in detectors))
            findings.extend(await self._run(detectors, ctx))

            current = score(findings)

            # Confident block: deeper stages cannot change the outcome.
            if current >= policy.block_threshold:
                break

            # Below the flag line the cheap layer has no opinion -- and rule
            # silence is not evidence of innocence, since stage 0 is
            # high-precision and low-recall. Triage decides whether the input
            # is worth an expensive look, so ordinary product traffic stops
            # here while anything discussing the assistant escalates.
            if current < policy.flag_threshold:
                # Triage exists to decide whether a *prompt* deserves the
                # classifier. Outbound has no stage 1, so there is nothing to
                # escalate to and nothing to pay for.
                if ctx.direction is not Direction.INBOUND:
                    break
                verdict = triage(ctx.text)
                if not verdict.escalate:
                    break
                stages_run.append(f"triage:{verdict.summary}")

        latency_ms = (time.perf_counter() - started) * 1000
        return decide(
            findings,
            policy,
            direction=ctx.direction,
            stages_run=stages_run,
            latency_ms=latency_ms,
        )


def build_inbound_pipeline() -> DetectionPipeline:
    """Detectors that inspect what the client sends.

    Covers LLM01 (injection), the content-shaped half of LLM04 (requests built
    to cost more than they look -- the volume half is enforced as a hard limit
    in `app/ratelimit/quota.py`, not detected here), and LLM10 (extraction
    patterns across requests).
    """
    from app.detectors.abuse import ResourceAbuseDetector
    from app.detectors.classifier import InjectionClassifier
    from app.detectors.extraction import ExtractionDetector
    from app.detectors.rules import (
        EncodedPayloadDetector,
        ObfuscationDetector,
        RuleDetector,
    )

    return DetectionPipeline(
        [
            RuleDetector(),
            ObfuscationDetector(),
            EncodedPayloadDetector(),
            ResourceAbuseDetector(),
            ExtractionDetector(),
            InjectionClassifier(),
        ]
    )


def build_outbound_pipeline() -> DetectionPipeline:
    """Detectors that inspect what the model returns (OWASP LLM06).

    All of these are stage 0: a response is inspected on the way to a user who
    is already waiting, so there is no budget for a model here. Structure --
    key shapes, checksums, a random canary, shingle overlap -- carries the
    confidence instead.
    """
    from app.config import settings as _settings

    if not _settings.outbound_scanning:
        return DetectionPipeline([])

    from app.detectors.leakage import (
        CanaryDetector,
        PIIDetector,
        SecretDetector,
        SystemPromptLeakDetector,
    )

    return DetectionPipeline(
        [
            CanaryDetector(),
            SecretDetector(),
            SystemPromptLeakDetector(),
            PIIDetector(),
        ]
    )


inbound_pipeline = build_inbound_pipeline()
outbound_pipeline = build_outbound_pipeline()


def inspection_context(
    text: str,
    direction: Direction,
    policy: Policy,
    messages: list[tuple[str, str]] | None = None,
) -> InspectionContext:
    return InspectionContext(
        text=text,
        direction=direction,
        messages=messages or [],
        canary_token=policy.canary_token,
        system_prompt=policy.system_prompt,
        tenant_id=policy.tenant_id,
    )
