"""The architectural rule: expensive stages stay off the hot path."""

from __future__ import annotations

from app.detectors.base import Detector, InspectionContext
from app.detectors.pipeline import DetectionPipeline
from app.models.schemas import (
    Decision,
    Direction,
    Finding,
    OwaspCategory,
    Severity,
)
from tests.test_policy import _policy


class Recording(Detector):
    def __init__(self, name: str, stage: int, confidence: float | None) -> None:
        self.name = name  # type: ignore[misc]
        self.stage = stage  # type: ignore[misc]
        self.directions = (Direction.INBOUND, Direction.OUTBOUND)  # type: ignore[misc]
        self._confidence = confidence
        self.calls = 0

    async def inspect(self, ctx: InspectionContext) -> list[Finding]:
        self.calls += 1
        if self._confidence is None:
            return []
        return [
            Finding(
                detector=self.name,
                category=OwaspCategory.LLM01_PROMPT_INJECTION,
                severity=Severity.CRITICAL,
                confidence=self._confidence,
                message=f"{self.name} fired",
                direction=ctx.direction,
            )
        ]


def _ctx(text: str = "some prompt") -> InspectionContext:
    return InspectionContext(text=text, direction=Direction.INBOUND)


async def test_clean_traffic_never_reaches_the_classifier() -> None:
    cheap = Recording("rules", stage=0, confidence=None)
    expensive = Recording("classifier", stage=1, confidence=0.9)
    verdict = await DetectionPipeline([cheap, expensive]).inspect(_ctx(), _policy())

    assert cheap.calls == 1
    assert expensive.calls == 0, "stage 1 must not run on unambiguous traffic"
    assert verdict.decision is Decision.ALLOW


async def test_obvious_attacks_short_circuit_before_the_classifier() -> None:
    cheap = Recording("rules", stage=0, confidence=0.99)
    expensive = Recording("classifier", stage=1, confidence=0.5)
    verdict = await DetectionPipeline([cheap, expensive]).inspect(_ctx(), _policy())

    assert expensive.calls == 0, "a confident block should not pay for stage 1"
    assert verdict.decision is Decision.BLOCK


async def test_ambiguous_traffic_escalates_to_the_next_stage() -> None:
    cheap = Recording("rules", stage=0, confidence=0.6)
    expensive = Recording("classifier", stage=1, confidence=0.8)
    verdict = await DetectionPipeline([cheap, expensive]).inspect(_ctx(), _policy())

    assert expensive.calls == 1
    assert verdict.decision is Decision.BLOCK
    assert any("stage1" in s for s in verdict.stages_run)


class Exploding(Recording):
    async def inspect(self, ctx: InspectionContext) -> list[Finding]:
        self.calls += 1
        raise RuntimeError("detector bug")


async def test_a_broken_detector_cannot_take_down_the_gateway() -> None:
    broken = Exploding("broken", stage=0, confidence=None)
    healthy = Recording("rules", stage=0, confidence=None)
    verdict = await DetectionPipeline([broken, healthy]).inspect(_ctx(), _policy())

    assert broken.calls == 1 and healthy.calls == 1
    assert verdict.decision is Decision.ALLOW


async def test_empty_input_is_skipped_entirely() -> None:
    cheap = Recording("rules", stage=0, confidence=0.99)
    verdict = await DetectionPipeline([cheap]).inspect(_ctx(text="   "), _policy())
    assert cheap.calls == 0
    assert verdict.decision is Decision.ALLOW


async def test_stages_run_records_what_actually_executed() -> None:
    pipeline = DetectionPipeline([Recording("rules", stage=0, confidence=None)])
    verdict = await pipeline.inspect(_ctx(), _policy())
    assert verdict.stages_run == ["stage0:rules"]
