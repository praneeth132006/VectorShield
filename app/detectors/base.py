"""Detector contract and the inspection context passed down the pipeline.

Detectors are cheap, independent, and opinion-only: each returns findings with a
confidence, never a decision. The Decision Engine is the single place that turns
findings into allow/flag/sanitize/block.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import ClassVar

from app.models.schemas import Direction, Finding


@dataclass(slots=True)
class InspectionContext:
    """Everything a detector may look at for one direction of one request."""

    text: str
    direction: Direction
    # Full conversation as (role, text); detectors that only care about the
    # latest user turn should use `text`.
    messages: list[tuple[str, str]] = field(default_factory=list)
    canary_token: str | None = None
    system_prompt: str | None = None
    tenant_id: str | None = None
    metadata: dict[str, str] = field(default_factory=dict)


class Detector(ABC):
    """Base class for every detection stage.

    `stage` controls cost tiering:
      0 -- always runs, microsecond-scale (regex, structural checks)
      1 -- runs only when stage 0 is ambiguous (ML classifier)
      2 -- runs only when stage 1 is ambiguous (embeddings, LLM-as-judge)

    This is the architectural rule of the project: the model never sits on the
    hot path for ordinary traffic.
    """

    name: ClassVar[str] = "detector"
    stage: ClassVar[int] = 0
    directions: ClassVar[tuple[Direction, ...]] = (Direction.INBOUND,)

    def applies_to(self, ctx: InspectionContext) -> bool:
        return ctx.direction in self.directions and bool(ctx.text.strip())

    @abstractmethod
    async def inspect(self, ctx: InspectionContext) -> list[Finding]:
        """Return zero or more findings. Must never raise for ordinary input."""

    async def warmup(self) -> None:
        """Optional: load models at startup so the first request isn't slow."""
        return None
