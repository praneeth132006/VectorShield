"""TF-IDF + Logistic Regression prompt-injection classifier (OWASP LLM01).

Registered at stage 1: the pipeline runs this classifier only when stage 0
leaves the request in the ambiguous risk band.

The model is a joblib bundle produced by `scripts/train_classifier.py`:
    {"pipeline": <sklearn Pipeline>, "meta": {...}}
joblib files are pickles: only load files you trained yourself.

If the file is missing the detector logs a warning and returns no findings
(fail-open), so the gateway still starts. Check `detector.available`.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any, ClassVar

from app.detectors._util import make_finding
from app.detectors.base import Detector, InspectionContext
from app.models.schemas import Direction, Finding, Severity

logger = logging.getLogger(__name__)

# The training script truncates to the same length.
MAX_CHARS = 4000

DEFAULT_MODEL_PATH = Path(__file__).resolve().parents[2] / "models" / "injection_clf.joblib"


def default_model_path() -> Path:
    override = os.getenv("VECTORSHIELD_INJECTION_MODEL")
    return Path(override) if override else DEFAULT_MODEL_PATH


class TfidfInjectionDetector(Detector):
    name: ClassVar[str] = "tfidf_lr"
    stage: ClassVar[int] = 1
    directions: ClassVar[tuple[Direction, ...]] = (Direction.INBOUND,)

    def __init__(
        self, model_path: Path | str | None = None, min_probability: float = 0.30
    ) -> None:
        self._path = Path(model_path) if model_path else default_model_path()
        self._min_probability = min_probability
        self._pipeline: Any = None
        self._attack_index = 1
        self._load_attempted = False

    @property
    def available(self) -> bool:
        self._ensure_loaded()
        return self._pipeline is not None

    def _ensure_loaded(self) -> None:
        if self._load_attempted:
            return
        self._load_attempted = True
        if not self._path.exists():
            logger.warning(
                "injection classifier not found at %s; run scripts/train_classifier.py. "
                "The ML detector is DISABLED (rules still run).",
                self._path,
            )
            return
        try:
            import joblib  # local import: scikit-learn is only needed if the model exists

            bundle = joblib.load(self._path)
            pipeline = bundle["pipeline"]
            self._attack_index = list(pipeline.classes_).index(1)
            self._pipeline = pipeline
            logger.info("loaded injection classifier from %s", self._path)
        except Exception:
            logger.exception("failed to load injection classifier from %s", self._path)

    async def warmup(self) -> None:
        self._ensure_loaded()
        if self._pipeline is not None:
            self._pipeline.predict_proba(["warmup"])

    def probability(self, text: str) -> float | None:
        """P(injection) for `text`, or None when the model is unavailable."""
        self._ensure_loaded()
        if self._pipeline is None:
            return None
        proba = self._pipeline.predict_proba([text[:MAX_CHARS]])[0]
        return float(proba[self._attack_index])

    async def inspect(self, ctx: InspectionContext) -> list[Finding]:
        p = self.probability(ctx.text)
        if p is None or p < self._min_probability:
            return []
        # CRITICAL has weight 1.0, so the finding's score equals the probability
        # and the policy thresholds (0.45 / 0.85) act directly on the classifier.
        return [
            make_finding(
                detector=self.name,
                message=f"classifier: injection probability {p:.2f}",
                confidence=round(p, 4),
                severity=Severity.CRITICAL,
            )
        ]
