"""Stage 1: the TF-IDF + Logistic Regression classifier (OWASP LLM01).

This runs *only* when stage 0 leaves a request in the ambiguous band. Ordinary
traffic never reaches it, which is what keeps the model off the hot path.

If the artifact is missing the detector degrades to a no-op and says so once at
startup -- an untrained gateway still enforces the rule layer rather than
failing closed on every request.
"""

from __future__ import annotations

import logging
import threading
from pathlib import Path
from typing import Any

from app.config import settings
from app.detectors.base import Detector, InspectionContext
from app.detectors.normalize import normalize
from app.models.schemas import Direction, Finding, OwaspCategory, Severity

logger = logging.getLogger(__name__)

# Below this the model's opinion is not worth reporting at all.
MIN_REPORTABLE_PROBABILITY = 0.5


class InjectionClassifier(Detector):
    name = "classifier"
    stage = 1
    directions = (Direction.INBOUND,)

    def __init__(self, model_path: Path | None = None) -> None:
        self._path = Path(model_path or settings.classifier_model_path)
        self._bundle: dict[str, Any] | None = None
        self._lock = threading.Lock()
        self._load_failed = False

    # --- loading ---------------------------------------------------------

    @property
    def loaded(self) -> bool:
        return self._bundle is not None

    @property
    def metadata(self) -> dict[str, Any]:
        if not self._bundle:
            return {}
        return {
            "sources": self._bundle.get("sources", []),
            "trained_at": self._bundle.get("trained_at"),
            "metrics": self._bundle.get("metrics", {}),
        }

    def _load(self) -> None:
        """Load once, under a lock. joblib.load is not reentrant-safe."""
        if self._bundle is not None or self._load_failed:
            return
        with self._lock:
            if self._bundle is not None or self._load_failed:
                return
            if not self._path.exists():
                self._load_failed = True
                logger.warning(
                    "classifier artifact not found at %s -- stage 1 disabled. "
                    "Train it with: python -m training.train_classifier",
                    self._path,
                )
                return
            try:
                import joblib

                self._bundle = joblib.load(self._path)
            except Exception:
                self._load_failed = True
                logger.exception("failed to load classifier from %s", self._path)
                return

            metrics = self._bundle.get("metrics", {})
            logger.info(
                "classifier loaded from %s (f1=%s, fpr=%s, trained %s)",
                self._path.name,
                metrics.get("f1"),
                metrics.get("false_positive_rate"),
                self._bundle.get("trained_at"),
            )

    async def warmup(self) -> None:
        """Load at startup so the first ambiguous request isn't the slow one."""
        self._load()
        if self.loaded:
            # Prime the vectorizers; the first transform is far slower than the rest.
            self._score("warmup probe: ignore previous instructions")

    def applies_to(self, ctx: InspectionContext) -> bool:
        return super().applies_to(ctx) and not self._load_failed

    # --- inference -------------------------------------------------------

    def _score(self, text: str) -> float | None:
        self._load()
        if self._bundle is None:
            return None
        model = self._bundle["model"]
        try:
            # Same normalization as training -- avoids train/serve skew.
            return float(model.predict_proba([normalize(text).basic])[0][1])
        except Exception:
            logger.exception("classifier inference failed")
            return None

    async def inspect(self, ctx: InspectionContext) -> list[Finding]:
        probability = self._score(ctx.text)
        if probability is None or probability < MIN_REPORTABLE_PROBABILITY:
            return []

        # predict_proba is calibrated, so the probability *is* the confidence.
        # Applying a severity discount on top of it would double-count the
        # uncertainty and silence the model at exactly the probabilities where
        # its opinion matters. Severity is therefore fixed at HIGH, whose weight
        # (0.85) is below 1.0 -- which means the model alone can reach the flag
        # line but never the block line, no matter how certain it is. Blocking
        # still requires the rule layer, or a second detector, to agree.
        severity = Severity.HIGH

        return [
            Finding(
                detector=self.name,
                category=OwaspCategory.LLM01_PROMPT_INJECTION,
                severity=severity,
                confidence=round(probability, 4),
                message=f"Classifier scored this as prompt injection (p={probability:.2f})",
                direction=ctx.direction,
                metadata={"probability": f"{probability:.4f}"},
            )
        ]


classifier = InjectionClassifier()
