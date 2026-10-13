"""Stage 0: content-shaped resource abuse (OWASP LLM04).

There are two separate ways to exhaust an LLM, and they need separate answers.

The first is *volume*: too many requests, or too many tokens, per minute. That
is accounting, not detection -- there is no judgement call in "this key has
spent 80,000 tokens in the last minute", so it is enforced as a hard limit in
`app/ratelimit/quota.py` and returns 429 before any detector runs.

The second is *shape*, and that is what this module is for. A single request
that sits comfortably inside every quota can still be built to cost far more
than it looks: a 500-fold repetition that a budget charges once at submission
and the model pays for on every generated token, an instruction to continue
forever, a request for fifty thousand words. These need judgement, so they
produce findings with a confidence and let the Decision Engine decide -- the
same contract every other detector follows.

The signals are deliberately conservative. "Write me a long essay" is a
legitimate request, and a gateway that blocks it is worse than useless, so the
thresholds here are set where ordinary verbosity stops and a deliberate cost
attack starts. Most of these findings land in the flag band rather than the
block band on their own, and say so.
"""

from __future__ import annotations

import math
import re
from collections import Counter

from app.config import settings
from app.detectors.base import Detector, InspectionContext
from app.models.schemas import Direction, Finding, OwaspCategory, Severity

# Scanning cost has to stay bounded even when the payload cap is raised.
MAX_SCAN_CHARS = 64_000

# --- Repetition ------------------------------------------------------------
# A repetition bomb is cheap to send and expensive to answer. The giveaway is
# that the text carries almost no information for its length: a handful of
# distinct tokens repeated until the context window fills.

# Below this length, low diversity means nothing -- "yes yes yes" is a normal
# thing for a person to type.
REPETITION_MIN_WORDS = 120
# Share of the text made up of its single most common word.
DOMINANT_WORD_SHARE = 0.35
# Distinct words as a fraction of total words.
LOW_DIVERSITY_RATIO = 0.08
# A single character repeated this many times in a row is not prose.
RUN_LENGTH = 400

_LONG_RUN = re.compile(rf"(.)\1{{{RUN_LENGTH - 1},}}", re.DOTALL)
# The same short phrase pasted back to back many times over.
_REPEATED_PHRASE = re.compile(r"(\b\w[\w\s,.'-]{2,60}?\b)(?:\s*\1){14,}", re.IGNORECASE)

# --- Unbounded output ------------------------------------------------------
# An instruction whose completion condition never arrives. The model will
# generate until it hits a stop limit, and the operator pays for all of it.

# Verbs that ask for generation, with their inflections. "generating" and
# "writing" are how people actually phrase this, so stemming is not optional.
# `count` is spelled out rather than stemmed: `count\w*` also matches "country"
# and "counter", and "which country has unlimited shipping" is not an attack.
_GEN_VERB = (
    r"(?:repeat(?:ing)?|says?|saying|print(?:ing)?|output(?:ting)?|writ(?:e|ing)|"
    r"continu(?:e|ing)|generat(?:e|ing)|count(?:ing)?|list(?:ing)?|produc(?:e|ing)|"
    r"expand(?:ing)?|enumerat(?:e|ing))"
)

# Two shapes, because an unbounded request is phrased two ways.
#
# The first is a generation verb with an adverb of endlessness close behind:
# "repeat this forever", "count to infinity".
#
# The second is a generation verb anywhere nearby plus an instruction never to
# stop: "write about cats and never stop". This one needs the generation verb
# as a precondition rather than matching "never stop" on its own, because
# "I will never stop recommending your product" is a compliment, and an earlier
# version of this rule flagged it.
_UNBOUNDED = re.compile(
    r"\b" + _GEN_VERB + r"\b[\s\S]{0,40}?"
    r"\b(?:forever|for ?ever|indefinitely|infinitely|infinity|endlessly|"
    r"without (?:ever )?stopping|until you run out|non[- ]?stop|ad infinitum)\b"
    r"|\b" + _GEN_VERB + r"\b[\s\S]{0,80}?"
    r"\b(?:never|do ?n[o']?t(?: ever)?|dont) (?:stop|end|finish|terminate|halt)\b"
    r"|\bin an infinite loop\b"
    r"|\brecursively (?:expand|repeat|describe|generate)\b",
    re.IGNORECASE,
)

# A subject that makes a nearby generation verb somebody else's action rather
# than an instruction to the model. "Our team will continue using this service
# indefinitely" is a compliment, and it was a false positive before this.
_NON_IMPERATIVE_SUBJECT = re.compile(
    r"\b(?:i|we|they|he|she|you|everyone|nobody|"
    r"(?:our|my|their|his|her|the)\s+\w+|customers?|users?|clients?|people)\s+"
    r"(?:will|would|can|could|may|might|shall|should|have|has|had|am|is|are|was|were|"
    r"keeps?|kept|plans?|intends?|wants?)\s*$",
    re.IGNORECASE,
)

# An explicit, very large output request. The number is what makes it a cost
# attack: "write 500 words" is a normal ask, "write 500000 words" is not.
#
# Up to three words may sit between the count and its unit, because that is how
# people write: "90000 different product name ideas" names its unit four words
# after its number, and an adjacent-only pattern missed it entirely.
_HUGE_OUTPUT = re.compile(
    r"\b(\d[\d,]{2,})\s+(?:[a-z-]+\s+){0,3}?"
    r"(words?|tokens?|characters?|chars?|lines?|paragraphs?|pages?|sentences?|items?|"
    r"times|rows?|entries|ideas?|names?|examples?|variations?|suggestions?|"
    r"records?|results?)\b",
    re.IGNORECASE,
)

# Thresholds per unit: how much output is more than any real request wants.
_OUTPUT_LIMITS: dict[str, int] = {
    "word": 20_000,
    "token": 20_000,
    "character": 100_000,
    "char": 100_000,
    "line": 5_000,
    "paragraph": 2_000,
    "page": 500,
    "sentence": 5_000,
    "item": 5_000,
    "time": 1_000,
    "row": 10_000,
    "entry": 10_000,
    "idea": 5_000,
    "name": 5_000,
    "example": 5_000,
    "variation": 5_000,
    "suggestion": 5_000,
    "record": 10_000,
    "result": 10_000,
}


def _normalize_unit(unit: str) -> str:
    unit = unit.lower().rstrip("s")
    return "char" if unit == "char" else unit


def _parse_count(raw: str) -> int | None:
    """Read a human-written number. Returns None if it is not one."""
    digits = re.sub(r"[,.\s]", "", raw)
    if not digits.isdigit() or len(digits) > 18:
        return None
    return int(digits)


def word_diversity(text: str) -> tuple[float, float, int]:
    """Return (distinct ratio, dominant-word share, word count)."""
    words = re.findall(r"\w+", text.lower())
    if not words:
        return 1.0, 0.0, 0
    counts = Counter(words)
    return len(counts) / len(words), counts.most_common(1)[0][1] / len(words), len(words)


def shannon_entropy(text: str) -> float:
    """Per-character entropy in bits. Padding and repetition drive it down."""
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


class ResourceAbuseDetector(Detector):
    """Requests built to cost more than they look (LLM04).

    Reports; it never enforces. Volume limits are the quota layer's job, and
    the Decision Engine decides what any of these findings is worth.
    """

    name = "resource-abuse"
    stage = 0
    directions = (Direction.INBOUND,)

    def applies_to(self, ctx: InspectionContext) -> bool:
        return settings.detect_resource_abuse and super().applies_to(ctx)

    async def inspect(self, ctx: InspectionContext) -> list[Finding]:
        text = ctx.text[:MAX_SCAN_CHARS]
        findings: list[Finding] = []

        findings.extend(self._repetition(text, ctx))
        findings.extend(self._unbounded_output(text, ctx))
        findings.extend(self._huge_output(text, ctx))
        return findings

    # -- signals -----------------------------------------------------------

    def _repetition(self, text: str, ctx: InspectionContext) -> list[Finding]:
        """Text that is long but carries almost no information."""
        run = _LONG_RUN.search(text)
        if run:
            return [
                self._finding(
                    ctx,
                    rule_id="character-run",
                    severity=Severity.HIGH,
                    confidence=0.8,
                    message=(
                        f"Single character repeated {len(run.group(0)):,} times: "
                        "a padding or token-exhaustion payload"
                    ),
                    evidence=run.group(0)[:60],
                    metadata={"run_length": len(run.group(0))},
                )
            ]

        phrase = _REPEATED_PHRASE.search(text)
        if phrase:
            return [
                self._finding(
                    ctx,
                    rule_id="repeated-phrase",
                    severity=Severity.MEDIUM,
                    confidence=0.7,
                    message="A short phrase repeated back to back many times over",
                    evidence=phrase.group(1)[:60],
                )
            ]

        ratio, dominant, words = word_diversity(text)
        if words >= REPETITION_MIN_WORDS and (
            ratio <= LOW_DIVERSITY_RATIO or dominant >= DOMINANT_WORD_SHARE
        ):
            return [
                self._finding(
                    ctx,
                    rule_id="low-diversity",
                    severity=Severity.MEDIUM,
                    confidence=0.55,
                    message=(
                        f"{words:,} words but only {ratio:.1%} of them distinct: "
                        "a repetition payload rather than a question"
                    ),
                    metadata={
                        "words": words,
                        "distinct_ratio": round(ratio, 4),
                        "dominant_share": round(dominant, 4),
                        "entropy_bits": round(shannon_entropy(text[:8_000]), 3),
                    },
                )
            ]
        return []

    def _unbounded_output(self, text: str, ctx: InspectionContext) -> list[Finding]:
        """An instruction to generate with no stopping condition.

        Matches are filtered by who the verb belongs to. "Continue ...
        indefinitely" is an attack when it is addressed to the model and a
        compliment when the subject is the customer's own team, and the
        difference is visible in the few words before the verb.
        """
        for match in _UNBOUNDED.finditer(text):
            lead = text[max(0, match.start() - 40) : match.start()]
            if _NON_IMPERATIVE_SUBJECT.search(lead):
                continue
            return [
                self._finding(
                    ctx,
                    rule_id="unbounded-output",
                    severity=Severity.MEDIUM,
                    confidence=0.65,
                    message="Asks the model to generate without a stopping condition",
                    evidence=match.group(0)[:120],
                )
            ]
        return []

    def _huge_output(self, text: str, ctx: InspectionContext) -> list[Finding]:
        """An explicit request for an absurd amount of output.

        Only the largest offender is reported: a prompt saying "100000 words"
        twice is one attack, and emitting two findings would let repetition
        inflate the risk score through noisy-OR.
        """
        worst: tuple[int, int, str, str] | None = None
        for match in _HUGE_OUTPUT.finditer(text):
            count = _parse_count(match.group(1))
            if count is None:
                continue
            unit = _normalize_unit(match.group(2))
            limit = _OUTPUT_LIMITS.get(unit)
            if limit is None or count <= limit:
                continue
            if worst is None or count / limit > worst[0] / worst[1]:
                worst = (count, limit, unit, match.group(0))

        if worst is None:
            return []

        count, limit, unit, evidence = worst
        # Confidence grows with how far past the line it is, but never reaches
        # the block band on this signal alone -- a long document request is a
        # real thing, and only the quota layer knows what the tenant can afford.
        over = count / limit
        confidence = min(0.75, 0.5 + 0.1 * math.log10(max(over, 1.0) * 10))
        return [
            self._finding(
                ctx,
                rule_id="huge-output-request",
                severity=Severity.MEDIUM,
                confidence=round(confidence, 3),
                message=(
                    f"Requests roughly {count:,} {unit}s of output, "
                    f"{over:.0f}x past what a real request asks for"
                ),
                evidence=evidence[:120],
                metadata={"requested": count, "unit": unit, "limit": limit},
            )
        ]

    # -- helper ------------------------------------------------------------

    def _finding(
        self,
        ctx: InspectionContext,
        *,
        rule_id: str,
        severity: Severity,
        confidence: float,
        message: str,
        evidence: str | None = None,
        metadata: dict | None = None,
    ) -> Finding:
        return Finding(
            detector=self.name,
            category=OwaspCategory.LLM04_MODEL_DOS,
            severity=severity,
            confidence=confidence,
            message=message,
            direction=ctx.direction,
            evidence=evidence,
            metadata={"rule_id": rule_id, **(metadata or {})},
        )
