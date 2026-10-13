"""Stage 0: model extraction detection (OWASP LLM10).

Every other detector in this project judges one request on its own text. This
one cannot, because extraction has no signature inside a single request. Each
individual prompt in a distillation harvest is ordinary -- "summarize this
review", "summarize this review", ten thousand times with a different review
each time. The attack is the *pattern*, and the pattern is only visible across
requests.

So this detector keeps a small per-tenant history of prompt fingerprints and
asks three questions of it:

  near-duplicate flood   Is this prompt a near-copy of many recent ones?
                         Systematic probing varies one slot and holds the rest
                         fixed, which is exactly what a similarity measure
                         sees. Caught with SimHash, so "summarize this: A" and
                         "summarize this: B" land close together while two
                         genuinely different questions do not.

  template enumeration   Do many recent prompts share a skeleton once numbers,
                         quoted strings, emails, and ids are blanked out? This
                         catches the same behavior from the other side and
                         survives a slot value long enough to move the SimHash.

  probe persistence      Is the tenant repeatedly asking about the model's own
                         configuration -- its prompt, its rules, its training,
                         its parameters? One such question is curiosity and is
                         LLM01's business. Thirty in ten minutes is mapping.

What this is not: a confident detector. Volume and repetition are legitimate
for a batch classification workload, which is why every finding here is
MEDIUM at most and lands in the flag band rather than the block band. The
honest claim is that it surfaces a pattern worth an operator's attention, not
that it has caught a thief. A tenant running real batch traffic should turn it
off with `DETECT_EXTRACTION=false` rather than fight it.

State is in-process and bounded. Across several workers each sees only its own
slice of a tenant's traffic, which lowers recall -- a sweep spread over four
workers looks four times slower to each of them -- but never manufactures a
detection. Recall here is best-effort by construction, and the docs say so.
"""

from __future__ import annotations

import re
import time
from collections import defaultdict, deque
from dataclasses import dataclass

from app.config import settings
from app.detectors.base import Detector, InspectionContext
from app.detectors.normalize import normalize
from app.models.schemas import Direction, Finding, OwaspCategory, Severity

# --- Fingerprinting --------------------------------------------------------

SIMHASH_BITS = 64
# Hamming distance at or below which two prompts count as near-duplicates.
#
# Measured rather than guessed. Over templated probe sets (one slot varying,
# the rest fixed) and a varied support queue, pairwise distances separate
# cleanly: templated pairs run a median of 14, while no two distinct support
# questions came closer than 21. At 20 three quarters of templated pairs are
# caught and nothing in the varied set pairs falsely; at 24 that rises to 85%
# but 9% of ordinary question pairs start matching, which is the wrong trade
# for a signal that accumulates.
#
# Short prompts are the reason this is not tighter. A nine-word prompt has
# seven trigrams, so changing one word moves nearly half the fingerprint --
# "item number 3" and "item number 4" are 12 bits apart, not 2.
#
# Calibrated on this project's own corpora, which are small and self-authored.
# Treat it as a starting point, not a universal constant.
NEAR_DUPLICATE_DISTANCE = 20

# Slot values blanked out to leave a comparable skeleton behind.
_SLOT_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"[\w.+-]+@[\w-]+\.[\w.]+"),  # emails
    re.compile(r"https?://\S+"),  # urls
    re.compile(r"\"[^\"]{1,120}\"|'[^']{1,120}'"),  # quoted slot values
    re.compile(r"\b[0-9a-f]{8,}\b", re.IGNORECASE),  # hex ids
    re.compile(r"\b\d[\d,.]*\b"),  # numbers
)

# Questions about the model's own configuration rather than the product's.
# Narrower than the triage vocabulary on purpose: triage is allowed to
# over-trigger because something else judges what it selects, while this
# accumulates across requests and has to stay specific.
_PROBE = re.compile(
    r"\b(?:"
    r"system prompt|system message|system instructions|initial (?:prompt|instructions)|"
    r"your (?:instructions|rules|guidelines|configuration|training data|parameters|"
    r"weights|temperature|model name|context window|knowledge cutoff)|"
    r"what (?:model|llm|version) are you|which model are you|"
    r"were you (?:trained|fine[- ]?tuned)|how were you trained|"
    r"repeat (?:the|your) (?:prompt|instructions)|verbatim instructions|"
    r"everything above|text above this|preceding instructions"
    r")\b",
    re.IGNORECASE,
)


def _tokens(text: str) -> list[str]:
    return re.findall(r"\w+", text.lower())


def simhash(text: str, bits: int = SIMHASH_BITS) -> int:
    """Charikar SimHash over word trigrams.

    Trigrams rather than single words: word-level hashing makes any two
    prompts drawn from the same vocabulary look alike, and a support queue is
    full of those. Trigrams keep word order in the fingerprint, so similarity
    means "phrased the same way", not "about the same topic".
    """
    words = _tokens(text)
    if not words:
        return 0
    if len(words) < 3:
        features = [" ".join(words)]
    else:
        features = [" ".join(words[i : i + 3]) for i in range(len(words) - 2)]

    vector = [0] * bits
    for feature in features:
        # Python's hash() is randomized per process, which would make
        # fingerprints incomparable across restarts. FNV-1a is stable.
        h = _fnv1a(feature) % (1 << bits)
        for bit in range(bits):
            vector[bit] += 1 if h >> bit & 1 else -1

    out = 0
    for bit in range(bits):
        if vector[bit] > 0:
            out |= 1 << bit
    return out


def _fnv1a(text: str) -> int:
    h = 0xCBF29CE484222325
    for byte in text.encode("utf-8"):
        h ^= byte
        h = (h * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return h


def hamming(a: int, b: int) -> int:
    return (a ^ b).bit_count()


def skeleton(text: str) -> str:
    """The prompt with its variable parts blanked out.

    "Translate 'hello' to French" and "Translate 'goodbye' to French" both
    reduce to `translate § to french`, which is what makes templated
    enumeration countable.
    """
    view = normalize(text).basic
    for pattern in _SLOT_PATTERNS:
        view = pattern.sub("§", view)
    view = re.sub(r"\s+", " ", view).strip().lower()
    # Long tails differ even in templated probing (a pasted document, say);
    # the opening is what carries the template.
    return view[:160]


# --- Per-tenant history ----------------------------------------------------


@dataclass(slots=True)
class Fingerprint:
    at: float
    simhash: int
    skeleton: str
    probe: bool


class ProfileStore:
    """Bounded per-tenant ring of recent prompt fingerprints.

    Holds no prompt text -- only a 64-bit hash, a blanked skeleton, and a
    flag. A gateway that hashes prompts by default should not keep a
    plaintext shadow copy of them in memory to do behavioral analysis.
    """

    def __init__(self, *, window_seconds: int | None = None, history: int | None = None):
        self._window = window_seconds or settings.extraction_window_seconds
        self._history = history or settings.extraction_history
        self._by_tenant: dict[str, deque[Fingerprint]] = defaultdict(
            lambda: deque(maxlen=self._history)
        )

    @property
    def window_seconds(self) -> int:
        return self._window

    def clear(self) -> None:
        self._by_tenant.clear()

    def record(self, tenant: str, fingerprint: Fingerprint) -> list[Fingerprint]:
        """Append this request and return the still-live prior history."""
        window = self._by_tenant[tenant]
        cutoff = fingerprint.at - self._window
        prior = [f for f in window if f.at >= cutoff]
        window.append(fingerprint)
        return prior


store = ProfileStore()


# --- Thresholds ------------------------------------------------------------
# Set where a batch workload's ordinary repetition ends. Deliberately high:
# the cost of a false positive here is an operator chasing a customer's normal
# traffic, and this detector cannot see enough to justify that.

NEAR_DUPLICATE_MIN = 12
TEMPLATE_MIN = 15
PROBE_MIN = 8


class ExtractionDetector(Detector):
    """Systematic probing or harvesting across requests (LLM10)."""

    name = "extraction"
    stage = 0
    directions = (Direction.INBOUND,)

    def __init__(self, profiles: ProfileStore | None = None) -> None:
        self._store = profiles or store

    def applies_to(self, ctx: InspectionContext) -> bool:
        # Without a tenant there is no history to compare against: an
        # unauthenticated caller has no identity to accumulate a pattern under.
        return (
            settings.detect_extraction
            and ctx.tenant_id is not None
            and super().applies_to(ctx)
        )

    async def inspect(self, ctx: InspectionContext) -> list[Finding]:
        assert ctx.tenant_id is not None  # guarded by applies_to
        text = ctx.text
        current = Fingerprint(
            at=time.monotonic(),
            simhash=simhash(text),
            skeleton=skeleton(text),
            probe=bool(_PROBE.search(text)),
        )
        prior = self._store.record(ctx.tenant_id, current)
        if not prior:
            return []

        findings: list[Finding] = []

        near = sum(
            1 for f in prior if hamming(f.simhash, current.simhash) <= NEAR_DUPLICATE_DISTANCE
        )
        if near >= NEAR_DUPLICATE_MIN:
            findings.append(
                self._finding(
                    ctx,
                    rule_id="near-duplicate-flood",
                    confidence=self._scale(near, NEAR_DUPLICATE_MIN),
                    message=(
                        f"{near} near-identical prompts from this tenant in the last "
                        f"{self._store.window_seconds // 60} minutes: systematic probing"
                    ),
                    metadata={"near_duplicates": near, "window_size": len(prior)},
                )
            )

        same_skeleton = sum(1 for f in prior if f.skeleton == current.skeleton)
        if same_skeleton >= TEMPLATE_MIN:
            findings.append(
                self._finding(
                    ctx,
                    rule_id="template-enumeration",
                    confidence=self._scale(same_skeleton, TEMPLATE_MIN),
                    message=(
                        f"{same_skeleton} prompts sharing one template with only the "
                        "slot values changed: enumeration"
                    ),
                    evidence=current.skeleton[:120],
                    metadata={"template_hits": same_skeleton},
                )
            )

        if current.probe:
            probes = sum(1 for f in prior if f.probe)
            if probes >= PROBE_MIN:
                findings.append(
                    self._finding(
                        ctx,
                        rule_id="probe-persistence",
                        confidence=self._scale(probes, PROBE_MIN),
                        severity=Severity.MEDIUM,
                        message=(
                            f"{probes} questions about the model's own configuration "
                            "from this tenant: mapping rather than curiosity"
                        ),
                        metadata={"probe_count": probes},
                    )
                )

        return findings

    @staticmethod
    def _scale(observed: int, threshold: int) -> float:
        """Confidence that grows past the threshold but stays out of the block
        band. Three times the threshold is still only 0.7, because no amount of
        repetition makes a volume signal certain about intent."""
        over = (observed - threshold) / max(threshold, 1)
        return round(min(0.7, 0.45 + 0.12 * over), 3)

    def _finding(
        self,
        ctx: InspectionContext,
        *,
        rule_id: str,
        confidence: float,
        message: str,
        severity: Severity = Severity.LOW,
        evidence: str | None = None,
        metadata: dict | None = None,
    ) -> Finding:
        return Finding(
            detector=self.name,
            category=OwaspCategory.LLM10_MODEL_THEFT,
            severity=severity,
            confidence=confidence,
            message=message,
            direction=ctx.direction,
            evidence=evidence,
            metadata={"rule_id": rule_id, **(metadata or {})},
        )
