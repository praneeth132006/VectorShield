"""Stage 0: outbound leakage detection (OWASP LLM06).

Inbound inspection asks "is this user trying to subvert the model?". This
module asks the opposite question about the other direction: "did the model
just hand the user something it should not have?" -- a secret it read out of a
tool result, a customer record it pulled from RAG context, or the tenant's own
system prompt.

Four things are worth catching, in descending order of how certain we can be:

  canary      The tenant's system-prompt marker appeared in the response. There
              is no innocent explanation, so this is the one outbound finding
              confident enough to replace the whole answer.
  secret      A credential with a recognizable shape (AWS key id, GitHub PAT,
              private-key header). Structure carries the confidence; these are
              redacted, not dropped, so the user still gets their answer.
  system      A long verbatim run of the tenant's system prompt, caught by
              shingle overlap rather than by an exact match, so paraphrase-
              resistant leakage still surfaces.
  pii         Email addresses, phone numbers, national IDs, card numbers. The
              weakest signal by far: a support bot is *supposed* to say
              "email us at support@acme.com". Single hits are logged and
              allowed; it takes several, or one high-structure hit like a
              Luhn-valid card number, to reach the sanitize band.

Findings carry the exact matched strings in `metadata["matches"]` so the
gateway can redact precisely those spans and leave the rest of the answer
intact.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from app.config import settings
from app.detectors.base import Detector, InspectionContext
from app.detectors.normalize import LEET, normalize
from app.models.schemas import Direction, Finding, OwaspCategory, Severity

# How much of a response we scan. Beyond this a leak is already out; the cost
# of regexing a megabyte of streamed text is not.
MAX_SCAN_CHARS = 100_000


@dataclass(frozen=True, slots=True)
class Signature:
    id: str
    pattern: re.Pattern[str]
    severity: Severity
    confidence: float
    message: str
    # Which capture group holds the value to redact (0 = the whole match).
    # Assignment-style patterns keep the key name visible and redact only the
    # value, so an operator reading the audit log still knows what leaked.
    group: int = 0
    # When set, the full confidence is only earned if this appears in the
    # sentence around the match. Patterns whose *shape* is ambiguous -- a
    # national id and a warehouse bay number are both ddd-dd-dddd -- need the
    # text around them to mean anything.
    context: re.Pattern[str] | None = None
    # Confidence to use when the shape matched but the context did not: enough
    # to appear in the audit log, never enough to rewrite an answer alone.
    uncorroborated_confidence: float = 0.3


# ---------------------------------------------------------------------------
# Credentials
#
# Confidence here comes from structure, not from context. "AKIA" followed by
# exactly 16 uppercase alphanumerics is an AWS key id and nothing else, so it
# scores far higher than a generic `password = ...` assignment that could
# plausibly be documentation.
# ---------------------------------------------------------------------------

SECRETS: tuple[Signature, ...] = (
    Signature(
        "aws-access-key-id",
        re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b"),
        Severity.CRITICAL,
        0.95,
        "AWS access key id in response",
    ),
    Signature(
        "private-key-block",
        re.compile(r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----"),
        Severity.CRITICAL,
        0.97,
        "Private key material in response",
    ),
    Signature(
        "anthropic-api-key",
        re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}"),
        Severity.CRITICAL,
        0.95,
        "Anthropic API key in response",
    ),
    Signature(
        "openai-api-key",
        re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}"),
        Severity.CRITICAL,
        0.93,
        "OpenAI API key in response",
    ),
    Signature(
        "github-token",
        re.compile(
            r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b"
            r"|\bgithub_pat_[A-Za-z0-9_]{30,}\b"
        ),
        Severity.CRITICAL,
        0.95,
        "GitHub access token in response",
    ),
    Signature(
        "slack-token",
        re.compile(r"\bxox[baprse]-[A-Za-z0-9-]{10,}\b"),
        Severity.CRITICAL,
        0.93,
        "Slack token in response",
    ),
    Signature(
        "google-api-key",
        re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
        Severity.CRITICAL,
        0.93,
        "Google API key in response",
    ),
    Signature(
        "stripe-key",
        re.compile(r"\b[sr]k_(?:live|test)_[0-9A-Za-z]{16,}\b"),
        Severity.CRITICAL,
        0.93,
        "Stripe secret key in response",
    ),
    Signature(
        "vectorshield-gateway-key",
        re.compile(r"\bvs_[A-Za-z0-9_-]{32,}"),
        Severity.CRITICAL,
        0.95,
        "VectorShield gateway API key in response",
    ),
    Signature(
        "jwt",
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
        Severity.HIGH,
        0.8,
        "JSON Web Token in response",
    ),
    Signature(
        "credentialed-url",
        # scheme://user:password@host -- how database URLs leak.
        re.compile(r"\b[a-z][a-z0-9+.-]{2,}://[^\s:@/]{1,64}:([^\s:@/]{3,64})@[^\s/]{3,}"),
        Severity.CRITICAL,
        0.9,
        "Connection string with embedded credentials",
        group=1,
    ),
    Signature(
        "assigned-secret",
        # The weakest of the credential rules: it is shape-agnostic, so it also
        # matches documentation and placeholders. Kept at a confidence that
        # cannot sanitize alone.
        re.compile(
            r"\b(?:api[_-]?key|apikey|secret|secret[_-]?key|access[_-]?token|"
            r"auth[_-]?token|password|passwd|client[_-]?secret)\b"
            r"\s*[:=]\s*[\"']?([A-Za-z0-9_\-./+]{16,})[\"']?",
            re.IGNORECASE,
        ),
        Severity.HIGH,
        0.6,
        "Credential-shaped assignment in response",
        group=1,
    ),
)

# Obvious non-secrets that match the generic assignment rule. Redacting the
# word "your-api-key-here" out of a code sample is a false positive that makes
# the product feel broken.
_PLACEHOLDER = re.compile(
    r"^(?:x{4,}|\*{4,}|\.{4,}|<[^>]+>|\{\{?[^}]+\}?\}|\[[^\]]+\]"
    r"|(?:your|my|the|some|example|sample|placeholder|dummy|test|fake|redacted|"
    r"insert|replace)[_\-a-z0-9]*)$",
    re.IGNORECASE,
)


# `apiKey: process.env.ACME_API_KEY` is the *correct* way to write it. Flagging
# the sample answer that teaches it would make the gateway punish good advice.
_ENV_REFERENCE = re.compile(
    r"^(?:process\.env\.|import\.meta\.env\.|os\.environ|os\.getenv|"
    r"System\.getenv|ENV\[|Deno\.env|\$\{?)"
    r"|^[A-Z][A-Z0-9_]{7,}$",  # a bare SCREAMING_CASE name is a variable, not a value
)


def _is_placeholder(value: str) -> bool:
    if _PLACEHOLDER.match(value) or _ENV_REFERENCE.match(value):
        return True
    # "your-api-key-here", "REPLACE_ME_WITH_TOKEN"
    lowered = value.lower()
    return any(
        word in lowered
        for word in ("example", "placeholder", "your_", "your-", "xxxx", "redacted")
    )


# ---------------------------------------------------------------------------
# Personal data
#
# Everything here is low-confidence on its own and is meant to accumulate.
# ---------------------------------------------------------------------------

# ddd-dd-dddd is also a warehouse bay, a part number, and a date range. The
# shape alone is not evidence, so the surrounding sentence has to agree.
_ID_CONTEXT = re.compile(
    r"\b(?:ssn|social security(?: number| no\.?)?|taxpayer|tax ?id|tin|itin|"
    r"national id|national insurance)\b",
    re.IGNORECASE,
)

# How far around a match to look for that corroborating word. Wide enough for
# "the taxpayer id we have on record for that account is <id>", narrow enough
# that a keyword three sentences away does not vouch for an unrelated number.
CONTEXT_WINDOW = 90

PII: tuple[Signature, ...] = (
    Signature(
        "us-ssn",
        re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"),
        Severity.HIGH,
        0.85,
        "US Social Security number in response",
        context=_ID_CONTEXT,
    ),
    Signature(
        "us-itin",
        # Individual Taxpayer Identification Number: always 9xx, with the
        # middle group drawn from a fixed set of ranges.
        re.compile(r"\b9\d{2}-(?:5\d|6[0-5]|7\d|8[0-8]|9[0-2]|9[4-9])-\d{4}\b"),
        Severity.HIGH,
        0.85,
        "US taxpayer identification number in response",
        context=_ID_CONTEXT,
    ),
    Signature(
        "iban",
        re.compile(r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){3,7}\b"),
        Severity.HIGH,
        0.7,
        "IBAN in response",
    ),
    Signature(
        "email",
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        Severity.LOW,
        0.4,
        "Email address in response",
    ),
    Signature(
        "phone",
        re.compile(
            r"(?<![\w.])(?:\+\d{1,3}[\s.-]?)?(?:\(\d{3}\)|\d{3})[\s.-]\d{3}[\s.-]\d{4}"
            r"(?![\w.])"
        ),
        Severity.LOW,
        0.4,
        "Phone number in response",
    ),
)

# Card numbers get their own path: the regex is only a candidate filter and
# Luhn does the actual deciding.
_CARD = re.compile(r"\b\d(?:[ -]?\d){12,18}\b")


def luhn_valid(digits: str) -> bool:
    """Standard mod-10 checksum. Filters random 16-digit numbers from card numbers."""
    total = 0
    for index, char in enumerate(reversed(digits)):
        value = int(char)
        if index % 2:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


def find_card_numbers(text: str) -> list[str]:
    found: list[str] = []
    for match in _CARD.finditer(text):
        digits = re.sub(r"[ -]", "", match.group(0))
        if 13 <= len(digits) <= 19 and luhn_valid(digits):
            found.append(match.group(0))
    return found


# ---------------------------------------------------------------------------
# Detectors
# ---------------------------------------------------------------------------


def _scan(
    text: str, signatures: tuple[Signature, ...]
) -> list[tuple[Signature, list[str], bool]]:
    """One entry per signature that fired, carrying every distinct match.

    Grouping by signature rather than by occurrence is deliberate: findings are
    combined with noisy-OR, so emitting one finding per matched email address
    would let a directory listing block itself purely by repetition.
    """
    results: list[tuple[Signature, list[str], bool]] = []
    for sig in signatures:
        seen: list[str] = []
        corroborated = False
        for match in sig.pattern.finditer(text):
            value = match.group(sig.group) or match.group(0)
            if not value or value in seen:
                continue
            if sig.id == "assigned-secret" and _is_placeholder(value):
                continue
            if sig.context is not None and sig.context.search(
                text[max(0, match.start() - CONTEXT_WINDOW) : match.end() + 30]
            ):
                corroborated = True
            seen.append(value)
        if seen:
            results.append((sig, seen, sig.context is None or corroborated))
    return results


def _finding(
    detector: str,
    sig: Signature,
    matches: list[str],
    ctx: InspectionContext,
    *,
    confidence: float | None = None,
    severity: Severity | None = None,
) -> Finding:
    return Finding(
        detector=detector,
        category=OwaspCategory.LLM06_INFO_DISCLOSURE,
        severity=severity or sig.severity,
        confidence=confidence if confidence is not None else sig.confidence,
        message=(
            sig.message if len(matches) == 1 else f"{sig.message} ({len(matches)} occurrences)"
        ),
        direction=ctx.direction,
        evidence=matches[0][:200],
        metadata={"rule_id": sig.id, "matches": matches, "count": len(matches)},
    )


class CanaryDetector(Detector):
    """The tenant's system-prompt marker, echoed back by the model.

    The gateway plants a unique token in every system prompt it owns. The token
    is random, so a response can only contain it by having been shown the
    system prompt -- there is no false positive to trade away here, which is
    why this is the one outbound detector confident enough to block outright.

    Checked against the compact normalized view as well, so a model that emits
    the token letter-spaced or punctuation-split is still caught.
    """

    name = "canary"
    stage = 0
    directions = (Direction.OUTBOUND,)

    async def inspect(self, ctx: InspectionContext) -> list[Finding]:
        token = ctx.canary_token
        if not token:
            return []

        text = ctx.text[:MAX_SCAN_CHARS]
        if token in text:
            return [
                Finding(
                    detector=self.name,
                    category=OwaspCategory.LLM06_INFO_DISCLOSURE,
                    severity=Severity.CRITICAL,
                    confidence=0.99,
                    message="Canary token leaked: the system prompt was disclosed",
                    direction=ctx.direction,
                    evidence=token,
                    metadata={
                        "rule_id": "canary-verbatim",
                        "matches": [token],
                        # Deleting the marker would leave the disclosed
                        # instructions in place, so this one drops the answer.
                        "unredactable": True,
                    },
                )
            ]

        # Obfuscated echo: "V S - C A N A R Y - 9f3c..." still means the model
        # read the marker, even though nothing literal matched. The token is
        # folded the same way the compact view is -- including leetspeak, which
        # rewrites digits -- so the two sides stay comparable.
        compact_token = re.sub(r"[^a-z0-9]", "", token.lower().translate(LEET))
        if compact_token and compact_token in normalize(text).compact:
            return [
                Finding(
                    detector=self.name,
                    category=OwaspCategory.LLM06_INFO_DISCLOSURE,
                    severity=Severity.CRITICAL,
                    confidence=0.95,
                    message="Canary token leaked in obfuscated form",
                    direction=ctx.direction,
                    metadata={"rule_id": "canary-obfuscated", "unredactable": True},
                )
            ]
        return []


class SecretDetector(Detector):
    """Credentials with a recognizable shape."""

    name = "secrets"
    stage = 0
    directions = (Direction.OUTBOUND,)

    async def inspect(self, ctx: InspectionContext) -> list[Finding]:
        text = ctx.text[:MAX_SCAN_CHARS]
        return [
            _finding(
                self.name,
                sig,
                matches,
                ctx,
                confidence=(sig.confidence if corroborated else sig.uncorroborated_confidence),
            )
            for sig, matches, corroborated in _scan(text, SECRETS)
        ]


class PIIDetector(Detector):
    """Personal data in a model response.

    Everything here is calibrated to *not* fire the gateway on its own. One
    support email address is ordinary; an email plus a phone number plus a
    date of birth in one answer is a record being read out, and noisy-OR is
    what turns that combination into a sanitize.
    """

    name = "pii"
    stage = 0
    directions = (Direction.OUTBOUND,)

    async def inspect(self, ctx: InspectionContext) -> list[Finding]:
        if not settings.detect_pii:
            return []

        text = ctx.text[:MAX_SCAN_CHARS]
        findings: list[Finding] = []

        for sig, matches, corroborated in _scan(text, PII):
            if not corroborated:
                # The shape matched but the sentence did not back it up. Worth
                # a line in the audit log, not worth rewriting the answer.
                findings.append(
                    _finding(
                        self.name,
                        sig,
                        matches,
                        ctx,
                        confidence=sig.uncorroborated_confidence,
                        severity=Severity.LOW,
                    )
                )
                continue
            # A second occurrence of the same kind is mildly corroborating; a
            # tenth is not ten times the evidence, so the bump saturates.
            bump = min(0.1 * (len(matches) - 1), 0.2)
            findings.append(
                _finding(
                    self.name,
                    sig,
                    matches,
                    ctx,
                    confidence=min(sig.confidence + bump, 0.95),
                )
            )

        cards = find_card_numbers(text)
        if cards:
            findings.append(
                Finding(
                    detector=self.name,
                    category=OwaspCategory.LLM06_INFO_DISCLOSURE,
                    severity=Severity.HIGH,
                    confidence=0.85,
                    message=(
                        "Payment card number in response"
                        if len(cards) == 1
                        else f"Payment card number in response ({len(cards)} occurrences)"
                    ),
                    direction=ctx.direction,
                    evidence=cards[0],
                    metadata={"rule_id": "payment-card", "matches": cards},
                )
            )

        return findings


class SystemPromptLeakDetector(Detector):
    """Verbatim runs of the tenant's own system prompt in the answer.

    The canary catches a full disclosure. This catches a partial one -- a model
    that paraphrases most of its instructions but reproduces one distinctive
    sentence intact, or a tenant running with the canary disabled.

    Word shingles rather than substring search, so reformatting (markdown
    bullets, changed punctuation, collapsed whitespace) does not defeat it.
    """

    name = "system-prompt-leak"
    stage = 0
    directions = (Direction.OUTBOUND,)

    # Long enough that ordinary sentences do not collide by chance, short
    # enough to catch a single leaked instruction.
    SHINGLE = 8

    async def inspect(self, ctx: InspectionContext) -> list[Finding]:
        prompt = (ctx.system_prompt or "").strip()
        if not prompt:
            return []

        prompt_words = _words(prompt)
        answer_words = _words(ctx.text[:MAX_SCAN_CHARS])
        if len(prompt_words) < self.SHINGLE or len(answer_words) < self.SHINGLE:
            return []

        prompt_shingles = _shingles(prompt_words, self.SHINGLE)
        answer_shingles = _shingles(answer_words, self.SHINGLE)
        overlap = prompt_shingles & answer_shingles
        if not overlap:
            return []

        # Share of the system prompt reproduced, not share of the answer: a
        # long answer that happens to contain the whole prompt is still a full
        # leak.
        ratio = len(overlap) / len(prompt_shingles)
        confidence = min(0.6 + ratio, 0.93)
        leaked = " ".join(next(iter(overlap)))

        return [
            Finding(
                detector=self.name,
                category=OwaspCategory.LLM06_INFO_DISCLOSURE,
                severity=Severity.HIGH if ratio >= 0.3 else Severity.MEDIUM,
                confidence=round(confidence, 3),
                message=(f"Response reproduces {ratio:.0%} of the system prompt verbatim"),
                direction=ctx.direction,
                evidence=leaked[:200],
                metadata={
                    "rule_id": "system-prompt-overlap",
                    "overlap_ratio": round(ratio, 3),
                },
            )
        ]


def _words(text: str) -> list[str]:
    return re.findall(r"[a-z0-9']+", text.lower())


def _shingles(words: list[str], size: int) -> set[tuple[str, ...]]:
    return {tuple(words[i : i + size]) for i in range(len(words) - size + 1)}
