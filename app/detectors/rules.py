"""Stage 0: rule-based prompt-injection detection (OWASP LLM01).

This layer must settle the overwhelming majority of traffic in microseconds so
the classifier never sees it. Rules are deliberately conservative: a pattern
that also appears in ordinary customer conversation gets a low confidence, or it
does not ship at all. False positives break real products.

Every pattern is written with plain spaces and compiled with flexible gaps, so
one rule survives spacing, punctuation, and zero-width evasion.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import re
from dataclasses import dataclass

from app.detectors.base import Detector, InspectionContext
from app.detectors.normalize import NormalizedText, normalize
from app.models.schemas import Direction, Finding, OwaspCategory, Severity

# A literal space in a pattern becomes "any run of separators, or none", which
# is what makes "i g n o r e   a l l" match a rule written "ignore all".
_GAP = r"[\s\W_]{0,4}"


@dataclass(frozen=True, slots=True)
class Patterns:
    """One rule, compiled for the ordinary views and for the compact view.

    The compact view has every separator stripped ("ignoreallpreviousrules"), so
    word-boundary anchors can never match inside it. The compact variant drops
    them. That is safe because a compact match still requires the full
    multi-word phrase to be present in order.
    """

    standard: re.Pattern[str]
    compact: re.Pattern[str]


def _flex(pattern: str) -> Patterns:
    # A space directly before a quantifier would expand into a doubled repeat.
    # Write "\s*" explicitly in that case rather than relying on a literal space.
    if re.search(r" [*+?{]", pattern):
        raise ValueError(f"rule pattern has a space before a quantifier: {pattern!r}")
    return Patterns(
        standard=re.compile(pattern.replace(" ", _GAP), re.IGNORECASE),
        compact=re.compile(pattern.replace(" ", _GAP).replace(r"\b", ""), re.IGNORECASE),
    )


def _exact(pattern: re.Pattern[str]) -> Patterns:
    """A rule whose structure would be destroyed by separator-flexible matching."""
    return Patterns(standard=pattern, compact=pattern)


@dataclass(frozen=True, slots=True)
class Rule:
    id: str
    patterns: Patterns
    severity: Severity
    confidence: float
    message: str
    category: OwaspCategory = OwaspCategory.LLM01_PROMPT_INJECTION


# ---------------------------------------------------------------------------
# The rule table.
#
# Confidence calibration, roughly:
#   0.90+  I would stake a block on this. No benign reading exists.
#   0.70   Strongly suspicious, but a determined edge case could be innocent.
#   0.45   A real signal that must be corroborated before it means anything.
# ---------------------------------------------------------------------------

RULES: tuple[Rule, ...] = (
    # --- Direct instruction override ---------------------------------------
    Rule(
        "instruction-override",
        _flex(
            r"\b(?:ignore|disregard|forget|discard|override|bypass|skip)\b[\s\S]{0,30}?"
            r"\b(?:all |any |the |your |these |those )*"
            r"(?:previous|prior|preceding|above|earlier|initial|original|system|prompt)\b"
            r"[\s\S]{0,20}?"
            r"\b(?:instruction|instructions|prompt|prompts|rule|rules|direction|directions|"
            r"command|commands|guideline|guidelines|constraint|constraints|context)\b"
        ),
        Severity.CRITICAL,
        0.95,
        "Direct instruction-override attempt",
    ),
    Rule(
        "instruction-override-short",
        _flex(
            r"\b(?:ignore|disregard|forget) (?:all |everything |your )*"
            r"(?:above|previous|prior)\b"
        ),
        Severity.HIGH,
        0.85,
        "Shorthand instruction-override phrasing",
    ),
    Rule(
        "new-instructions",
        _flex(
            r"\b(?:new|updated|revised|real|actual|true) (?:instruction|instructions|"
            r"system prompt|directive|directives|rules)\b[\s\S]{0,15}?[:\-]"
        ),
        Severity.HIGH,
        0.75,
        "Claims to supply replacement instructions",
    ),
    # --- Persona / jailbreak framing ---------------------------------------
    Rule(
        "dan-jailbreak",
        _flex(
            r"\b(?:you are|act as|pretend to be|roleplay as|simulate|become)\b[\s\S]{0,40}?"
            r"\b(?:dan|do anything now|stan|dude|aim|developer mode|dev mode|jailbroken|"
            r"unfiltered|uncensored|unrestricted|evil|opposite mode)\b"
        ),
        Severity.CRITICAL,
        0.93,
        "Known jailbreak persona pattern (DAN-family)",
    ),
    Rule(
        "no-restrictions-persona",
        _flex(
            r"\b(?:you|your responses?|the ai)\b[\s\S]{0,40}?"
            r"\b(?:have no|has no|without any|free of|no longer have|are not bound by|"
            r"are free from)\b[\s\S]{0,20}?"
            r"\b(?:restriction|restrictions|limitation|limitations|filter|filters|rule|rules|"
            r"guideline|guidelines|policy|policies|ethic|ethics|moral|morals)\b"
        ),
        Severity.CRITICAL,
        0.9,
        "Attempts to declare the model unrestricted",
    ),
    Rule(
        "developer-mode",
        _flex(
            r"\b(?:developer|debug|god|admin|root|maintenance|sudo) mode\b"
            r"[\s\S]{0,20}?(?:enabled|on|activated|:)"
        ),
        Severity.HIGH,
        0.85,
        "Fabricated privileged-mode activation",
    ),
    Rule(
        "authority-spoof",
        _flex(
            r"\b(?:i am|this is|as) (?:your |the )?(?:developer|creator|administrator|admin|"
            r"openai|anthropic|engineer|owner)\b[\s\S]{0,30}?"
            r"\b(?:override|disable|turn off|unlock|grant|authorize|permission)\b"
        ),
        Severity.HIGH,
        0.82,
        "Impersonates an authority to unlock behavior",
    ),
    # --- System prompt extraction (feeds LLM06) -----------------------------
    Rule(
        "system-prompt-extraction",
        _flex(
            r"\b(?:what|show|print|repeat|reveal|output|display|tell me|give me|list|"
            r"echo|dump|recite)\b[\s\S]{0,30}?"
            r"\b(?:your |the |all )*(?:system prompt|initial prompt|original prompt|"
            r"system message|initial instructions|original instructions|prompt template|"
            r"configuration|hidden instructions)\b"
        ),
        Severity.HIGH,
        0.88,
        "Attempts to extract the system prompt",
    ),
    Rule(
        "verbatim-context-dump",
        _flex(
            r"\b(?:repeat|print|output|echo|reproduce|write out)\b[\s\S]{0,25}?"
            r"\b(?:everything|all (?:the )?text|the text|words|content|tokens)\b"
            r"[\s\S]{0,25}?\b(?:above|before this|preceding|prior to|so far)\b"
        ),
        Severity.HIGH,
        0.85,
        "Requests a verbatim dump of preceding context",
    ),
    # --- Structural / delimiter injection ------------------------------------
    Rule(
        "chat-template-injection",
        _exact(
            re.compile(
                r"(<\|(?:im_start|im_end|system|user|assistant|endoftext|eot_id"
                r"|start_header_id)\|>"
                r"|\[/?INST\]|<<SYS>>|###\s*(?:System|Instruction)\s*:"
                r"|\bassistant\s*:\s*$)",
                re.IGNORECASE | re.MULTILINE,
            )
        ),
        Severity.CRITICAL,
        0.92,
        "Chat-template control tokens in user input",
    ),
    Rule(
        "fake-system-turn",
        _exact(
            re.compile(
                r"(?:^|\n)\s*(?:\[|<|\{)?\s*(?:system|assistant)\s*(?:\]|>|\})?\s*:\s",
                re.IGNORECASE,
            )
        ),
        Severity.MEDIUM,
        0.6,
        "User input impersonates a system turn",
    ),
    # --- Refusal suppression -------------------------------------------------
    Rule(
        "refusal-suppression",
        _flex(
            r"\b(?:do not|don't|never|you must not|refrain from)\b[\s\S]{0,25}?"
            r"\b(?:refuse|say no|apologize|warn|decline|mention|reveal)\b[\s\S]{0,30}?"
            r"\b(?:cannot|can't|unable|policy|guidelines|restrictions|limitations|ai)\b"
        ),
        Severity.HIGH,
        0.8,
        "Attempts to suppress refusals",
    ),
    Rule(
        "answer-compulsion",
        _flex(
            r"\byou (?:must|have to|will|shall) (?:answer|comply|respond|obey|do)\b"
            r"[\s\S]{0,30}?\b(?:no matter what|regardless|whatever it takes|always"
            r"|without exception)\b"
        ),
        Severity.MEDIUM,
        0.62,
        "Coercive compliance framing",
    ),
    # --- Payload smuggling ----------------------------------------------------
    Rule(
        "indirect-execution",
        _flex(
            r"\b(?:decode|translate|decrypt|unscramble|reverse|execute|run|interpret)\b"
            r"[\s\S]{0,40}?\b(?:and (?:then )?(?:follow|do|obey|execute|comply|apply)"
            r"|then follow|and act on)\b"
        ),
        Severity.HIGH,
        0.82,
        "Instructs the model to decode then obey a payload",
    ),
    Rule(
        "hypothetical-bypass",
        _flex(
            r"\b(?:hypothetically|in a fictional|for a (?:story|novel|movie|game)|"
            r"imagine (?:a world|that you)|in an alternate)\b[\s\S]{0,60}?"
            r"\b(?:no rules|no restrictions|anything is allowed|nothing is forbidden|"
            r"ai has no|without ethics|illegal)\b"
        ),
        Severity.MEDIUM,
        0.65,
        "Fictional framing used to bypass policy",
    ),
)


# ---------------------------------------------------------------------------
# Encoded-payload handling
# ---------------------------------------------------------------------------

_B64 = re.compile(r"\b[A-Za-z0-9+/]{24,}={0,2}\b")
_HEX = re.compile(r"\b(?:[0-9a-fA-F]{2}[\s:]?){12,}\b")


def _decode_candidates(text: str) -> list[tuple[str, str]]:
    """Return (scheme, decoded) for payloads worth re-scanning.

    Only decodings that yield mostly-printable text are returned -- random
    base64-looking identifiers decode to noise and are dropped.
    """
    out: list[tuple[str, str]] = []

    for match in _B64.finditer(text):
        blob = match.group(0)
        try:
            raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True)
            decoded = raw.decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        if _is_texty(decoded):
            out.append(("base64", decoded))

    for match in _HEX.finditer(text):
        blob = re.sub(r"[\s:]", "", match.group(0))
        if len(blob) % 2:
            continue
        try:
            decoded = bytes.fromhex(blob).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        if _is_texty(decoded):
            out.append(("hex", decoded))

    # ROT13 is cheap enough to always try; it only matters if it reveals a rule hit.
    rotated = codecs.encode(text, "rot_13")
    if rotated != text:
        out.append(("rot13", rotated))

    return out


def _is_texty(decoded: str) -> bool:
    if len(decoded) < 8:
        return False
    printable = sum(1 for ch in decoded if ch.isprintable() or ch.isspace())
    return printable / len(decoded) > 0.85


# ---------------------------------------------------------------------------
# Detectors
# ---------------------------------------------------------------------------


def match_rules(norm: NormalizedText) -> list[tuple[Rule, str]]:
    """Run every rule against every normalized view; return (rule, evidence)."""
    hits: list[tuple[Rule, str]] = []
    for rule in RULES:
        for view, pattern in (
            (norm.basic, rule.patterns.standard),
            (norm.aggressive, rule.patterns.standard),
            (norm.compact, rule.patterns.compact),
        ):
            found = pattern.search(view)
            if found:
                hits.append((rule, found.group(0)[:200]))
                break  # one hit per rule; the views are the same text
    return hits


class RuleDetector(Detector):
    """The always-on stage 0 layer."""

    name = "rules"
    stage = 0
    directions = (Direction.INBOUND,)

    async def inspect(self, ctx: InspectionContext) -> list[Finding]:
        norm = normalize(ctx.text)
        findings: list[Finding] = []

        for rule, evidence in match_rules(norm):
            findings.append(
                Finding(
                    detector=self.name,
                    category=rule.category,
                    severity=rule.severity,
                    confidence=rule.confidence,
                    message=rule.message,
                    direction=ctx.direction,
                    evidence=evidence,
                    metadata={"rule_id": rule.id},
                )
            )
        return findings


class ObfuscationDetector(Detector):
    """Flags evasion machinery itself, independent of what the text says.

    Invisible characters in a support-chat message are suspicious on their own.
    On its own this rarely blocks; combined with a rule hit, noisy-OR pushes the
    request over the line.
    """

    name = "obfuscation"
    stage = 0
    directions = (Direction.INBOUND,)

    async def inspect(self, ctx: InspectionContext) -> list[Finding]:
        norm = normalize(ctx.text)
        findings: list[Finding] = []

        if norm.invisible_chars >= 3:
            findings.append(
                Finding(
                    detector=self.name,
                    category=OwaspCategory.LLM01_PROMPT_INJECTION,
                    severity=Severity.MEDIUM,
                    confidence=min(0.5 + norm.invisible_chars * 0.05, 0.8),
                    message=f"{norm.invisible_chars} zero-width or bidi control characters",
                    direction=ctx.direction,
                    metadata={"invisible_chars": str(norm.invisible_chars)},
                )
            )

        if norm.homoglyphs >= 3:
            findings.append(
                Finding(
                    detector=self.name,
                    category=OwaspCategory.LLM01_PROMPT_INJECTION,
                    severity=Severity.LOW,
                    confidence=0.5,
                    message=f"{norm.homoglyphs} non-Latin homoglyph substitutions",
                    direction=ctx.direction,
                    metadata={"homoglyphs": str(norm.homoglyphs)},
                )
            )

        if norm.letter_spacing:
            findings.append(
                Finding(
                    detector=self.name,
                    category=OwaspCategory.LLM01_PROMPT_INJECTION,
                    severity=Severity.LOW,
                    confidence=0.45,
                    message="Letter-spacing obfuscation",
                    direction=ctx.direction,
                )
            )

        return findings


class EncodedPayloadDetector(Detector):
    """Decodes base64/hex/rot13 payloads and re-runs the rules on the result.

    A hit here is high-confidence by construction: benign text does not happen
    to base64-decode into an instruction override.
    """

    name = "encoded-payload"
    stage = 0
    directions = (Direction.INBOUND,)

    async def inspect(self, ctx: InspectionContext) -> list[Finding]:
        findings: list[Finding] = []

        for scheme, decoded in _decode_candidates(ctx.text):
            hits = match_rules(normalize(decoded))
            for rule, evidence in hits:
                findings.append(
                    Finding(
                        detector=self.name,
                        category=rule.category,
                        severity=Severity.CRITICAL,
                        confidence=min(rule.confidence + 0.03, 0.99),
                        message=f"{scheme}-encoded payload contains: {rule.message.lower()}",
                        direction=ctx.direction,
                        evidence=evidence,
                        metadata={"scheme": scheme, "rule_id": rule.id},
                    )
                )
        return findings
