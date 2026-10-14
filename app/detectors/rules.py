"""Stage 0 rule-based prompt-injection detector (OWASP LLM01).

Pure regex/structural checks over normalised text. Severity and confidence are
chosen against the Decision Engine's maths (confidence x severity weight, noisy-OR):

  CRITICAL @ 0.90 -> 0.90  (>= block threshold 0.85: blocks on its own)
  HIGH     @ 0.80 -> 0.68  (flags on its own)
  MEDIUM   @ 0.60 -> 0.36  (below flag alone; two weak signals together reach ~0.59)
"""

from __future__ import annotations

import base64
import binascii
import codecs
import re
import unicodedata
from dataclasses import dataclass
from typing import ClassVar

from app.detectors._util import make_finding
from app.detectors.base import Detector, InspectionContext
from app.models.schemas import Direction, Finding, Severity

MAX_SCAN_CHARS = 20_000

_INVISIBLE = re.compile("[\u200b-\u200d\u2060\ufeff\u202a-\u202e\u2066-\u2069]")
# ZWJ/ZWNJ appear legitimately (emoji, Persian), so only these count as suspicious.
_SUSPICIOUS_INVISIBLE = re.compile("[\u200b\u2060\ufeff\u202a-\u202e\u2066-\u2069]")
_WS = re.compile(r"\s+")
_B64 = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")


def normalize(text: str) -> str:
    """NFKC-fold, drop invisible characters, collapse whitespace, lowercase."""
    folded = unicodedata.normalize("NFKC", text)
    folded = _INVISIBLE.sub("", folded)
    return _WS.sub(" ", folded).lower().strip()


@dataclass(frozen=True, slots=True)
class Rule:
    rule_id: str
    pattern: re.Pattern[str]
    severity: Severity
    confidence: float
    message: str


_V = r"(?:ignore|disregard|forget|discard)"
_Q = (
    r"(?:all|any|every|previous|prior|above|earlier|preceding|former|your|system|"
    r"initial|original|safety|these|those)"
)
_N = (
    r"(?:instructions?|prompts?|rules?|guidelines?|directions?|programming|"
    r"restrictions?|constraints?|commands?)"
)
_GAP = r"(?:\w+\W+)"

_OVERRIDE = re.compile(rf"\b{_V}\W+{_GAP}{{0,3}}?{_Q}\W+{_GAP}{{0,2}}?{_N}\b")

_EMBEDDED_INSTRUCTIONS = re.compile(
    r"\b(?:follow|obey|execute|carry out)\W+"
    r"(?:(?:any|all|the)\W+)?"
    r"(?:(?:malicious|hidden|embedded)\W+)?"
    r"(?:instructions?|commands?|directions?)\W+"
    r"(?:(?:(?:you\W+)?(?:find|found|read|encounter|see))|"
    r"(?:embedded|hidden|contained|written|included))?\W+"
    r"(?:in|from|inside|within|on)\W+"
    r"(?:(?:the|this|that|a|an)\W+)?(?:webpage|website|web\W+page|page|email|e-mail|"
    r"document|attachment|file|quoted\W+text|quoted\W+content)\b"
)

_EDUCATIONAL_CONTEXT = re.compile(
    r"\b(?:explain|analyze|classify|describe|discuss|teach|summarize)\b"
)
_EDUCATIONAL_SUBJECT = re.compile(
    r"\b(?:prompt\W+injection|security\W+(?:class|training)|attack|example|"
    r"phrase|quoted|quotation|instruction)\b"
)
_QUOTE_PAIRS = (
    (chr(34), chr(34)),
    (chr(39), chr(39)),
    (chr(0x201C), chr(0x201D)),
    (chr(0x2018), chr(0x2019)),
)


def _is_quoted_educational_mention(text: str, start: int, end: int) -> bool:
    """Ignore a quoted rule match only when the surrounding request discusses it."""
    opening: tuple[int, str, str] | None = None
    for left, right in _QUOTE_PAIRS:
        index = text.rfind(left, 0, start)
        if index >= 0 and (opening is None or index > opening[0]):
            opening = (index, left, right)
    if opening is None:
        return False

    opening_index, _left, right = opening
    closing_index = text.find(right, end)
    if closing_index < 0:
        return False

    context = text[:opening_index] + " " + text[closing_index + len(right) :]
    return bool(_EDUCATIONAL_CONTEXT.search(context) and _EDUCATIONAL_SUBJECT.search(context))


RULES: tuple[Rule, ...] = (
    Rule(
        "override_instructions",
        _OVERRIDE,
        Severity.CRITICAL,
        0.90,
        "attempt to override or discard prior instructions",
    ),
    Rule(
        "forget_everything",
        re.compile(
            rf"\b{_V}\W+(?:everything|all)\W+(?:above|before|prior|previously|"
            r"you were told|you have been told|that came before)\b"
        ),
        Severity.HIGH,
        0.80,
        "attempt to wipe earlier context",
    ),
    Rule(
        "system_prompt_extraction",
        re.compile(
            r"\b(?:reveal|show|print|repeat|display|output|leak|expose|disclose|tell me|"
            r"give me|share|dump|recite)\W+(?:\w+\W+){0,4}?"
            r"(?:system|initial|hidden|secret|developer|internal)\W+"
            r"(?:prompt|instructions?|message|rules)\b"
            r"|\bwhat (?:is|are|were)\W+(?:your|the)\W+"
            r"(?:system|initial|hidden|secret)\W+(?:prompt|instructions?)\b"
        ),
        Severity.HIGH,
        0.85,
        "attempt to extract the system prompt",
    ),
    Rule(
        "persona_jailbreak",
        re.compile(
            r"\b(?:do anything now|dan mode|stan mode|dude mode|aim mode|evil confidant|"
            r"jailbroken mode|developer mode (?:enabled|activated|output)|"
            r"(?:you are|you're|act as|pretend to be)\W+(?:now\W+)?dan)\b"
        ),
        Severity.HIGH,
        0.85,
        "known jailbreak persona",
    ),
    Rule(
        "roleplay_no_rules",
        re.compile(
            r"\b(?:you are|you're|act as|pretend\W+(?:to be|you are|you're)|"
            r"from now on\W+you)\b"
            r".{0,100}?\b(?:no|without|free\W+(?:of|from)|not bound by|do not (?:follow|have)|"
            r"don't (?:follow|have))\W+(?:\w+\W+){0,2}?"
            r"(?:rules|restrictions|limitations|filters|guidelines|ethics|censorship|boundaries)\b"
        ),
        Severity.HIGH,
        0.80,
        "role-play framing that removes the rules",
    ),
    Rule(
        "fake_role_delimiters",
        re.compile(
            r"\[/?(?:system|inst|sys)\]|<\|(?:im_start|im_end|system|endoftext)\|>|<<\s*/?sys\s*>>"
        ),
        Severity.HIGH,
        0.80,
        "spoofed chat-template / role delimiters",
    ),
    Rule(
        "safety_bypass",
        re.compile(
            rf"\b(?:override|bypass|circumvent|disable|turn off|remove)\W+{_GAP}{{0,3}}?"
            r"(?:safety|content|ethical|moderation|safeguards?)\W+"
            r"(?:filters?|guidelines?|rules?|restrictions?|policies|policy|protocols?|"
            r"checks?|guardrails?|mode)\b"
        ),
        Severity.HIGH,
        0.75,
        "request to bypass safety controls",
    ),
    Rule(
        "follow_embedded_instructions",
        _EMBEDDED_INSTRUCTIONS,
        Severity.HIGH,
        0.80,
        "request to follow instructions embedded in external content",
    ),
    Rule(
        "jailbreak_keyword",
        re.compile(
            r"\bjailbr(?:eak|oke|oken|eaking)\b"
            r"|\b(?:uncensored|unfiltered)\W+(?:mode|ai|version|response)\b"
            r"|\b(?:without|no)\W+(?:any\W+)?(?:filters?|censorship|"
            r"ethical\W+(?:guidelines|constraints))\b"
        ),
        Severity.MEDIUM,
        0.60,
        "jailbreak vocabulary (weak signal)",
    ),
    Rule(
        "new_instructions_marker",
        re.compile(
            r"\b(?:new|updated|real|actual|additional|revised)\W+(?:instructions?|task|rules)\s*:"
            r"|\bsystem\s*:\s*(?:you are|ignore|override|new)"
            r"|\bfrom now on\W+(?:you|always|only)\b"
            r"|\bend of (?:the )?(?:system )?(?:prompt|instructions)\b"
        ),
        Severity.MEDIUM,
        0.60,
        "instruction-injection marker (weak signal)",
    ),
)


def _snip(value: str, limit: int = 80) -> str:
    return value if len(value) <= limit else value[:limit] + "..."


def _printable_ratio(text: str) -> float:
    if not text:
        return 0.0
    return sum(1 for c in text if c.isprintable() or c.isspace()) / len(text)


def _decoded_base64(raw: str, limit: int = 5) -> list[str]:
    out: list[str] = []
    for match in _B64.finditer(raw):
        blob = match.group(0).rstrip("=")
        blob += "=" * (-len(blob) % 4)
        try:
            text = base64.b64decode(blob, validate=True).decode("utf-8")
        except (binascii.Error, ValueError):
            continue
        if len(text) >= 12 and _printable_ratio(text) >= 0.9:
            out.append(text)
        if len(out) >= limit:
            break
    return out


class InjectionRulesDetector(Detector):
    name: ClassVar[str] = "injection_rules"
    stage: ClassVar[int] = 0
    directions: ClassVar[tuple[Direction, ...]] = (Direction.INBOUND,)

    def scan(self, text: str) -> list[Finding]:
        """Synchronous core, reused by tests and the evaluation script."""
        raw = text[:MAX_SCAN_CHARS]
        norm = normalize(raw)
        findings: list[Finding] = []

        for rule in RULES:
            match = rule.pattern.search(norm)
            if match and not _is_quoted_educational_mention(norm, *match.span()):
                findings.append(
                    make_finding(
                        detector=self.name,
                        message=f"{rule.rule_id}: {rule.message}",
                        confidence=rule.confidence,
                        severity=rule.severity,
                        evidence=_snip(match.group(0)),
                    )
                )

        for decoded in _decoded_base64(raw):
            decoded_norm = normalize(decoded)
            if _OVERRIDE.search(decoded_norm):
                findings.append(
                    make_finding(
                        detector=self.name,
                        message="encoded_override: base64 payload contains an override",
                        confidence=0.90,
                        severity=Severity.CRITICAL,
                        evidence=_snip(decoded_norm),
                    )
                )
            else:
                findings.append(
                    make_finding(
                        detector=self.name,
                        message="base64_text_blob: long base64 block that decodes to text",
                        confidence=0.50,
                        severity=Severity.MEDIUM,
                    )
                )
            break  # one encoded-payload finding per request is enough

        if _OVERRIDE.search(codecs.decode(norm, "rot_13")):
            findings.append(
                make_finding(
                    detector=self.name,
                    message="rot13_override: ROT13-encoded override phrase",
                    confidence=0.80,
                    severity=Severity.HIGH,
                )
            )

        if len(_SUSPICIOUS_INVISIBLE.findall(raw)) >= 3:
            findings.append(
                make_finding(
                    detector=self.name,
                    message="invisible_characters: several zero-width/bidi characters",
                    confidence=0.50,
                    severity=Severity.MEDIUM,
                )
            )
        return findings

    async def inspect(self, ctx: InspectionContext) -> list[Finding]:
        return self.scan(ctx.text)
