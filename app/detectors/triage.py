"""Cheap triage: decides which requests deserve an expensive second look.

The rule layer is high-precision and low-recall by design, so a request that
fires no rule is not thereby clean -- it is merely unmatched. Escalating on rule
silence alone would send everything to the classifier; escalating on nothing
would mean the classifier never runs. Neither is right.

Triage is the missing third thing: a deliberately loose, microsecond-scale
signal that answers one question -- "is this ordinary product traffic, or is it
talking about the assistant, its instructions, or its constraints?" It is meant
to over-trigger. Its precision does not matter; only its recall and its cost do,
because everything it selects is then judged by a real detector.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from app.detectors.normalize import normalize

# Vocabulary that ordinary product questions rarely reach for, but that almost
# every injection attempt needs in order to talk about the model itself.
_META_TERMS = re.compile(
    # Deliberately excludes bare "policy", "system", and "training": "return
    # policy", "system requirements", and "training materials" are among the most
    # common things a real customer says. The model-specific phrases are listed
    # explicitly instead.
    r"\b(?:instruction|instructions|prompt|prompts|rule|rules|guideline|guidelines|"
    r"restriction|restrictions|constraint|constraints|filter|filters|"
    r"jailbreak|jailbroken|unrestricted|unfiltered|uncensored|persona|roleplay|"
    r"pretend|simulate|override|bypass|disregard|ignore|forget|reveal|disclose|"
    r"system prompt|system message|system instructions|content policy|safety policy|"
    r"developer mode|dan|ai model|language model|guardrail|guardrails"
    # German, Spanish, and French equivalents. Injection attempts are not written
    # in English just because the product's documentation is.
    r"|anweisung|anweisungen|anleitung|vorgabe|vorgaben|regel|regeln|"
    r"ignoriere|ignorieren|vergiss|vergessen|missachte|obigen|obige|vorherige|"
    r"stattdessen|tue so|verhalte dich|du bist jetzt|"
    r"instruccion|instrucciones|reglas|ignora|olvida|finge|actua como|"
    r"consigne|consignes|regles|ignore[sz]|oublie|fais semblant|agis comme)\b",
    re.IGNORECASE,
)

# Second-person imperatives aimed at the assistant's behavior.
_DIRECTIVES = re.compile(
    r"\b(?:you are|you're|you must|you will|you shall|you should|you can now|"
    r"from now on|act as|behave as|respond as|answer as|function as|"
    r"instead (?:of|write|say|answer|tell)|rather than (?:answering|responding)|"
    r"despite what|regardless of what|no matter what|"
    r"your (?:new |real |true )?(?:instruction|instructions|rule|rules|purpose|"
    r"role|task|prompt))\b",
    re.IGNORECASE,
)

# Abrupt conversational pivots: a second, contradictory command bolted onto an
# innocent-looking question. This is what indirect injection usually looks like.
_PIVOT = re.compile(
    r"(?:^|[.!?\n])\s*(?:stop|halt|wait|attention|achtung|stopp|warning|urgent|"
    r"important|note)\b[\s\W]{0,4}(?:[-:,]|\b)",
    re.IGNORECASE,
)

# Structural oddities: fake turn markers, control tokens, long payload blobs.
_STRUCTURAL = re.compile(
    r"(<\|[^|>]{1,32}\|>|\[/?INST\]|<<SYS>>|^\s*(?:system|assistant|user)\s*:|"
    r"###\s*\w+\s*:|\b[A-Za-z0-9+/]{40,}={0,2}\b)",
    re.IGNORECASE | re.MULTILINE,
)

# A question followed by a command is the classic "innocent wrapper" shape.
_IMPERATIVE_AFTER_QUESTION = re.compile(
    r"\?[\s\S]{0,40}\b(?:write|say|tell|print|output|answer|respond|make|create|"
    r"generate|schreibe|sage|antworte|nenne)\b",
    re.IGNORECASE,
)

# Shouted imperatives. Normal chat does not sustain three all-caps words.
_SHOUTED_IMPERATIVE = re.compile(r"\b[A-Z]{2,}(?:[\s\W]+[A-Z]{2,}){2,}\b")

# Blank-line padding used to push earlier instructions out of the model's view.
_PADDING = re.compile(r"(?:\r?\n[ \t]*){4,}")

# Retrieval scaffolding: an attacker framing their text as the document the
# assistant should trust. Classic indirect injection, in several languages.
_DOCUMENT_SCAFFOLD = re.compile(
    r"\b(?:document|context|kontext|contexto|contexte|passage|source|retrieved)\b"
    r"[\s\W]{0,4}(?:context|frage|question|pregunta|:|\")",
    re.IGNORECASE,
)

LONG_INPUT_CHARS = 2_000


@dataclass(frozen=True, slots=True)
class TriageResult:
    escalate: bool
    reasons: tuple[str, ...] = ()

    @property
    def summary(self) -> str:
        return ", ".join(self.reasons)


def triage(text: str) -> TriageResult:
    """Return whether this input is worth a deeper (more expensive) look."""
    if not text.strip():
        return TriageResult(False)

    view = normalize(text).basic
    reasons: list[str] = []

    if _META_TERMS.search(view):
        reasons.append("meta-language about the assistant or its rules")
    if _DIRECTIVES.search(view):
        reasons.append("second-person directive to the assistant")
    if _STRUCTURAL.search(text):
        reasons.append("structural markers or an encoded blob")
    if _PIVOT.search(view):
        reasons.append("abrupt imperative pivot mid-message")
    if view.count("?") >= 1 and _IMPERATIVE_AFTER_QUESTION.search(view):
        reasons.append("command appended after a question")
    if _SHOUTED_IMPERATIVE.search(text):
        reasons.append("sustained all-caps imperative")
    if _PADDING.search(text):
        reasons.append("blank-line padding")
    if _DOCUMENT_SCAFFOLD.search(text):
        reasons.append("retrieval/document scaffolding")
    if len(text) > LONG_INPUT_CHARS:
        # Long inputs are where instructions get buried mid-document.
        reasons.append("unusually long input")

    return TriageResult(bool(reasons), tuple(reasons))
