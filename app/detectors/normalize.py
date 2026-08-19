"""Text normalization applied before any rule matches.

Attackers do not send "ignore previous instructions" verbatim. They send it
zero-width-padded, letter-spaced, homoglyph-substituted, or leetspeak-encoded.
Normalizing first means one rule covers a whole family of evasions instead of
each rule growing its own tangle of optional characters.

Everything here is cheap string work -- it runs on every request.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

# Zero-width and bidirectional-control characters: invisible to the reader,
# but they break naive substring matching.
INVISIBLE = dict.fromkeys(
    [
        0x00AD,  # soft hyphen
        0x200B,  # zero-width space
        0x200C,  # zero-width non-joiner
        0x200D,  # zero-width joiner
        0x200E,  # left-to-right mark
        0x200F,  # right-to-left mark
        0x2060,  # word joiner
        0xFEFF,  # zero-width no-break space
    ]
    + list(range(0x202A, 0x202F))  # bidi embedding/override
    + list(range(0x2066, 0x206A))  # bidi isolates
)

# Cyrillic/Greek lookalikes that render identically to Latin in most fonts.
HOMOGLYPHS = str.maketrans(
    {
        "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
        "і": "i", "ѕ": "s", "ԁ": "d", "һ": "h", "ӏ": "l", "ν": "v", "ο": "o",
        "α": "a", "ρ": "p", "τ": "t", "ϲ": "c", "ѵ": "v", "ｅ": "e",
    }
)

# Applied only to the extra "aggressive" view, never to the text a human reads.
LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})

_WHITESPACE = re.compile(r"\s+")
# "i g n o r e   a l l" -- single letters separated by spaces or punctuation.
_LETTER_SPACED = re.compile(r"\b(?:[a-z][\s._\-*]){3,}[a-z]\b")
_REPEATED_PUNCT = re.compile(r"([^\w\s])\1{3,}")


@dataclass(slots=True)
class NormalizedText:
    """Several views of the same input; rules match against all of them.

    A hit on any view counts, but `evidence` is always taken from the original
    so redaction and audit logs show what the attacker actually sent.
    """

    original: str
    basic: str
    aggressive: str
    # All separators removed. Rules compile with flexible gaps so a pattern
    # written "ignore all rules" still matches "i g n o r e a l l r u l e s".
    compact: str = ""
    # Signals worth reporting on their own -- an invisible character in a support
    # chat message is itself suspicious, whatever the text says.
    invisible_chars: int = 0
    homoglyphs: int = 0
    letter_spacing: bool = False

    @property
    def views(self) -> tuple[str, str, str]:
        return (self.basic, self.aggressive, self.compact)


def _collapse_letter_spacing(text: str) -> str:
    def join(match: re.Match[str]) -> str:
        return re.sub(r"[\s._\-*]", "", match.group(0))

    return _LETTER_SPACED.sub(join, text)


def normalize(text: str) -> NormalizedText:
    """Produce the matching views. Cost is a few microseconds per KB."""
    invisible = sum(1 for ch in text if ord(ch) in INVISIBLE)
    stripped = text.translate(INVISIBLE)

    # NFKC folds fullwidth and styled-unicode variants back to plain ASCII.
    folded = unicodedata.normalize("NFKC", stripped).lower()

    de_homoglyphed = folded.translate(HOMOGLYPHS)
    homoglyphs = sum(1 for a, b in zip(folded, de_homoglyphed, strict=False) if a != b)

    basic = _WHITESPACE.sub(" ", _REPEATED_PUNCT.sub(r"\1", de_homoglyphed)).strip()

    collapsed = _collapse_letter_spacing(basic)
    aggressive = _WHITESPACE.sub(" ", collapsed.translate(LEET)).strip()

    return NormalizedText(
        original=text,
        basic=basic,
        aggressive=aggressive,
        compact=re.sub(r"[^a-z0-9]", "", aggressive),
        invisible_chars=invisible,
        homoglyphs=homoglyphs,
        letter_spacing=collapsed != basic,
    )
