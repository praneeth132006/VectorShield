"""Token estimation for budget accounting (OWASP LLM04).

A token budget has to be charged *before* the model runs, and at that point
nobody knows what the real count will be -- not even the provider, since the
completion does not exist yet. So the gateway estimates up front, then
reconciles against the provider's own `usage` block once the answer comes back.
Over a minute-long window the estimate's error washes out; what matters is that
a client cannot spend an unbounded amount before anyone notices.

The estimator is deliberately dependency-free. `tiktoken` would be more
accurate for OpenAI models and simply wrong for everything else -- Llama,
Mistral, and Claude all tokenize differently -- and pulling a 2MB vocabulary
onto the hot path to improve a pre-flight guess that gets corrected seconds
later is a bad trade. The heuristic below is within roughly 10-15% on English
prose, which is the accuracy a budget check actually needs.

Where the estimate is wrong it errs high, because a budget that
under-charges is a budget an attacker can walk through.
"""

from __future__ import annotations

import re

# Average characters per token for English text under BPE vocabularies. The
# real figure sits near 4.0; 3.7 is used so ordinary prose charges slightly
# high rather than slightly low.
CHARS_PER_TOKEN = 3.7

# Per-message framing (role markers, separators) that every chat API adds on
# top of the content itself.
TOKENS_PER_MESSAGE = 4

# CJK text has no whitespace and tokenizes far denser than Latin script --
# roughly one token per character rather than one per four.
_CJK = re.compile(r"[぀-ヿ㐀-䶿一-鿿豈-﫿ｦ-ﾟ가-힯]")

# Runs of punctuation, digits, and symbols fragment into many more tokens than
# their character count suggests: "!!!!!!!!" is not two tokens.
_DENSE = re.compile(r"[^\w\s]|[0-9]")


def estimate_tokens(text: str) -> int:
    """Estimate the token count of a string. Never returns less than 1 for
    non-empty input, so an empty budget cannot be bypassed with tiny requests."""
    if not text:
        return 0

    cjk = len(_CJK.findall(text))
    dense = len(_DENSE.findall(text))
    # CJK characters are charged per character and removed from the pool that
    # gets the cheaper chars-per-token rate.
    plain = max(0, len(text) - cjk)

    estimate = (plain / CHARS_PER_TOKEN) + cjk + (dense * 0.25)
    return max(1, int(estimate))


def estimate_messages(messages: list[tuple[str, str]]) -> int:
    """Estimate prompt tokens for a conversation of (role, text) pairs."""
    total = 0
    for role, text in messages:
        total += TOKENS_PER_MESSAGE + estimate_tokens(role) + estimate_tokens(text)
    return total
