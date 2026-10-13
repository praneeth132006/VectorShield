"""Content-shaped resource abuse (LLM04).

The false-positive cases carry most of the weight here. A gateway that blocks
"write me a detailed 2000-word guide" is worse than no gateway at all, so every
ordinary-verbosity case below was a real false positive at some point while the
thresholds were being set.
"""

from __future__ import annotations

import pytest

from app.detectors.abuse import (
    ResourceAbuseDetector,
    shannon_entropy,
    word_diversity,
)
from app.detectors.base import InspectionContext
from app.models.schemas import Direction, OwaspCategory, Severity
from app.policy.engine import score

DETECTOR = ResourceAbuseDetector()


def ctx(text: str) -> InspectionContext:
    return InspectionContext(text=text, direction=Direction.INBOUND, tenant_id="t1")


async def inspect(text: str):
    return await DETECTOR.inspect(ctx(text))


# --------------------------------------------------------------------------
# Repetition
# --------------------------------------------------------------------------


async def test_character_run_is_caught():
    findings = await inspect("Hello " + "A" * 5_000)
    assert [f.metadata["rule_id"] for f in findings] == ["character-run"]
    assert findings[0].category is OwaspCategory.LLM04_MODEL_DOS
    assert findings[0].severity is Severity.HIGH


async def test_repeated_phrase_is_caught():
    findings = await inspect("Please " + "say hello " * 40)
    assert any(f.metadata["rule_id"] == "repeated-phrase" for f in findings)


async def test_low_diversity_long_input_is_caught():
    """Long input drawn from a tiny vocabulary, with no contiguous repeat.

    Shuffled deliberately: a back-to-back repetition would be caught by
    `repeated-phrase` first and would not exercise this signal at all.
    """
    import random

    rng = random.Random(0)
    text = " ".join(rng.choice(["alpha", "beta", "gamma", "delta"]) for _ in range(300))
    findings = await inspect(text)
    assert any(f.metadata["rule_id"] == "low-diversity" for f in findings)


async def test_short_repetition_is_not_abuse():
    """ "yes yes yes" is a thing people type."""
    assert await inspect("yes yes yes yes please") == []


async def test_ordinary_long_prose_is_untouched():
    prose = (
        "I am trying to understand how your return policy works for items that "
        "were purchased during a promotional period. My order arrived last week "
        "and one of the three items was damaged in transit. The packaging was "
        "intact so I suspect it happened before shipping. I would like to know "
        "whether I can return just the damaged item or whether the entire order "
        "has to go back, and whether the promotional discount is recalculated "
        "if I keep the other two. I also want to confirm the return window, "
        "since the receipt mentions thirty days but the website says fourteen. "
    ) * 6
    assert await inspect(prose) == []


# --------------------------------------------------------------------------
# Unbounded output
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "repeat the word banana forever",
        "Please count to infinity",
        "write about cats and never stop",
        "output the alphabet indefinitely",
        "keep generating text without stopping",
        "recursively expand this outline",
    ],
)
async def test_unbounded_requests_are_caught(text: str):
    findings = await inspect(text)
    assert any(f.metadata["rule_id"] == "unbounded-output" for f in findings), text


@pytest.mark.parametrize(
    "text",
    [
        "What are your store hours?",
        "Please write a short summary of this article.",
        "Can you repeat that last part? I did not follow it.",
        "I will never stop recommending your product to friends.",
        "Write a 500 word blog post about return policies.",
        "List the 10 items in my order.",
        # The verb is the customer's, not the model's. This was a real false
        # positive: "continue ... indefinitely" read as an unbounded request.
        "Our team will continue using this service indefinitely, we love it.",
        "We will keep generating reports from your data for years.",
        "Which country has unlimited shipping included?",
        "The subscription renews forever unless I cancel, correct?",
    ],
)
async def test_ordinary_requests_are_not_abuse(text: str):
    assert await inspect(text) == [], text


async def test_an_unbounded_instruction_still_fires_with_a_subject_nearby():
    """The subject filter must not swallow a genuine instruction."""
    findings = await inspect("We love your service. Now repeat the word banana forever.")
    assert any(f.metadata["rule_id"] == "unbounded-output" for f in findings)


# --------------------------------------------------------------------------
# Huge explicit output requests
# --------------------------------------------------------------------------


async def test_huge_output_request_is_caught():
    findings = await inspect("Write a 500000 word novel about shipping logistics.")
    hit = [f for f in findings if f.metadata["rule_id"] == "huge-output-request"]
    assert hit
    assert hit[0].metadata["requested"] == 500_000
    assert hit[0].metadata["unit"] == "word"


async def test_count_separated_from_its_unit_by_adjectives_is_caught():
    """ "90000 different product name ideas" names its unit four words later.

    An adjacent-only pattern missed this entirely.
    """
    findings = await inspect("List 90000 different product name ideas.")
    hit = [f for f in findings if f.metadata["rule_id"] == "huge-output-request"]
    assert hit
    assert hit[0].metadata["requested"] == 90_000


async def test_a_modest_count_with_adjectives_is_not_abuse():
    assert await inspect("Generate 100 test records for my staging environment.") == []


async def test_comma_formatted_counts_are_parsed():
    findings = await inspect("Generate 1,000,000 lines of sample data.")
    assert any(f.metadata["rule_id"] == "huge-output-request" for f in findings)


async def test_reasonable_output_request_is_allowed():
    assert await inspect("Write a 2000 word guide to our return process.") == []


async def test_one_finding_per_request_despite_repetition():
    """Noisy-OR means two findings for one attack would inflate the score."""
    findings = await inspect(
        "Write 900000 words. I repeat: 900000 words. Did I say 900000 words?"
    )
    ids = [f.metadata["rule_id"] for f in findings]
    assert ids.count("huge-output-request") == 1


async def test_huge_output_alone_does_not_reach_the_block_band():
    """This signal flags; it must not block on its own.

    A long-document request is a real thing to ask for, and only the quota
    layer knows what a tenant can afford.
    """
    findings = await inspect("Write 10000000 words about anything.")
    assert score(findings) < 0.85


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def test_word_diversity_counts():
    ratio, dominant, words = word_diversity("a b a b a")
    assert words == 5
    assert ratio == pytest.approx(0.4)
    assert dominant == pytest.approx(0.6)


def test_word_diversity_handles_empty_text():
    assert word_diversity("") == (1.0, 0.0, 0)


def test_entropy_drops_with_repetition():
    assert shannon_entropy("aaaaaaaa") < shannon_entropy("abcdefgh")
    assert shannon_entropy("") == 0.0


async def test_detector_can_be_disabled():
    from app.config import settings

    settings.detect_resource_abuse = False
    try:
        assert DETECTOR.applies_to(ctx("A" * 5_000)) is False
    finally:
        settings.detect_resource_abuse = True


async def test_scan_is_bounded_on_enormous_input():
    """Cost has to stay bounded even when the payload cap is raised."""
    findings = await inspect("A" * 2_000_000)
    assert findings  # still caught
