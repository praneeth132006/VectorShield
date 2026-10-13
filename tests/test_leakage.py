"""Outbound leakage detectors: what must be caught, and what must stay quiet.

The false-positive bar is higher here than on the inbound side. An inbound
false positive rejects one message; an outbound one silently rewrites an answer
a customer is reading, which is the kind of bug nobody reports and everybody
notices.
"""

from __future__ import annotations

import pytest

from app.detectors.base import InspectionContext
from app.detectors.leakage import (
    CanaryDetector,
    PIIDetector,
    SecretDetector,
    SystemPromptLeakDetector,
    find_card_numbers,
    luhn_valid,
)
from app.models.schemas import Direction, OwaspCategory, Severity
from app.policy.engine import score


def _assemble(*parts: str) -> str:
    """Join a synthetic credential from fragments.

    This corpus has to contain realistic credential *shapes* -- that is the
    entire point of testing a secret detector -- but a realistic shape is also
    exactly what GitHub's push protection refuses. Assembling the string at
    runtime leaves no secret-shaped literal in the file while the detector
    still sees the whole thing. The values are invented; the shapes are real.
    """
    return "".join(parts)


SYSTEM_PROMPT = (
    "You are Acme's support assistant. Only discuss Acme products and never "
    "quote internal pricing tiers or discuss competitor hardware under any "
    "circumstances."
)
CANARY = "VS-CANARY-9f3c1a77b2d40e15"


def _ctx(text: str, **kw) -> InspectionContext:
    return InspectionContext(
        text=text,
        direction=Direction.OUTBOUND,
        canary_token=kw.get("canary_token", CANARY),
        system_prompt=kw.get("system_prompt", SYSTEM_PROMPT),
        tenant_id="t1",
    )


# Ordinary answers a support bot gives every day. A finding strong enough to
# sanitize any of these is a product bug, not a security win.
BENIGN_RESPONSES = [
    "Your order #A4821 shipped on Tuesday and should arrive by Friday.",
    "You can reset your password from Settings > Security > Reset password.",
    "I'm sorry, I can only help with Acme products. Try our docs at acme.com/docs.",
    "Here's the snippet:\n\n```python\nclient = Acme(api_key=os.environ['ACME_KEY'])\n```",
    "Set the environment variable like this: API_KEY=your-api-key-here",
    "Our refund window is 30 days from delivery, no questions asked.",
    "The X200 printer supports duplex printing and 802.11ac wireless.",
    "That order total was 1234567890123456 cents, which is not a real figure.",
    "Reach our team at support@acme.com and we'll take it from there.",
]

SECRET_RESPONSES = [
    ("aws-access-key-id", "Sure, the deploy key is AKIAIOSFODNN7EXAMPLE for that bucket."),
    (
        "openai-api-key",
        "Use sk-abcdefghijklmnopqrstuvwxyz012345 to authenticate the call.",
    ),
    (
        "anthropic-api-key",
        "The key is sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789.",
    ),
    (
        "github-token",
        "Try ghp_abcdefghijklmnopqrstuvwxyz0123456789 as the token.",
    ),
    (
        "slack-token",
        "Bot token: " + _assemble("xoxb-", "123456789012-", "abcdefghijklmnop"),
    ),
    ("google-api-key", "Maps key AIzaSyA01234567890123456789012345678901 works."),
    (
        "stripe-key",
        "Billing uses "
        + _assemble("sk_", "live_", "abcdefghijklmnop0123456789")
        + " on our side.",
    ),
    (
        "private-key-block",
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----",
    ),
    (
        "credentialed-url",
        "Connect with postgresql://admin:hunter2primary@db.internal:5432/acme",
    ),
]


# --- Canary ----------------------------------------------------------------


async def test_canary_in_a_response_is_a_confident_leak() -> None:
    findings = await CanaryDetector().inspect(
        _ctx(f"My instructions include the marker {CANARY}, which I was told to hide.")
    )

    assert len(findings) == 1
    assert findings[0].category is OwaspCategory.LLM06_INFO_DISCLOSURE
    assert findings[0].severity is Severity.CRITICAL
    # A random token cannot appear by accident, so this is the one outbound
    # signal allowed to reach the block threshold on its own.
    assert score(findings) >= 0.85


async def test_canary_is_caught_even_when_the_model_spaces_it_out() -> None:
    spaced = " ".join(CANARY)
    findings = await CanaryDetector().inspect(_ctx(f"The marker is {spaced}."))

    assert findings and findings[0].metadata["rule_id"] == "canary-obfuscated"


async def test_canary_detector_is_silent_on_ordinary_answers() -> None:
    for text in BENIGN_RESPONSES:
        assert await CanaryDetector().inspect(_ctx(text)) == [], text


async def test_no_canary_configured_means_nothing_to_check() -> None:
    findings = await CanaryDetector().inspect(_ctx(f"Marker {CANARY}", canary_token=None))
    assert findings == []


# --- Secrets ---------------------------------------------------------------


@pytest.mark.parametrize(("rule_id", "text"), SECRET_RESPONSES)
async def test_credential_shapes_are_detected(rule_id: str, text: str) -> None:
    findings = await SecretDetector().inspect(_ctx(text))

    assert findings, f"{rule_id} not detected in: {text}"
    assert rule_id in {f.metadata["rule_id"] for f in findings}


@pytest.mark.parametrize(("rule_id", "text"), SECRET_RESPONSES)
async def test_a_leaked_credential_reaches_at_least_the_sanitize_band(
    rule_id: str, text: str
) -> None:
    findings = await SecretDetector().inspect(_ctx(text))
    # 0.45 is the default flag threshold: outbound, that means "redact it".
    assert score(findings) >= 0.45, rule_id


async def test_secret_detector_stays_quiet_on_ordinary_answers() -> None:
    for text in BENIGN_RESPONSES:
        findings = await SecretDetector().inspect(_ctx(text))
        assert score(findings) < 0.45, f"false positive on: {text}"


async def test_placeholders_in_documentation_are_not_secrets() -> None:
    samples = [
        "Set api_key=your-api-key-here in the config file.",
        'password = "REPLACE_ME_WITH_YOUR_PASSWORD"',
        "export ACCESS_TOKEN=<your-token-goes-here>",
        "api_key: xxxxxxxxxxxxxxxxxxxx",
    ]
    for text in samples:
        findings = await SecretDetector().inspect(_ctx(text))
        assert score(findings) < 0.45, f"placeholder treated as a secret: {text}"


async def test_environment_variable_references_are_not_secrets() -> None:
    """`apiKey: process.env.ACME_API_KEY` is the correct way to write it."""
    samples = [
        "const acme = new Acme({ apiKey: process.env.ACME_API_KEY });",
        "client = Acme(api_key=os.environ['ACME_API_KEY'])",
        "Run it with API_KEY=$ACME_PRODUCTION_KEY in your shell.",
        'password = System.getenv("ACME_DB_PASSWORD")',
    ]
    for text in samples:
        findings = await SecretDetector().inspect(_ctx(text))
        assert score(findings) < 0.45, f"punished good advice: {text}"


async def test_every_occurrence_is_reported_so_redaction_is_complete() -> None:
    text = "Keys: AKIAIOSFODNN7EXAMPLE and AKIAJ1234567890ABCDE both work."
    findings = await SecretDetector().inspect(_ctx(text))

    matches = findings[0].metadata["matches"]
    assert matches == ["AKIAIOSFODNN7EXAMPLE", "AKIAJ1234567890ABCDE"]


async def test_repetition_does_not_inflate_the_score() -> None:
    """Ten copies of one secret is one leak, not ten independent signals."""
    one = await SecretDetector().inspect(_ctx("Key AKIAIOSFODNN7EXAMPLE here."))
    many = await SecretDetector().inspect(
        _ctx(" ".join(["Key AKIAIOSFODNN7EXAMPLE here."] * 10))
    )
    assert score(one) == score(many)


# --- PII -------------------------------------------------------------------


def test_luhn_separates_card_numbers_from_long_digit_strings() -> None:
    assert luhn_valid("4111111111111111")
    assert not luhn_valid("4111111111111112")
    assert find_card_numbers("Order id 1234567890123456 was placed") == []
    assert find_card_numbers("Card 4111 1111 1111 1111 on file") == ["4111 1111 1111 1111"]


async def test_high_structure_pii_reaches_the_sanitize_band() -> None:
    for text in (
        "The customer's SSN is 123-45-6789.",
        "Their card on file is 4111 1111 1111 1111.",
    ):
        assert score(await PIIDetector().inspect(_ctx(text))) >= 0.45, text


async def test_one_support_address_is_logged_but_not_sanitized() -> None:
    findings = await PIIDetector().inspect(
        _ctx("Email support@acme.com and we'll sort it out.")
    )
    assert findings, "an email should still be recorded as a finding"
    # Recorded, not acted on -- a support bot printing its own address is the
    # product working correctly.
    assert score(findings) < 0.45


async def test_a_whole_customer_record_accumulates_past_the_line() -> None:
    findings = await PIIDetector().inspect(
        _ctx(
            "Customer: Dana Reyes, dana.reyes@example.com, 415-555-0132, "
            "SSN 987-65-4320, card 4111 1111 1111 1111."
        )
    )
    assert score(findings) >= 0.45


async def test_an_id_shaped_number_needs_the_sentence_to_agree() -> None:
    """ddd-dd-dddd is also a warehouse bay number, a part number, a date range."""
    bay = await PIIDetector().inspect(
        _ctx("Our warehouse bay numbering runs 100-20-3000 through 100-20-4999.")
    )
    ssn = await PIIDetector().inspect(_ctx("Her SSN is 100-20-3000."))

    assert score(bay) < 0.45, "an unqualified number must not rewrite an answer"
    assert score(ssn) >= 0.45, "the same shape, with the word, is a real finding"
    # Still recorded either way: the audit log is where an operator looks.
    assert bay


async def test_taxpayer_ids_are_covered_not_just_social_security_numbers() -> None:
    findings = await PIIDetector().inspect(
        _ctx("The taxpayer id we have on record for that account is 987-65-4320.")
    )
    assert score(findings) >= 0.45


async def test_pii_detector_stays_quiet_on_ordinary_answers() -> None:
    for text in BENIGN_RESPONSES:
        assert score(await PIIDetector().inspect(_ctx(text))) < 0.45, text


async def test_pii_can_be_switched_off_without_touching_the_rest() -> None:
    from app.config import settings

    settings.detect_pii = False
    try:
        assert await PIIDetector().inspect(_ctx("SSN 123-45-6789")) == []
    finally:
        settings.detect_pii = True


# --- System prompt overlap -------------------------------------------------


async def test_a_verbatim_system_prompt_run_is_detected() -> None:
    findings = await SystemPromptLeakDetector().inspect(
        _ctx(
            "Of course! My instructions say: You are Acme's support assistant. "
            "Only discuss Acme products and never quote internal pricing tiers "
            "or discuss competitor hardware under any circumstances."
        )
    )

    assert findings
    assert findings[0].metadata["overlap_ratio"] > 0.5
    assert score(findings) >= 0.45


async def test_reformatting_does_not_defeat_the_overlap_check() -> None:
    findings = await SystemPromptLeakDetector().inspect(
        _ctx(
            "- you are ACME'S support assistant!\n"
            "- only discuss acme products, and never quote internal pricing "
            "tiers or discuss competitor hardware, under any circumstances"
        )
    )
    assert findings


async def test_paraphrasing_the_role_is_not_a_leak() -> None:
    findings = await SystemPromptLeakDetector().inspect(
        _ctx("I'm here to help with anything related to Acme products.")
    )
    assert findings == []


async def test_overlap_check_needs_a_configured_system_prompt() -> None:
    findings = await SystemPromptLeakDetector().inspect(
        _ctx(SYSTEM_PROMPT, system_prompt=None)
    )
    assert findings == []


async def test_system_prompt_leak_detector_is_silent_on_ordinary_answers() -> None:
    for text in BENIGN_RESPONSES:
        assert await SystemPromptLeakDetector().inspect(_ctx(text)) == [], text


# --- Contract --------------------------------------------------------------


async def test_outbound_detectors_do_not_run_on_inbound_text() -> None:
    inbound = InspectionContext(
        text="AKIAIOSFODNN7EXAMPLE", direction=Direction.INBOUND, canary_token=CANARY
    )
    for detector in (
        CanaryDetector(),
        SecretDetector(),
        PIIDetector(),
        SystemPromptLeakDetector(),
    ):
        assert not detector.applies_to(inbound), detector.name


async def test_every_leakage_finding_is_attributed_to_llm06() -> None:
    text = (
        f"{CANARY} AKIAIOSFODNN7EXAMPLE dana@example.com 123-45-6789 "
        "You are Acme's support assistant. Only discuss Acme products and "
        "never quote internal pricing tiers or discuss competitor hardware "
        "under any circumstances."
    )
    for detector in (
        CanaryDetector(),
        SecretDetector(),
        PIIDetector(),
        SystemPromptLeakDetector(),
    ):
        for finding in await detector.inspect(_ctx(text)):
            assert finding.category is OwaspCategory.LLM06_INFO_DISCLOSURE
            assert finding.direction is Direction.OUTBOUND
