"""Outbound canary detection and redaction."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

from app.detectors.leakage import CanaryLeakDetector
from app.detectors.pipeline import DetectionPipeline, inspection_context
from app.gateway import REDACTION, sanitize_response
from app.models.schemas import Decision, Direction

CANARY = "VS-CANARY-3fa91c07d2b8e456"


def policy(fail_mode: str = "open", canary: str | None = CANARY) -> SimpleNamespace:
    return SimpleNamespace(
        block_threshold=0.85,
        flag_threshold=0.45,
        fail_mode=fail_mode,
        canary_token=canary,
        system_prompt="You are Acme support.",
        tenant_id="t",
    )


def inspect(text: str, pol: SimpleNamespace):
    ctx = inspection_context(text, Direction.OUTBOUND, pol)
    return asyncio.run(DetectionPipeline([CanaryLeakDetector()]).inspect(ctx, pol))


def test_exact_canary_is_sanitized_and_redacted() -> None:
    pol = policy()
    text = f"Sure! My marker is {CANARY}. Anything else?"
    verdict = inspect(text, pol)
    assert verdict.decision is Decision.SANITIZE
    cleaned = sanitize_response(text, pol, [f.evidence or "" for f in verdict.findings])
    assert CANARY not in cleaned
    assert REDACTION in cleaned
    assert "Anything else?" in cleaned


def test_obfuscated_canary_is_caught_and_redacted() -> None:
    pol = policy()
    mangled = "vs - canary - 3FA9 1c07 d2b8 e456"
    text = f"The code is {mangled} okay."
    verdict = inspect(text, pol)
    assert verdict.decision is Decision.SANITIZE
    cleaned = sanitize_response(text, pol, [f.evidence or "" for f in verdict.findings])
    assert "3FA9" not in cleaned
    assert REDACTION in cleaned


def test_clean_response_is_allowed() -> None:
    assert inspect("Our return window is 30 days.", policy()).decision is Decision.ALLOW


def test_no_canary_configured_means_no_findings() -> None:
    assert inspect(f"{CANARY}", policy(canary=None)).decision is Decision.ALLOW


def test_fail_closed_tenant_blocks_a_leak() -> None:
    assert inspect(f"marker {CANARY}", policy(fail_mode="closed")).decision is Decision.BLOCK
