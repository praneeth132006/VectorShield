"""Public request/response contracts.

Two API surfaces share one core:
  * OpenAI-compatible  -> POST /v1/chat/completions  (drop-in, change base_url only)
  * Native             -> POST /v1/gateway/chat      (same call + full security metadata)
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class Decision(StrEnum):
    ALLOW = "allow"
    FLAG = "flag-and-log"
    SANITIZE = "sanitize"
    BLOCK = "block"


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class OwaspCategory(StrEnum):
    """OWASP Top 10 for LLM Applications categories VectorShield covers."""

    LLM01_PROMPT_INJECTION = "LLM01"
    LLM04_MODEL_DOS = "LLM04"
    LLM06_INFO_DISCLOSURE = "LLM06"
    LLM10_MODEL_THEFT = "LLM10"


class Direction(StrEnum):
    INBOUND = "inbound"
    OUTBOUND = "outbound"


# --------------------------------------------------------------------------
# Detection primitives
# --------------------------------------------------------------------------


class Finding(BaseModel):
    """One thing a detector noticed. Detectors report; they never decide."""

    detector: str
    category: OwaspCategory
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    message: str
    direction: Direction = Direction.INBOUND
    # Character span in the inspected text, when the detector can localize it.
    span: tuple[int, int] | None = None
    evidence: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class Verdict(BaseModel):
    """The Decision Engine's answer for one direction of one request."""

    decision: Decision
    risk_score: float = Field(ge=0.0, le=1.0)
    findings: list[Finding] = Field(default_factory=list)
    reason: str = ""
    latency_ms: float = 0.0
    # Detector stages that actually ran (proves the ML layer stayed off the
    # hot path for ordinary traffic).
    stages_run: list[str] = Field(default_factory=list)

    @property
    def blocked(self) -> bool:
        return self.decision is Decision.BLOCK


# --------------------------------------------------------------------------
# OpenAI-compatible surface
# --------------------------------------------------------------------------


class ChatMessage(BaseModel):
    model_config = ConfigDict(extra="allow")

    role: Literal["system", "user", "assistant", "tool", "developer"]
    content: str | list[dict[str, Any]] | None = None
    name: str | None = None

    def text(self) -> str:
        """Flatten multimodal content down to the inspectable text parts."""
        if self.content is None:
            return ""
        if isinstance(self.content, str):
            return self.content
        parts: list[str] = []
        for chunk in self.content:
            if isinstance(chunk, dict) and chunk.get("type") == "text":
                parts.append(str(chunk.get("text", "")))
        return "\n".join(parts)


class ChatCompletionRequest(BaseModel):
    model_config = ConfigDict(extra="allow")

    model: str | None = None
    messages: list[ChatMessage]
    temperature: float | None = None
    top_p: float | None = None
    max_tokens: int | None = None
    stream: bool = False
    stop: str | list[str] | None = None
    user: str | None = None


class ChatCompletionChoice(BaseModel):
    index: int = 0
    message: ChatMessage
    finish_reason: str | None = "stop"


class Usage(BaseModel):
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0


class ChatCompletionResponse(BaseModel):
    model_config = ConfigDict(extra="allow")

    id: str
    object: Literal["chat.completion"] = "chat.completion"
    created: int
    model: str
    choices: list[ChatCompletionChoice]
    usage: Usage = Field(default_factory=Usage)


# --------------------------------------------------------------------------
# Native surface
# --------------------------------------------------------------------------


class GatewayChatRequest(ChatCompletionRequest):
    """OpenAI request plus gateway-only knobs."""

    # Free-form so providers stay pluggable; an unknown name is rejected by the
    # registry with a 400 that lists what is actually available.
    provider: str | None = None
    # Per-call override; falls back to the tenant policy, then global defaults.
    dry_run: bool = False


class SecurityReport(BaseModel):
    request_id: str
    inbound: Verdict
    outbound: Verdict | None = None
    provider: str
    model: str
    total_latency_ms: float
    upstream_latency_ms: float | None = None
    overhead_ms: float


class GatewayChatResponse(BaseModel):
    completion: ChatCompletionResponse | None = None
    security: SecurityReport


class BlockedResponse(BaseModel):
    """Returned with HTTP 403 when the Decision Engine blocks a request."""

    error: dict[str, Any]
    security: SecurityReport


# --------------------------------------------------------------------------
# Admin / observability
# --------------------------------------------------------------------------


class TenantCreate(BaseModel):
    name: str
    system_prompt: str | None = None
    fail_mode: Literal["open", "closed"] | None = None
    rate_limit_rpm: int | None = None
    block_threshold: float | None = Field(default=None, ge=0.0, le=1.0)
    flag_threshold: float | None = Field(default=None, ge=0.0, le=1.0)


class TenantPublic(BaseModel):
    id: str
    name: str
    created_at: datetime
    fail_mode: str
    rate_limit_rpm: int
    block_threshold: float
    flag_threshold: float
    has_system_prompt: bool


class TenantCreated(TenantPublic):
    api_key: str = Field(description="Shown once at creation and never again.")


class HealthResponse(BaseModel):
    status: Literal["ok", "degraded"]
    version: str
    providers: dict[str, str]
    rate_limit_backend: str
    database: str
