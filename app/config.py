"""Runtime configuration for the VectorShield gateway.

Every knob is environment-driven so the same image runs on a laptop
(SQLite + in-memory rate limiting + Ollama) and in production
(Postgres + Redis + a hosted provider) with no code change.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

FailMode = Literal["open", "closed"]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

    # --- Service ---------------------------------------------------------
    app_name: str = "VectorShield"
    environment: Literal["dev", "prod"] = "dev"
    log_level: str = "INFO"

    # --- Storage ---------------------------------------------------------
    database_url: str = "sqlite+aiosqlite:///./vectorshield.db"

    # Hash prompts by default; keep raw text only when explicitly enabled.
    # Blocked requests always retain their content so attacks can be triaged.
    store_content: bool = False

    # --- Rate limiting ---------------------------------------------------
    # When unset, the limiter falls back to an in-process sliding window.
    redis_url: str | None = None
    rate_limit_requests_per_minute: int = 60
    rate_limit_tokens_per_minute: int = 40_000

    # --- Abuse / DoS hardening (LLM04) -----------------------------------
    # Request-shape caps, refused before any detector or upstream call runs.
    # A single request can exhaust a token budget without ever tripping a
    # per-minute request count, so size is capped independently of rate.
    max_prompt_chars: int = 48_000
    max_messages: int = 200
    # Ceiling on what a client may ask the model to generate. A request for
    # 100k completion tokens is a cost attack whatever its text says.
    max_output_tokens: int = 4_096
    # What a reply is *assumed* to cost when the client names no max_tokens.
    # Reserving the full ceiling instead would make the token budget bind far
    # tighter than the request limit it sits beside -- at the defaults above,
    # ~9 requests a minute against an advertised 60 -- for replies that are
    # usually a fraction of the ceiling. Reserve the likely cost, then correct
    # it from the provider's real usage once the answer exists.
    expected_completion_tokens: int = 512
    # Content-shaped DoS detection: repetition bombs, unbounded-output
    # requests. Reports findings like any other detector; it does not enforce.
    detect_resource_abuse: bool = True

    # --- Extraction detection (LLM10) ------------------------------------
    # Behavioral, so it needs per-tenant request history. The store is
    # in-process: a multi-worker deployment sees each worker's slice of the
    # traffic, which lowers recall but never invents a detection.
    detect_extraction: bool = True
    extraction_window_seconds: int = 600
    # How many recent prompt fingerprints to keep per tenant. Bounded so a
    # busy tenant cannot grow the profile store without limit.
    extraction_history: int = 256

    # --- Upstream providers ----------------------------------------------
    default_provider: Literal["openai", "ollama"] = "ollama"
    openai_api_key: str | None = None
    openai_base_url: str = "https://api.openai.com/v1"
    openai_default_model: str = "gpt-4o-mini"
    ollama_base_url: str = "http://localhost:11434"
    ollama_default_model: str = "llama3.2:3b"
    upstream_timeout_seconds: float = 60.0

    # --- Detection -------------------------------------------------------
    # Stage 1 artifact. Missing file = rule layer only, with a startup warning.
    classifier_model_path: str = "models/injection_clf.joblib"

    # --- Security policy defaults ----------------------------------------
    # "open": ambiguous verdicts are allowed and flagged. A false positive that
    # breaks a real chatbot costs more than one logged probe.
    fail_mode: FailMode = "open"
    block_threshold: float = 0.85
    flag_threshold: float = 0.45

    # Gateway-owned system prompt + canary (protects a tenant's instructions).
    inject_system_prompt: bool = True
    canary_enabled: bool = True

    # --- Outbound scanning (LLM06) ---------------------------------------
    # Response inspection: secrets, personal data, canary and system-prompt
    # leakage. Turning it off leaves the inbound path untouched.
    outbound_scanning: bool = True
    # PII is the noisiest outbound signal -- a support bot legitimately prints
    # email addresses. Disable it to keep only credential and canary checks.
    detect_pii: bool = True

    # --- Auth ------------------------------------------------------------
    # Bootstrap key created on first startup when no tenants exist.
    bootstrap_api_key: str | None = None
    admin_token: str | None = None

    @field_validator("flag_threshold")
    @classmethod
    def _flag_below_block(cls, v: float, info) -> float:
        block = info.data.get("block_threshold", 1.0)
        if v > block:
            raise ValueError("flag_threshold must be <= block_threshold")
        return v

    @property
    def rate_limit_backend(self) -> Literal["redis", "memory"]:
        return "redis" if self.redis_url else "memory"


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
