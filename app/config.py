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

    # --- Upstream providers ----------------------------------------------
    default_provider: Literal["openai", "ollama"] = "ollama"
    openai_api_key: str | None = None
    openai_base_url: str = "https://api.openai.com/v1"
    openai_default_model: str = "gpt-4o-mini"
    ollama_base_url: str = "http://localhost:11434"
    ollama_default_model: str = "llama3.2:3b"
    upstream_timeout_seconds: float = 60.0

    # --- Security policy defaults ----------------------------------------
    # "open": ambiguous verdicts are allowed and flagged. A false positive that
    # breaks a real chatbot costs more than one logged probe.
    fail_mode: FailMode = "open"
    block_threshold: float = 0.85
    flag_threshold: float = 0.45

    # Gateway-owned system prompt + canary (protects a tenant's instructions).
    inject_system_prompt: bool = True
    canary_enabled: bool = True

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
