"""SQLAlchemy models. SQLite in dev, Postgres in production -- same schema."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def _uuid() -> str:
    return uuid.uuid4().hex


def _now() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    pass


class Tenant(Base):
    """An API consumer: one small company, one app, or one environment.

    Policy lives here rather than in global config so a support chatbot and an
    internal tool can run under different rules on the same gateway.
    """

    __tablename__ = "tenants"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    active: Mapped[bool] = mapped_column(Boolean, default=True)

    # Auth: only the hash is stored. The raw key is shown once at creation.
    api_key_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    api_key_prefix: Mapped[str] = mapped_column(String(16))

    # Gateway-owned system prompt + canary token (LLM06 system-prompt leakage).
    system_prompt: Mapped[str | None] = mapped_column(Text, nullable=True)
    canary_token: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Policy overrides; NULL means "use the global default".
    fail_mode: Mapped[str | None] = mapped_column(String(8), nullable=True)
    block_threshold: Mapped[float | None] = mapped_column(Float, nullable=True)
    flag_threshold: Mapped[float | None] = mapped_column(Float, nullable=True)
    rate_limit_rpm: Mapped[int | None] = mapped_column(Integer, nullable=True)
    store_content: Mapped[bool | None] = mapped_column(Boolean, nullable=True)

    logs: Mapped[list[RequestLog]] = relationship(
        back_populates="tenant", cascade="all, delete-orphan"
    )


class RequestLog(Base):
    """One row per request, written regardless of the decision.

    Prompt text is hashed by default. Raw content is persisted only when the
    tenant opts in, or when the request was blocked (so attacks stay triageable).
    """

    __tablename__ = "request_logs"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    tenant_id: Mapped[str | None] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), nullable=True, index=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, index=True
    )

    client_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    route: Mapped[str] = mapped_column(String(64), default="/v1/chat/completions")
    provider: Mapped[str] = mapped_column(String(32))
    model: Mapped[str] = mapped_column(String(128))

    prompt_hash: Mapped[str] = mapped_column(String(64), index=True)
    response_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    prompt_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    response_text: Mapped[str | None] = mapped_column(Text, nullable=True)

    decision: Mapped[str] = mapped_column(String(16), index=True)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    outbound_decision: Mapped[str | None] = mapped_column(String(16), nullable=True)
    outbound_risk_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    blocked_by: Mapped[str | None] = mapped_column(String(64), nullable=True)

    prompt_tokens: Mapped[int] = mapped_column(Integer, default=0)
    completion_tokens: Mapped[int] = mapped_column(Integer, default=0)

    total_latency_ms: Mapped[float] = mapped_column(Float, default=0.0)
    upstream_latency_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    overhead_ms: Mapped[float] = mapped_column(Float, default=0.0)
    status_code: Mapped[int] = mapped_column(Integer, default=200)

    tenant: Mapped[Tenant | None] = relationship(back_populates="logs")
    findings: Mapped[list[FindingLog]] = relationship(
        back_populates="request", cascade="all, delete-orphan"
    )


Index("ix_request_logs_tenant_created", RequestLog.tenant_id, RequestLog.created_at)


class FindingLog(Base):
    """A detector hit attached to a request -- the dashboard's raw material."""

    __tablename__ = "finding_logs"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    request_id: Mapped[str] = mapped_column(
        ForeignKey("request_logs.id", ondelete="CASCADE"), index=True
    )
    detector: Mapped[str] = mapped_column(String(64), index=True)
    category: Mapped[str] = mapped_column(String(16), index=True)
    severity: Mapped[str] = mapped_column(String(16))
    direction: Mapped[str] = mapped_column(String(16), default="inbound")
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    message: Mapped[str] = mapped_column(Text, default="")
    evidence: Mapped[str | None] = mapped_column(Text, nullable=True)

    request: Mapped[RequestLog] = relationship(back_populates="findings")
