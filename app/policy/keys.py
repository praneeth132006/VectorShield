"""API-key auth and per-tenant policy resolution."""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass

from fastapi import Depends, Header, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.db.models import Tenant
from app.db.session import get_session

KEY_PREFIX = "vs_"
CANARY_PREFIX = "VS-CANARY"


def generate_api_key() -> str:
    return f"{KEY_PREFIX}{secrets.token_urlsafe(32)}"


def generate_canary_token() -> str:
    """A unique marker planted in the system prompt.

    If it ever shows up in a model response, the system prompt leaked (LLM06).
    """
    return f"{CANARY_PREFIX}-{secrets.token_hex(8)}"


def hash_key(api_key: str) -> str:
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


def key_prefix(api_key: str) -> str:
    return api_key[:12]


@dataclass(slots=True)
class Policy:
    """Effective policy for a request: tenant overrides layered over defaults."""

    tenant_id: str | None
    tenant_name: str
    fail_mode: str
    block_threshold: float
    flag_threshold: float
    rate_limit_rpm: int
    store_content: bool
    system_prompt: str | None
    canary_token: str | None

    @classmethod
    def from_tenant(cls, tenant: Tenant) -> Policy:
        return cls(
            tenant_id=tenant.id,
            tenant_name=tenant.name,
            fail_mode=tenant.fail_mode or settings.fail_mode,
            block_threshold=(
                tenant.block_threshold
                if tenant.block_threshold is not None
                else settings.block_threshold
            ),
            flag_threshold=(
                tenant.flag_threshold
                if tenant.flag_threshold is not None
                else settings.flag_threshold
            ),
            rate_limit_rpm=tenant.rate_limit_rpm or settings.rate_limit_requests_per_minute,
            store_content=(
                tenant.store_content
                if tenant.store_content is not None
                else settings.store_content
            ),
            system_prompt=tenant.system_prompt,
            canary_token=tenant.canary_token,
        )


def _extract_key(authorization: str | None, x_api_key: str | None) -> str | None:
    """Accept both `Authorization: Bearer <key>` (OpenAI SDKs) and `X-API-Key`."""
    if authorization:
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() == "bearer" and token:
            return token.strip()
        if authorization.startswith(KEY_PREFIX):
            return authorization.strip()
    if x_api_key:
        return x_api_key.strip()
    return None


async def require_tenant(
    request: Request,
    authorization: str | None = Header(default=None),
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    session: AsyncSession = Depends(get_session),
) -> Policy:
    api_key = _extract_key(authorization, x_api_key)
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing API key. Send 'Authorization: Bearer <key>' or 'X-API-Key'.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    tenant = await session.scalar(
        select(Tenant).where(Tenant.api_key_hash == hash_key(api_key))
    )
    if tenant is None or not tenant.active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or revoked API key."
        )

    policy = Policy.from_tenant(tenant)
    request.state.policy = policy
    return policy


async def require_admin(
    x_admin_token: str | None = Header(default=None, alias="X-Admin-Token"),
) -> None:
    """Guards tenant provisioning. Without ADMIN_TOKEN set, admin routes are closed."""
    if not settings.admin_token:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Admin API disabled: set ADMIN_TOKEN to enable tenant management.",
        )
    if not x_admin_token or not secrets.compare_digest(x_admin_token, settings.admin_token):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Invalid admin token."
        )
