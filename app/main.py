"""VectorShield -- a security gateway that sits in front of your LLM.

Two ways in:
  POST /v1/chat/completions   OpenAI-compatible. Point your existing SDK's
                              base_url here and you are protected.
  POST /v1/gateway/chat       Same call, plus the full security report.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app import __version__
from app.config import settings
from app.db.models import Tenant
from app.db.session import dispose_db, get_session, get_sessionmaker, init_db
from app.detectors.pipeline import inbound_pipeline, outbound_pipeline
from app.gateway import RequestBlocked, process_chat
from app.models.schemas import (
    ChatCompletionRequest,
    ChatCompletionResponse,
    GatewayChatRequest,
    GatewayChatResponse,
    HealthResponse,
    TenantCreate,
    TenantCreated,
    TenantPublic,
)
from app.policy.keys import (
    Policy,
    generate_api_key,
    generate_canary_token,
    hash_key,
    key_prefix,
    require_admin,
    require_tenant,
)
from app.proxy.llm_client import PROVIDERS, UpstreamError, pool
from app.ratelimit.limiter import limiter

logging.basicConfig(level=settings.log_level.upper())
logger = logging.getLogger("vectorshield")


async def _bootstrap_tenant() -> None:
    """Create the first tenant from BOOTSTRAP_API_KEY so a fresh clone is usable."""
    if not settings.bootstrap_api_key:
        return
    async with get_sessionmaker()() as session:
        existing = await session.scalar(
            select(Tenant).where(Tenant.api_key_hash == hash_key(settings.bootstrap_api_key))
        )
        if existing:
            return
        session.add(
            Tenant(
                name="bootstrap",
                api_key_hash=hash_key(settings.bootstrap_api_key),
                api_key_prefix=key_prefix(settings.bootstrap_api_key),
                canary_token=generate_canary_token(),
            )
        )
        await session.commit()
        logger.info("bootstrap tenant created from BOOTSTRAP_API_KEY")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    await init_db()
    await pool.start()
    await limiter.start()
    await inbound_pipeline.warmup()
    await outbound_pipeline.warmup()
    await _bootstrap_tenant()
    logger.info(
        "VectorShield %s up | provider=%s | ratelimit=%s | fail_mode=%s",
        __version__,
        settings.default_provider,
        limiter.backend_name,
        settings.fail_mode,
    )
    try:
        yield
    finally:
        await limiter.stop()
        await pool.stop()
        await dispose_db()


app = FastAPI(
    title="VectorShield",
    description="An AI security gateway for LLM applications (OWASP LLM01/04/06/10).",
    version=__version__,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(UpstreamError)
async def _upstream_error_handler(_: Request, exc: UpstreamError) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": {
                "message": str(exc),
                "type": "upstream_error",
                "provider": exc.provider,
            }
        },
    )


@app.exception_handler(RequestBlocked)
async def _blocked_handler(_: Request, exc: RequestBlocked) -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_403_FORBIDDEN,
        content={
            "error": {
                "message": exc.message,
                "type": "vectorshield_blocked",
                "code": "request_blocked",
                "request_id": exc.report.request_id,
                "reason": exc.report.inbound.reason,
                "risk_score": exc.report.inbound.risk_score,
            },
            "security": exc.report.model_dump(mode="json"),
        },
    )


def _client_ip(request: Request) -> str | None:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else None


async def _enforce_rate_limit(request: Request, policy: Policy) -> None:
    key = policy.tenant_id or _client_ip(request) or "anonymous"
    result = await limiter.check(key, policy.rate_limit_rpm)
    if not result.allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=(
                f"Rate limit exceeded ({result.limit} requests/min). "
                f"Penalty level: {result.penalty}."
            ),
            headers={
                "Retry-After": str(result.retry_after),
                "X-RateLimit-Limit": str(result.limit),
                "X-RateLimit-Remaining": "0",
                "X-VectorShield-Penalty": result.penalty,
            },
        )


# --------------------------------------------------------------------------
# Health
# --------------------------------------------------------------------------


@app.get("/health", response_model=HealthResponse, tags=["ops"])
async def health(session: AsyncSession = Depends(get_session)) -> HealthResponse:
    providers = {name: await p.health(pool.client) for name, p in PROVIDERS.items()}
    try:
        await session.execute(select(func.count()).select_from(Tenant))
        database = "ok"
    except Exception:
        logger.exception("database health check failed")
        database = "error"

    degraded = database != "ok" or providers.get(settings.default_provider) != "ok"
    return HealthResponse(
        status="degraded" if degraded else "ok",
        version=__version__,
        providers=providers,
        rate_limit_backend=limiter.backend_name,
        database=database,
    )


# --------------------------------------------------------------------------
# Gateway surfaces
# --------------------------------------------------------------------------


@app.post("/v1/chat/completions", response_model=ChatCompletionResponse, tags=["gateway"])
async def chat_completions(
    body: ChatCompletionRequest,
    request: Request,
    policy: Policy = Depends(require_tenant),
    session: AsyncSession = Depends(get_session),
) -> ChatCompletionResponse:
    """OpenAI-compatible. Change base_url, keep your code."""
    if body.stream:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "Streaming is not supported yet: responses must be fully inspected "
                "before they reach the client. Set stream=false."
            ),
        )
    await _enforce_rate_limit(request, policy)
    result = await process_chat(
        GatewayChatRequest(**body.model_dump()),
        policy,
        session,
        client_ip=_client_ip(request),
        route="/v1/chat/completions",
    )
    assert result.completion is not None
    return result.completion


@app.post("/v1/gateway/chat", response_model=GatewayChatResponse, tags=["gateway"])
async def gateway_chat(
    body: GatewayChatRequest,
    request: Request,
    policy: Policy = Depends(require_tenant),
    session: AsyncSession = Depends(get_session),
) -> GatewayChatResponse:
    """Native surface: the completion plus the full security report."""
    if body.stream:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Streaming is not supported yet. Set stream=false.",
        )
    await _enforce_rate_limit(request, policy)
    return await process_chat(
        body,
        policy,
        session,
        client_ip=_client_ip(request),
        route="/v1/gateway/chat",
    )


# --------------------------------------------------------------------------
# Admin
# --------------------------------------------------------------------------


@app.post(
    "/admin/tenants",
    response_model=TenantCreated,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_admin)],
    tags=["admin"],
)
async def create_tenant(
    body: TenantCreate, session: AsyncSession = Depends(get_session)
) -> TenantCreated:
    api_key = generate_api_key()
    tenant = Tenant(
        name=body.name,
        api_key_hash=hash_key(api_key),
        api_key_prefix=key_prefix(api_key),
        system_prompt=body.system_prompt,
        canary_token=generate_canary_token(),
        fail_mode=body.fail_mode,
        block_threshold=body.block_threshold,
        flag_threshold=body.flag_threshold,
        rate_limit_rpm=body.rate_limit_rpm,
    )
    session.add(tenant)
    await session.commit()
    policy = Policy.from_tenant(tenant)
    return TenantCreated(
        id=tenant.id,
        name=tenant.name,
        created_at=tenant.created_at,
        fail_mode=policy.fail_mode,
        rate_limit_rpm=policy.rate_limit_rpm,
        block_threshold=policy.block_threshold,
        flag_threshold=policy.flag_threshold,
        has_system_prompt=bool(tenant.system_prompt),
        api_key=api_key,
    )


@app.get(
    "/admin/tenants",
    response_model=list[TenantPublic],
    dependencies=[Depends(require_admin)],
    tags=["admin"],
)
async def list_tenants(session: AsyncSession = Depends(get_session)) -> list[TenantPublic]:
    tenants = (await session.scalars(select(Tenant).order_by(Tenant.created_at))).all()
    out: list[TenantPublic] = []
    for tenant in tenants:
        policy = Policy.from_tenant(tenant)
        out.append(
            TenantPublic(
                id=tenant.id,
                name=tenant.name,
                created_at=tenant.created_at,
                fail_mode=policy.fail_mode,
                rate_limit_rpm=policy.rate_limit_rpm,
                block_threshold=policy.block_threshold,
                flag_threshold=policy.flag_threshold,
                has_system_prompt=bool(tenant.system_prompt),
            )
        )
    return out
