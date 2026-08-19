"""Upstream LLM adapters.

VectorShield is a real proxy: allowed requests are forwarded to a real model and
the real response comes back. Every provider normalizes to the OpenAI chat
completion shape so the rest of the pipeline only knows one format.
"""

from __future__ import annotations

import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

import httpx

from app.config import settings
from app.models.schemas import (
    ChatCompletionChoice,
    ChatCompletionRequest,
    ChatCompletionResponse,
    ChatMessage,
    Usage,
)


class UpstreamError(RuntimeError):
    """Upstream provider failed. Carries the status code to pass through."""

    def __init__(self, message: str, status_code: int = 502, provider: str = "") -> None:
        super().__init__(message)
        self.status_code = status_code
        self.provider = provider


@dataclass(slots=True)
class UpstreamResult:
    response: ChatCompletionResponse
    latency_ms: float

    @property
    def text(self) -> str:
        if not self.response.choices:
            return ""
        return self.response.choices[0].message.text()


class LLMProvider(ABC):
    name: str

    @abstractmethod
    async def complete(
        self, request: ChatCompletionRequest, client: httpx.AsyncClient
    ) -> UpstreamResult: ...

    @abstractmethod
    async def health(self, client: httpx.AsyncClient) -> str: ...

    @property
    @abstractmethod
    def default_model(self) -> str: ...


class OpenAIProvider(LLMProvider):
    name = "openai"

    @property
    def default_model(self) -> str:
        return settings.openai_default_model

    def _headers(self) -> dict[str, str]:
        if not settings.openai_api_key:
            raise UpstreamError(
                "OPENAI_API_KEY is not configured on the gateway.",
                status_code=503,
                provider=self.name,
            )
        return {"Authorization": f"Bearer {settings.openai_api_key}"}

    async def complete(
        self, request: ChatCompletionRequest, client: httpx.AsyncClient
    ) -> UpstreamResult:
        payload = request.model_dump(exclude_none=True, exclude={"provider", "dry_run"})
        payload["model"] = request.model or self.default_model
        payload["stream"] = False

        started = time.perf_counter()
        try:
            resp = await client.post(
                f"{settings.openai_base_url.rstrip('/')}/chat/completions",
                json=payload,
                headers=self._headers(),
            )
        except httpx.HTTPError as exc:
            raise UpstreamError(f"OpenAI request failed: {exc}", 502, self.name) from exc
        latency_ms = (time.perf_counter() - started) * 1000

        if resp.status_code >= 400:
            raise UpstreamError(_extract_error(resp, "OpenAI"), resp.status_code, self.name)
        return UpstreamResult(ChatCompletionResponse(**resp.json()), latency_ms)

    async def health(self, client: httpx.AsyncClient) -> str:
        if not settings.openai_api_key:
            return "unconfigured"
        try:
            resp = await client.get(
                f"{settings.openai_base_url.rstrip('/')}/models",
                headers=self._headers(),
                timeout=5.0,
            )
            return "ok" if resp.status_code < 400 else f"error:{resp.status_code}"
        except (httpx.HTTPError, UpstreamError):
            return "unreachable"


class OllamaProvider(LLMProvider):
    """Local models via Ollama -- the zero-cost, fully offline fallback."""

    name = "ollama"

    @property
    def default_model(self) -> str:
        return settings.ollama_default_model

    async def complete(
        self, request: ChatCompletionRequest, client: httpx.AsyncClient
    ) -> UpstreamResult:
        model = request.model or self.default_model
        options: dict[str, Any] = {}
        if request.temperature is not None:
            options["temperature"] = request.temperature
        if request.top_p is not None:
            options["top_p"] = request.top_p
        if request.max_tokens is not None:
            options["num_predict"] = request.max_tokens

        payload: dict[str, Any] = {
            "model": model,
            "messages": [{"role": m.role, "content": m.text()} for m in request.messages],
            "stream": False,
        }
        if options:
            payload["options"] = options

        started = time.perf_counter()
        try:
            resp = await client.post(
                f"{settings.ollama_base_url.rstrip('/')}/api/chat", json=payload
            )
        except httpx.HTTPError as exc:
            raise UpstreamError(
                f"Ollama is unreachable at {settings.ollama_base_url}: {exc}",
                503,
                self.name,
            ) from exc
        latency_ms = (time.perf_counter() - started) * 1000

        if resp.status_code >= 400:
            raise UpstreamError(_extract_error(resp, "Ollama"), resp.status_code, self.name)

        body = resp.json()
        message = body.get("message") or {}
        completion = ChatCompletionResponse(
            id=f"chatcmpl-{uuid.uuid4().hex[:24]}",
            created=int(time.time()),
            model=body.get("model", model),
            choices=[
                ChatCompletionChoice(
                    index=0,
                    message=ChatMessage(role="assistant", content=message.get("content", "")),
                    finish_reason=body.get("done_reason") or "stop",
                )
            ],
            usage=Usage(
                prompt_tokens=body.get("prompt_eval_count", 0) or 0,
                completion_tokens=body.get("eval_count", 0) or 0,
                total_tokens=(body.get("prompt_eval_count", 0) or 0)
                + (body.get("eval_count", 0) or 0),
            ),
        )
        return UpstreamResult(completion, latency_ms)

    async def health(self, client: httpx.AsyncClient) -> str:
        try:
            resp = await client.get(
                f"{settings.ollama_base_url.rstrip('/')}/api/tags", timeout=3.0
            )
            return "ok" if resp.status_code < 400 else f"error:{resp.status_code}"
        except httpx.HTTPError:
            return "unreachable"


def _extract_error(resp: httpx.Response, label: str) -> str:
    try:
        body = resp.json()
    except ValueError:
        return f"{label} returned {resp.status_code}: {resp.text[:200]}"
    if isinstance(body, dict):
        err = body.get("error")
        if isinstance(err, dict):
            return f"{label}: {err.get('message', err)}"
        if err:
            return f"{label}: {err}"
    return f"{label} returned {resp.status_code}"


PROVIDERS: dict[str, LLMProvider] = {
    OpenAIProvider.name: OpenAIProvider(),
    OllamaProvider.name: OllamaProvider(),
}


def get_provider(name: str | None = None) -> LLMProvider:
    key = (name or settings.default_provider).lower()
    provider = PROVIDERS.get(key)
    if provider is None:
        raise UpstreamError(
            f"Unknown provider '{key}'. Available: {', '.join(sorted(PROVIDERS))}", 400
        )
    return provider


class UpstreamClientPool:
    """One shared httpx client for the process; opened and closed on lifespan."""

    def __init__(self) -> None:
        self._client: httpx.AsyncClient | None = None

    async def start(self) -> None:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=settings.upstream_timeout_seconds)

    async def stop(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    @property
    def client(self) -> httpx.AsyncClient:
        if self._client is None:
            raise RuntimeError("Upstream client pool not started.")
        return self._client


pool = UpstreamClientPool()
