# VectorShield — Project Context

> **Current Status:** Phase 0 is shipped. Phase 1 inbound prompt-injection rules and an optional Stage 1 TF-IDF classifier are registered. Phase 2 is partial: outbound canary leak detection is registered, but PII and secret detectors are not. The classifier is disabled until a trained model artifact is present. Patch tests were added but have not been run in this integration.

---

## 1. Project Purpose

**VectorShield** (`v0.1.0`) is an asynchronous, multi-tenant **AI security gateway (reverse proxy)** for LLM applications. It sits between client applications and upstream LLM providers (**Ollama** or **OpenAI**), inspecting prompts before they reach the model and responses before they reach the user, while writing a privacy-preserving audit trail.

### OWASP LLM Top 10 Coverage
| Category | Threat | Gateway Defense |
|---|---|---|
| **LLM01** | Prompt Injection / Jailbreaking | Staged inbound inspection pipeline + gateway-owned system prompt replacement. |
| **LLM04** | Model Denial of Service | Per-tenant 60s sliding-window rate limiting with escalating penalties (`none` → `warn` → `throttle` → `block`). |
| **LLM06** | Sensitive Information Disclosure | Outbound response inspection, span redaction (`[REDACTED BY VECTORSHIELD]`), and canary token planting (`VS-CANARY-<hex>`). |
| **LLM10** | Model Theft / Extraction | Planned per-tenant request anomaly detection (stretch goal). |

---

## 2. Architecture & Request Flow

```
Client ──▶ Auth (require_tenant)
       ──▶ Rate Limiter (Memory / Redis)
       ──▶ Inbound Pipeline (Stage 0 → Stage 1 → Stage 2) + Decision Engine
             ├── BLOCK ──▶ Audit Log + HTTP 403 (with SecurityReport)
             └── ALLOW / FLAG
                   ──▶ System Prompt Replacement + Canary Token Injection
                   ──▶ Upstream Provider Adapter (Ollama / OpenAI)
                   ──▶ Outbound Pipeline + Decision Engine
                         ├── BLOCK    ──▶ Replace response with BLOCK_MESSAGE
                         ├── SANITIZE ──▶ Redact canary & finding evidence spans
                         └── ALLOW / FLAG
                   ──▶ Audit Log (SHA-256 hashes + optional raw content)
                   ──▶ Client (HTTP 200)
```

### Repository Structure
* `app/main.py` — FastAPI app, lifespan management, bootstrap tenant creation, rate-limit enforcement, and HTTP routes:
  * `GET /health` — Database and upstream provider health check.
  * `POST /v1/chat/completions` — Drop-in OpenAI-compatible surface.
  * `POST /v1/gateway/chat` — Native surface returning `completion` + full `SecurityReport` (supports `dry_run` and `provider` override).
  * `POST /admin/tenants` & `GET /admin/tenants` — Admin-token-protected (`X-Admin-Token`) tenant management.
* `app/gateway.py` — End-to-end request orchestration (`process_chat`), system prompt replacement (`apply_system_prompt`), and outbound redaction (`sanitize_response`).
* `app/detectors/` — `Detector` ABC (`base.py`), staged pipeline, Stage 0 injection rules, Stage 1 TF-IDF classifier, and outbound canary detector. Stage 1 runs only when Stage 0 leaves risk in `[flag_threshold, block_threshold)`; the classifier is unavailable until `models/injection_clf.joblib` is trained.
* `app/policy/` — Noisy-OR risk scoring and `decide()` logic (`engine.py`), plus SHA-256 API key hashing (`vs_...`) and per-tenant `Policy` resolution (`keys.py`).
* `app/proxy/llm_client.py` — Shared `httpx.AsyncClient` pool and normalized `OllamaProvider` / `OpenAIProvider` adapters.
* `app/ratelimit/limiter.py` — Sliding-window rate limiter with `MemoryBackend` and `RedisBackend` (falls back to memory if Redis is unavailable).
* `app/db/` & `app/audit.py` — Async SQLAlchemy 2.0 models (`Tenant`, `RequestLog`, `FindingLog`), session management, and SHA-256 hashed audit logging (`store_content=False` by default; raw text retained on `BLOCK`/`SANITIZE` or tenant opt-in).
* `scripts/` — Optional dataset preparation, classifier training, and evaluation scripts; dataset preparation downloads external datasets.
* `tests/` — Async `pytest` suite wired to an in-process `MockProvider`, with added rule, classifier, leakage, and hardening coverage. Tests have not been run as part of this integration.

---

## 3. Technology Stack

* **Language**: Python `>=3.11` (CI tests `3.11`, `3.12`, `3.13`)
* **Framework & Server**: `fastapi>=0.115,<1.0`, `uvicorn[standard]>=0.32,<1.0`
* **Config & Schemas**: `pydantic>=2.9,<3.0`, `pydantic-settings>=2.6,<3.0`
* **HTTP Client**: `httpx>=0.27,<1.0`
* **Database**: `sqlalchemy[asyncio]>=2.0.36,<3.0`, `aiosqlite>=0.20` (dev default), `asyncpg>=0.30` (PostgreSQL in prod)
* **Rate Limiting**: `redis>=5.2,<7.0` (optional; falls back to in-memory sliding window)
* **Testing & Tooling**: `pytest>=8.3`, `pytest-asyncio>=0.24`, `ruff>=0.8`

---

## 4. Setup, Run & Test Commands

### Local Setup (Windows PowerShell)
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt
Copy-Item .env.example .env
```

### Run the Gateway
```powershell
# Start local server (Swagger UI at http://localhost:8000/docs)
uvicorn app.main:app --reload

# Or run with Docker Compose (Gateway + Redis)
docker compose up --build
```

### Run Tests & Linting
The test suite uses a mock upstream provider and temporary SQLite DB (no API keys, network, Redis, or Ollama needed):
```powershell
pytest
ruff check .
ruff format --check .
```

---

## 5. Current Implementation Status

| Phase | Scope | Status |
|---|---|---|
| **Phase 0** | Authenticated proxy, multi-tenant policies, noisy-OR decision engine, rate limiting, system prompt + canary injection, audit log | ✅ **Shipped** |
| **Phase 1** | Module 1 — Inbound prompt injection / jailbreak detection (LLM01) | Implemented; classifier needs trained model |
| **Phase 2** | Module 2 — Outbound PII/secret leakage & canary verification (LLM06) | Partial; canary detection only |
| **Phase 3** | Module 3 — DoS hardening & token-budget rate limiting (LLM04) | ⬜ Planned |
| **Phase 4** | Module 4 — Model extraction anomaly detection (LLM10) | ⬜ Stretch |
| **Phase 5** | Streamlit operations dashboard + reproducible benchmark suite | ⬜ Planned |

---

## 6. Known Issues & Edge Cases

1. **Stage 0 to Stage 1 escalation limit (`app/detectors/pipeline.py`)**: Stage 1 runs only when Stage 0 scores the request in the ambiguous band. A novel or paraphrased attack scored below `flag_threshold` short-circuits before the classifier.
2. **Optional classifier artifact**: The classifier loads `models/injection_clf.joblib`; without it, rule detection remains active and classifier checks are skipped.
3. **Partial outbound coverage**: Canary leaks are detected and sanitized, but PII, API-key, secret, and system-prompt-overlap detection are not implemented.
4. **Client `system` / `developer` handling**: When the tenant has a system prompt, client turns are inspected then stripped. Without a tenant prompt, client turns pass through after inspection.
5. **Unused Token-Budget Setting (`app/config.py`)**: `rate_limit_tokens_per_minute` (`40_000`) is defined in `Settings` but not yet enforced.
6. **Streaming Unsupported (`app/main.py`)**: Requests with `stream=True` are rejected with `HTTP 400` because responses must be buffered for outbound inspection.
7. **Tenant threshold validation**: `TenantCreate` now rejects a `flag_threshold` greater than `block_threshold`.
8. **Rate Limiter Counts Rejected Requests (`app/ratelimit/limiter.py`)**: Both `MemoryBackend` and `RedisBackend` record hits in the sliding window even when `count > limit`, extending the retry window for clients polling while rate-limited. `MemoryBackend._hits` also retains empty deques for inactive keys.
9. **Unconditional `X-Forwarded-For` Trust (`app/main.py`)**: `_client_ip()` trusts `X-Forwarded-For` without verifying a trusted proxy hop.

---

## 7. Next Steps

1. **Train and evaluate the Stage 1 classifier** with the documented scripts, then publish only measured results. Confirm data sources and licenses before downloading.
2. **Implement remaining Phase 2 outbound checks** for PII, API keys, secrets, and system-prompt leakage.
3. **Harden Rate Limiting & Admin API (Phase 3)**:
   * Enforce `rate_limit_tokens_per_minute`, avoid recording rejected (`429`) hits in the sliding window, and add tenant update/deactivation/key-rotation endpoints.

