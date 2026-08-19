# VectorShield

**An AI security gateway for LLM applications.** It sits between your app and your model,
inspects every prompt before it reaches the model and every response before it reaches your
user, and logs the decision either way.

Built for the small team shipping a support chatbot as much as for the large platform:
point your existing OpenAI SDK at the gateway's URL and you are protected without rewriting
your client code.

```
                        VectorShield
      ┌──────────────────────────────────────────────────┐
      │                                                  │
      │   auth ─▶ rate limit ─▶ inbound inspection ──┐   │
Client ──▶│                          (LLM01, LLM04)       │   │
      │                                              ▼   │
      │                                    Decision Engine│──▶ block (403)
      │                                              │   │
      │                                              ▼   │
      │                                    system prompt  │
      │                                    + canary       │──▶ Target LLM
      │                                              │   │    (OpenAI / Ollama)
      │                                              ▼   │
Client ◀──│  ◀── outbound inspection ◀── Decision Engine  │◀── response
      │        (LLM06: PII, secrets, prompt leakage)     │
      │                                                  │
      │   every request logged (hashed) ──▶ SQLite/Postgres
      └──────────────────────────────────────────────────┘
```

---

## Status

VectorShield is being built in phases. This is honest about what exists today:

| Phase | Scope | Status |
|---|---|---|
| **0** | Real authenticated proxy, tenants + policy, decision engine, rate limiting, audit log | ✅ **shipped** |
| **1** | Module 1 — prompt injection / jailbreak detection (LLM01) | 🚧 next |
| **2** | Module 2 — data leakage & PII detection, canary verification (LLM06) | ⬜ planned |
| **3** | Module 3 — DoS/abuse hardening, token-budget limits (LLM04) | ⬜ planned |
| **4** | Module 4 — model extraction detection (LLM10) | ⬜ stretch |
| **5** | Streamlit ops dashboard + published benchmark table | ⬜ planned |

**The detection pipeline currently ships with zero detectors registered.** Phase 0 is the
proxy, the policy engine, and the seams the detectors plug into — everything is wired and
tested, but a prompt-injection attempt is not yet caught. Benchmark numbers will be published
in Phase 1 from a reproducible script; there are deliberately no invented figures here.

---

## Threat model

### What VectorShield defends against

| OWASP LLM Top 10 | Threat | How the gateway addresses it |
|---|---|---|
| **LLM01** | Prompt injection / jailbreaking | Staged inbound inspection: fast rules first, ML classifier only on ambiguous input. The gateway also owns the system prompt, so a client cannot override it. |
| **LLM04** | Model denial of service | Sliding-window rate limits per API key with escalating penalties (warn → throttle → block). |
| **LLM06** | Sensitive information disclosure | Outbound scanning for PII, API keys, and secrets, plus a canary token planted in the system prompt to catch prompt leakage. |
| **LLM10** | Model theft / extraction | Anomaly detection over per-tenant request patterns (stretch goal). |

### Explicitly out of scope

- **Training data poisoning.** A training-time problem, not a runtime gateway one. Nothing a proxy sees can address it.
- **Fine-tuning or hosting a model.** VectorShield proxies models; it does not train them.
- **Infrastructure security.** Securing the host, TLS termination, and network policy are the operator's job.
- **Guaranteed detection.** No prompt-injection defense is complete. VectorShield reduces risk and gives you an audit trail; it is a layer, not a solution.

### Trust assumptions

- The gateway is trusted with tenant system prompts and API keys. Run it inside your own infrastructure.
- Prompt text is **hashed by default** and never persisted in the clear unless you opt in with `STORE_CONTENT=true`. Blocked and sanitized requests always retain content so real attacks stay triageable.
- API keys are stored as SHA-256 hashes; the raw key is displayed exactly once, at creation.

---

## Quickstart

### 1. Install

```bash
git clone https://github.com/praneeth132006/VectorShield.git
cd VectorShield
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

### 2. Point it at a model

Fully offline, no API key, no cost:

```bash
ollama pull llama3.2:3b
```

Or use OpenAI — set `DEFAULT_PROVIDER=openai` and `OPENAI_API_KEY=sk-...` in `.env`.

### 3. Run

```bash
uvicorn app.main:app --reload
```

Interactive API docs: <http://localhost:8000/docs>

### 4. Get an API key

Set `ADMIN_TOKEN` in `.env`, restart, then:

```bash
curl -s localhost:8000/admin/tenants \
  -H "X-Admin-Token: $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"support-bot","system_prompt":"You are Acme support. Only discuss Acme products."}'
```

The response contains `api_key` — it is shown once and stored only as a hash.

### 5. Use it as a drop-in replacement

```python
from openai import OpenAI

client = OpenAI(
    base_url="http://localhost:8000/v1",  # the only line that changes
    api_key="vs_your_gateway_key",
)

client.chat.completions.create(
    model="llama3.2:3b",
    messages=[{"role": "user", "content": "What is your return policy?"}],
)
```

### Or run the whole stack in Docker

```bash
docker compose up
```

Brings up the gateway plus Redis. Your prompts never leave your infrastructure.

---

## The two API surfaces

| Route | Shape | Use it when |
|---|---|---|
| `POST /v1/chat/completions` | Byte-compatible with OpenAI | You have an existing app. Change `base_url`, change nothing else. |
| `POST /v1/gateway/chat` | OpenAI request + a full `security` report | You want the risk score, the findings, the decision, and the latency overhead back with every call. |

The native surface returns:

```jsonc
{
  "completion": { /* standard OpenAI chat completion */ },
  "security": {
    "request_id": "…",
    "inbound":  { "decision": "allow", "risk_score": 0.0, "findings": [], "stages_run": [] },
    "outbound": { "decision": "allow", "risk_score": 0.0, "findings": [] },
    "provider": "ollama",
    "overhead_ms": 1.83        // gateway cost, excluding the model call
  }
}
```

A blocked request returns **HTTP 403** with the same `security` block, so you always know why.

---

## Design decisions

**The ML classifier is never on the hot path.** Detectors declare a stage: stage 0 (regex,
structural checks) runs on every request in microseconds; stage 1 (classifier) and stage 2
(embeddings) run *only* when the accumulated risk lands in the ambiguous band between
`FLAG_THRESHOLD` and `BLOCK_THRESHOLD`. Confident-clean and confident-malicious traffic both
short-circuit. This is enforced by tests, not just convention.

**Detectors report; the Decision Engine decides.** A detector returns findings with a
confidence and a severity and nothing else. One place — `app/policy/engine.py` — turns those
into `allow` / `flag-and-log` / `sanitize` / `block`. Scores combine with noisy-OR, so several
weak signals accumulate without any single detector being able to dominate.

**Fail-open by default.** Only high-confidence findings block. Ambiguous ones are allowed and
logged, because a false positive that breaks a real customer's support chatbot costs more than
one logged probe. Flip any tenant to `fail_mode: "closed"` when the opposite is true for you.

**The gateway owns the system prompt.** When a tenant configures one, VectorShield strips
client-supplied system turns and prepends its own, with a unique canary token. A client cannot
drop your instructions, and if the canary ever appears in a response you know the system prompt
leaked.

**A broken detector cannot take down the proxy.** Detector exceptions are caught per-detector
and logged. Rate-limiter failures allow the request. Log-write failures never fail a user's call.

**Everything is per-tenant.** Thresholds, fail mode, rate limits, system prompt, and content
retention are all per-API-key, so an internal tool and a public chatbot can run different
policies on one gateway.

---

## Configuration

Every setting is an environment variable; see [`.env.example`](.env.example) for the annotated
list. The essentials:

| Variable | Default | Notes |
|---|---|---|
| `DEFAULT_PROVIDER` | `ollama` | `ollama` (free/offline) or `openai` |
| `DATABASE_URL` | SQLite file | Use a `postgresql+asyncpg://` URL in production |
| `REDIS_URL` | *(empty)* | Empty = in-process limiter. **Set this if you run more than one worker.** |
| `FAIL_MODE` | `open` | `open` flags ambiguous traffic; `closed` blocks it |
| `BLOCK_THRESHOLD` / `FLAG_THRESHOLD` | `0.85` / `0.45` | The ambiguous band between them is what escalates to expensive stages |
| `STORE_CONTENT` | `false` | `true` persists raw prompts and responses |
| `ADMIN_TOKEN` | *(empty)* | Empty disables the admin API entirely |

---

## Development

```bash
pip install -r requirements-dev.txt
pytest          # test suite
ruff check .    # lint
ruff format .   # format
```

See [CONTRIBUTING.md](CONTRIBUTING.md), including how to add a new detection rule.

## License

[MIT](LICENSE)
