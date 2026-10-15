# VectorShield dashboard (React)

A React + Vite console for the FastAPI gateway. Four views: **Overview**,
**Prompt scanner**, **Threat analytics**, and **System health**.

In development, Vite proxies `/health` and `/v1/*` to `http://127.0.0.1:8000`.
Override the target with `VITE_API_PROXY_TARGET` if the gateway listens elsewhere.

## Run locally

Start the gateway in one terminal, from the repository root:

```bash
.venv/bin/python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Start the dashboard in a second terminal:

```bash
cd frontend && npm install && npm run dev
```

Open <http://127.0.0.1:5173> and paste a tenant API key into **Prompt scanner**
(`BOOTSTRAP_API_KEY` from your `.env` works for local runs). The key is held in
page memory and sent as `X-API-Key`; it is never written to browser storage.

**Security test mode is on by default.** It sends `dry_run: true`, which runs the
full inbound inspection without calling the upstream model — so the scanner works
with no Ollama or OpenAI configured. Turn it off only when you want an allowed
prompt forwarded to a real provider.

## Production build

```bash
cd frontend && npm run build
```

To serve the built assets from a different origin than the API, set
`VITE_API_BASE_URL` at build time to the FastAPI origin. `/health` is public;
`/v1/gateway/chat` requires the tenant key.

## Scope

Scan history and analytics are derived only from responses received in the current
browser tab. The gateway exposes no historical scan endpoint, and this dashboard
persists neither prompts nor reports. For history across restarts — every request,
decision, and finding from the audit database — use the Streamlit ops dashboard:

```bash
.venv/bin/python -m streamlit run dashboard/ops.py
```
