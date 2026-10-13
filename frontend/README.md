# VectorShield dashboard

The dashboard is a React + Vite frontend for the existing FastAPI gateway. During development, Vite proxies `/health` and `/v1/*` to `http://127.0.0.1:8000`. Override the proxy with `VITE_API_PROXY_TARGET` if the backend listens elsewhere.

## Run locally

Start the backend in one PowerShell terminal from the repository root:

```powershell
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Start the dashboard in a second terminal:

```powershell
cd frontend
npm.cmd install
npm.cmd run dev
```

Open <http://127.0.0.1:5173>. Add a tenant API key in Prompt scanner. The key is held in page memory and sent using `X-API-Key`; it is not saved to browser storage. Security test mode is enabled by default. It sends `dry_run: true`, which runs inbound inspection without calling the upstream model. Turn it off only when you want to forward an allowed prompt to Ollama or OpenAI.

## Production build

```powershell
cd frontend
npm.cmd run build
```

To serve the built frontend from a separate origin, set `VITE_API_BASE_URL` at build time to the FastAPI origin. The FastAPI `/health` endpoint is public; `/v1/gateway/chat` requires the tenant key.

Scan history and analytics are derived only from reports received in the current browser session. The backend does not expose a historical scan endpoint, and the dashboard does not persist prompts or reports.
