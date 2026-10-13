# AI Agent Guidelines (`AGENTS.md`)

Instructions for AI coding assistants working on the **VectorShield** repository. Follow these rules strictly on every task.

---

## 1. Mandatory Onboarding & Context Reading

1. **Read core documentation first**: Before proposing plans or writing code, always read:
   * `PROJECT_CONTEXT.md` — current implementation status, module map, known issues, and roadmap.
   * `README.md` — threat model, API surfaces, and design philosophy.
   * `CONTRIBUTING.md` — coding style and rules for adding detection stages.
2. **Inspect before editing**: Read the relevant source files in `app/` and corresponding test files in `tests/` before modifying any code.
3. **Skip hidden/generated directories**: Do not read or traverse `.git/`, `.venv/`, `__pycache__/`, `.pytest_cache/`, or `.ruff_cache/`.

---

## 2. Command & Environment Safety

* **Never install packages without permission**: Do not run `pip install`, modify virtual environments, or add new third-party dependencies to `requirements.txt` / `requirements-dev.txt` without explicit user approval.
* **Never run destructive commands without permission**: Do not delete files, drop databases, reset git state (`git reset --hard`, `git clean`, `git push --force`), or overwrite untracked user files without asking the user first.
* **Ask before running shell commands** when the user has requested a read-only or documentation-only task.

---

## 3. Architectural Invariants to Preserve

1. **Staged Detection Discipline (`app/detectors/`)**:
   * **Stage 0** (microseconds: regex, keyword, encoding, structural checks) runs on every request.
   * **Stage 1** (~10ms: ML classifier) and **Stage 2** (~100ms: embeddings / LLM-as-judge) run **only** when the accumulated risk score lands in the ambiguous band `[flag_threshold, block_threshold)`.
   * Never place expensive checks or I/O at Stage 0.
2. **Detectors Report; the Decision Engine Decides**:
   * Detectors inherit from `Detector` (`app/detectors/base.py`), return `list[Finding]` with an honest `confidence` and `severity`, and must **never** make allow/block decisions or raise unhandled exceptions.
   * Only `app/policy/engine.py` (`score()` and `decide()`) converts findings into `allow`, `flag-and-log`, `sanitize`, or `block`.
   * Register shipped detectors in `build_pipeline()` inside `app/detectors/pipeline.py`.
3. **Single Shared Gateway Core (`app/gateway.py`)**:
   * Both `POST /v1/chat/completions` and `POST /v1/gateway/chat` must route through `process_chat()` in `app/gateway.py` so security enforcement never drifts between the two surfaces.
4. **Fail-Safe Operation**:
   * A broken detector, unreachable Redis instance, or failed audit database write must never crash a user's request. Preserve per-detector exception catching and fallback behavior.
5. **Code Style & Async Conventions**:
   * Include `from __future__ import annotations` at the top of every Python module.
   * Keep the request path 100% async (`async`/`await` with `httpx`, `sqlalchemy.ext.asyncio`, `aiosqlite`/`asyncpg`) — never introduce blocking I/O.
   * Add type annotations to all public functions, methods, and schemas.
   * Adhere to Ruff settings in `pyproject.toml` (`line-length = 95`, target `py311`).

---

## 4. Security & Secret Hygiene

* **Never expose or commit secrets**: Never hardcode or commit real `OPENAI_API_KEY`s, `ADMIN_TOKEN`s, tenant `vs_...` API keys, or `.env` files. Use placeholder fixture values in tests.
* **Respect privacy-by-default logging**:
  * Never log raw prompt or response text outside `app/audit.py` (which respects `store_content` and `BLOCK`/`SANITIZE` retention rules).
  * Never log raw tenant API keys (only store/compare SHA-256 hashes via `hash_key()`) or raw `canary_token` values.
* **Do not commit data or model binaries**: Keep `*.db`, `*.sqlite3`, `*.joblib`, `*.pkl`, `training/data/*`, and `benchmark/results/*` out of version control.

---

## 5. Testing & Verification Requirements

Every code or detector change must include corresponding tests in `tests/`:

* **General changes**: Add or update async unit/integration tests using the `client`, `tenant`, `auth`, and `mock_provider` fixtures in `tests/conftest.py` (no external network, Redis, or Ollama required).
* **New detectors**: Must include all three test categories:
  1. **True positives** — adversarial inputs the detector must catch.
  2. **False positives** — realistic benign prompts the detector must *not* flag.
  3. **Stage discipline** — verification that unambiguous traffic short-circuits without invoking deeper stages (`tests/test_pipeline.py`).
* **Verification checks**:
  ```powershell
  ruff check .
  ruff format --check .
  pytest
  ```

