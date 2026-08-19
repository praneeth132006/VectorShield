# Contributing to VectorShield

Thanks for helping. VectorShield is a security tool, so the bar for correctness is
higher than the bar for features — a detector that is wrong in production is worse
than a detector that does not exist.

## Getting set up

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
cp .env.example .env
pytest
```

The test suite runs against a mock upstream model, so it needs no API keys, no
network, no Redis, and no Ollama.

## Before you open a PR

```bash
ruff check .          # lint
ruff format .         # format
pytest                # all tests must pass
```

CI runs the same three commands on Python 3.11, 3.12, and 3.13.

## Coding style

- `ruff format` decides formatting. Do not hand-format.
- Type hints on everything public. `from __future__ import annotations` at the top of each module.
- Async all the way down — no blocking I/O inside a request path.
- Comments explain *why*, not *what*. If the code needs a comment to say what it does, rename something instead.
- Never log raw prompt content outside the audit layer, and never log an API key or canary token.

## Adding a new detection rule

Detectors report; they never decide. Yours returns findings with a confidence and a
severity, and `app/policy/engine.py` turns findings into a decision.

### 1. Pick a stage — this matters more than the rule itself

| Stage | Cost budget | What belongs here |
|---|---|---|
| `0` | microseconds | Regex, keyword, encoding and structural checks. Runs on **every** request. |
| `1` | ~10ms | The TF-IDF/LogReg classifier. Runs only on requests triage marks as worth a deeper look (~24% of traffic). |
| `2` | ~100ms | Embedding similarity, LLM-as-judge. Runs only when stage 1 is still ambiguous. |

**Putting an expensive check at stage 0 will be rejected in review.** The whole
architecture rests on cheap checks filtering the bulk of traffic.

### 2. Write the detector

```python
# app/detectors/rules.py
from app.detectors.base import Detector, InspectionContext
from app.models.schemas import Direction, Finding, OwaspCategory, Severity


class MyRuleDetector(Detector):
    name = "my-rule"
    stage = 0
    directions = (Direction.INBOUND,)

    async def inspect(self, ctx: InspectionContext) -> list[Finding]:
        if "some pattern" not in ctx.text.lower():
            return []
        return [
            Finding(
                detector=self.name,
                category=OwaspCategory.LLM01_PROMPT_INJECTION,
                severity=Severity.HIGH,
                confidence=0.9,
                message="Matched the known X pattern",
                direction=ctx.direction,
                evidence="the exact matched substring",  # enables sanitization
            )
        ]
```

Rules for detectors:

- **Never raise.** The pipeline catches exceptions, but a detector that throws is a bug.
- **Be honest about confidence.** `0.95` means "I would stake a block on this." A keyword that also appears in legitimate traffic is not a `0.95`.
- **Set `evidence`** to the exact matched substring when you can — it is what makes outbound redaction possible.
- **Localize with `span`** when the match has a position.

### 3. If your rule needs escalation, edit triage instead

A stage 1 or stage 2 detector only sees a request if
[`app/detectors/triage.py`](app/detectors/triage.py) decided the request was worth a deeper
look. If you are adding an attack family that the cheap rules cannot match — subtle indirect
injection, a new language, an unfamiliar structure — the change probably belongs in triage,
not in a new stage 0 rule.

Triage plays by inverted rules: it is *supposed* to over-trigger, and its precision does not
matter, because everything it selects is judged by a real detector afterwards. What does matter:

- **Cost.** It runs on every request. Keep it to plain regex over the normalized text.
- **Ordinary traffic.** Every term you add is checked against `ORDINARY` in `tests/test_triage.py`. Generic words fail here for good reason — bare `policy` was removed because "what is your return policy?" is the single most common support question there is.

### 4. Register it

Add it in `build_inbound_pipeline()` (or `build_outbound_pipeline()`) in
`app/detectors/pipeline.py`.

### 5. Test it — including the false positives

Every new detector needs three kinds of test:

1. **True positives** — the attacks it should catch.
2. **False positives** — realistic, benign prompts it must *not* fire on. This is the test reviewers read first.
3. **Stage discipline** — proof it does not escalate traffic it should have settled cheaply (see `tests/test_pipeline.py`).

A detector that raises the false-positive rate on the benchmark suite will not be
merged, however many attacks it catches.

### 6. Show the benchmark delta

Run it before and after your change and put both in the PR:

```bash
python -m benchmark.run_benchmark
```

If your change also touches training, retrain first (`python -m training.train_classifier`)
and say which datasets you used. Only public datasets — no proprietary data, ever.

## Reporting a vulnerability

Do not open a public issue for a security flaw in the gateway itself. Open a private
security advisory on the GitHub repository instead.

Bypasses of the *detection rules* are different — those are ordinary issues, and
finding them publicly is genuinely useful. Please include the exact prompt.
