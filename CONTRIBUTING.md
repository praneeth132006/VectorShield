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

### Adding an outbound signature instead

Response scanning ([`app/detectors/leakage.py`](app/detectors/leakage.py)) has a
lower ceiling and a higher bar. There is no stage 1 out here — the customer is
already waiting on the answer — so confidence has to come from structure: a key
shape, a checksum, a random canary, shingle overlap with the system prompt.

Two rules specific to this direction:

- **Report every occurrence, not just the first.** Put them all in
  `metadata["matches"]`; that list is exactly what the gateway redacts. A finding
  that reports one of forty leaked email addresses redacts one of forty.
- **A shape that ordinary text also has needs corroboration.** `ddd-dd-dddd` is a
  Social Security number *and* a warehouse bay number. Give the signature a
  `context` pattern: with the surrounding words, it is a real finding; without
  them, it drops to `uncorroborated_confidence` and only reaches the audit log.

Prefer redaction to refusal. A finding only sets `metadata["unredactable"]` when
removing the flagged spans would not actually contain the leak — today that is
the canary alone, because the marker's presence means the surrounding text *is*
the system prompt.

### Adding a resource limit instead

Before writing a detector, ask whether the thing you are checking has a
judgement in it. "This prompt is 90,000 characters" and "this key has spent its
minute's tokens" do not — they are facts with one correct answer, and they
belong in [`app/ratelimit/quota.py`](app/ratelimit/quota.py) as a hard limit
that refuses with a 413 or 429 before any detector runs. "This prompt looks like
a repetition bomb" does have a judgement in it, so it belongs in
[`app/detectors/abuse.py`](app/detectors/abuse.py) and goes through the normal
detector contract.

Getting this backwards is the common mistake. A limit expressed as a detector
becomes a threshold someone has to tune; a judgement expressed as a limit
becomes a hard refusal of traffic that was probably fine.

If you add a limit, add it per tenant as well as globally — `None` inherits the
default, `0` lifts it — and make sure both API surfaces enforce it. A cap you can
dodge by switching from `/v1/gateway/chat` to `/v1/chat/completions` is not a cap,
and `tests/test_abuse_e2e.py` has a test that says so.

### Adding a behavioral signal instead

[`app/detectors/extraction.py`](app/detectors/extraction.py) is the one detector
that looks across requests rather than at one. If you add a signal there:

- **Store a fingerprint, never the prompt.** The profile keeps a 64-bit SimHash
  and a slot-blanked skeleton. A gateway that hashes prompts by default must not
  keep a plaintext shadow copy of them in memory to do analysis on.
- **Bound the state.** Per-tenant history is a `deque` with a `maxlen`. A busy
  tenant must not be able to grow it without limit.
- **Cap the confidence below the block band.** Volume is never certain about
  intent — repetition is what a batch classification workload looks like. These
  signals flag; they do not block, and `test_extraction_findings_never_reach_the_block_band`
  enforces it.
- **Calibrate against repetitive benign traffic, not just against attacks.** The
  near-duplicate threshold in that module is a measured number with its
  derivation written down, not a guess. If you change it, re-measure and say so.

### 5. Test it — including the false positives

Every new detector needs three kinds of test:

1. **True positives** — the attacks it should catch.
2. **False positives** — realistic, benign prompts it must *not* fire on. This is the test reviewers read first.
3. **Stage discipline** — proof it does not escalate traffic it should have settled cheaply (see `tests/test_pipeline.py`).

For a behavioral signal, the false-positive test is a whole *session* of
realistic repetitive traffic, not a single prompt — a support queue asking the
same twenty questions all day has to pass clean.

A detector that raises the false-positive rate on the benchmark suite will not be
merged, however many attacks it catches.

### 6. Show the benchmark delta

Run it before and after your change and put both in the PR:

```bash
python -m benchmark.run_benchmark
```

If your change also touches training, retrain first (`python -m training.train_classifier`)
and say which datasets you used. Only public datasets — no proprietary data, ever.

Watch the latency table as well as the detection ones. Every stage 0 detector is
paid for on every single request: adding the LLM04 and LLM10 detectors roughly
doubled median overhead, which was worth it and was reported rather than quietly
absorbed. Do the same.

### Changing the dashboard

The query layer is [`dashboard/data.py`](dashboard/data.py) and it is tested;
[`dashboard/ops.py`](dashboard/ops.py) is rendering only. Put aggregation in the
former so a chart cannot quietly disagree with the query behind it, and keep
reads working on both SQLite and Postgres — `date_trunc` and percentile
functions exist on one and not the other, which is why bucketing and percentiles
are done in Python.

## Reporting a vulnerability

Do not open a public issue for a security flaw in the gateway itself. Open a private
security advisory on the GitHub repository instead.

Bypasses of the *detection rules* are different — those are ordinary issues, and
finding them publicly is genuinely useful. Please include the exact prompt.
