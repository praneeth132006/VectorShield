### Detection quality

Held-out split of deepset/prompt-injections, vectorshield/seed (194 examples the classifier never saw).

| Counted as a detection | Precision | Recall | F1 | False-positive rate |
|---|---|---|---|---|
| Blocked only | 1.000 | 0.175 | 0.298 | 0.000 |
| Blocked or flagged | 0.962 | 0.625 | 0.758 | 0.018 |

### Evasion robustness

The same four attacks, rewritten with each technique.

| Obfuscation | Detected | Blocked |
|---|---|---|
| none (plain text) | 4/4 | 4/4 |
| zero-width padding | 4/4 | 4/4 |
| letter spacing | 4/4 | 4/4 |
| punctuation splitting | 4/4 | 4/4 |
| leetspeak | 4/4 | 4/4 |
| homoglyphs | 4/4 | 4/4 |
| base64 payload | 4/4 | 4/4 |
| rot13 | 4/4 | 4/4 |

### Outbound leakage (LLM06)

This repo's own response corpus (60 model answers, self-authored -- there is no public equivalent). A redaction counts as a detection.

| Precision | Recall | F1 | False-positive rate |
|---|---|---|---|
| 1.000 | 1.000 | 1.000 | 0.000 |

| Leak type | Detected |
|---|---|
| anthropic | 1/1 |
| assigned | 1/1 |
| aws | 2/2 |
| canary | 2/2 |
| card | 1/1 |
| db-url | 2/2 |
| gateway-key | 1/1 |
| github | 1/1 |
| google | 1/1 |
| iban | 1/1 |
| jwt | 1/1 |
| openai | 2/2 |
| private-key | 1/1 |
| record | 3/3 |
| slack | 1/1 |
| ssn | 1/1 |
| stripe | 1/1 |
| system-prompt | 3/3 |

### Resource abuse (LLM04)

This repo's own corpus (42 requests, self-authored): 18 shaped to cost more than they look, against 24 verbose but legitimate ones. A finding of any confidence counts as a detection, since most of these are designed to flag rather than block.

| Precision | Recall | F1 | False-positive rate |
|---|---|---|---|
| 1.000 | 1.000 | 1.000 | 0.000 |

| Abuse shape | Detected |
|---|---|
| character-run | 2/2 |
| huge-output | 5/5 |
| low-diversity | 1/1 |
| repeated-phrase | 2/2 |
| unbounded-output | 8/8 |

### Extraction (LLM10)

Scored over whole sessions (8 of them), because a single prompt cannot be extraction. A session counts as detected if any request in it produced an LLM10 finding. The ordinary sessions are deliberately repetitive -- a support queue and a batch job repeat themselves constantly, and neither is theft.

| Precision | Recall | F1 | False-positive rate |
|---|---|---|---|
| 1.000 | 1.000 | 1.000 | 0.000 |

| Probing session | Detected | Requests | Caught at request # |
|---|---|---|---|
| classification-harvest | yes | 30 | 13 |
| config-probing | yes | 12 | 9 |
| slot-enumeration | yes | 30 | 13 |
| templated-sweep | yes | 30 | 14 |
| translation-harvest | yes | 30 | 16 |

### Latency overhead

Gateway cost per request, excluding the upstream model call (200 rounds).

| Median | Mean | p95 | p99 |
|---|---|---|---|
| 0.348 ms | 0.940 ms | 2.748 ms | 4.982 ms |

Stage 1 (the classifier) ran on **24.2%** of held-out requests; the rest were settled by the rule layer alone.
