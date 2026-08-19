### Detection quality

Held-out split of deepset/prompt-injections, vectorshield/seed (194 examples the classifier never saw).

| Counted as a detection | Precision | Recall | F1 | False-positive rate |
|---|---|---|---|---|
| Blocked only | 1.000 | 0.163 | 0.280 | 0.000 |
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

### Latency overhead

Gateway cost per request, excluding the upstream model call (200 rounds).

| Median | Mean | p95 | p99 |
|---|---|---|---|
| 0.223 ms | 0.711 ms | 2.025 ms | 2.535 ms |

Stage 1 (the classifier) ran on **24.2%** of held-out requests; the rest were settled by the rule layer alone.
