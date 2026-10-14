"""Audit prepared splits and compare rules, always-on ML, and gated hybrid detection.

Thresholds are selected on the jackhhao validation split with a 5% maximum
validation false-positive rate. Test files are evaluated only after selection.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import statistics
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.detectors.base import InspectionContext  # noqa: E402
from app.detectors.ml import TfidfInjectionDetector  # noqa: E402
from app.detectors.pipeline import DetectionPipeline, inspection_context  # noqa: E402
from app.detectors.rules import InjectionRulesDetector  # noqa: E402
from app.models.schemas import Decision, Direction  # noqa: E402
from app.policy.engine import decide, score  # noqa: E402

PROC = ROOT / "data" / "processed"
OUT = ROOT / "results"
TEST_SETS = ["jackhhao", "gandalf", "support_benign"]
VALIDATION_FPR_CAP = 0.05
BLOCK_THRESHOLD = 0.85
ML_MIN_PROBABILITY = 0.30
POLICY_BASE = {
    "block_threshold": BLOCK_THRESHOLD,
    "fail_mode": "open",
    "canary_token": None,
    "system_prompt": None,
    "tenant_id": "eval",
}


def percentile(values: list[float], q: float) -> float:
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(q * len(ordered)))]


def normalized(text: str) -> str:
    return " ".join(str(text).lower().split())


def read_frame(name: str) -> pd.DataFrame:
    path = PROC / f"{name}.csv"
    if not path.exists():
        raise FileNotFoundError(f"required prepared split missing: {path}")
    frame = pd.read_csv(path)
    if not {"text", "label"}.issubset(frame.columns):
        raise ValueError(f"{path.name} must contain text,label columns")
    if frame[["text", "label"]].isna().any().any():
        raise ValueError(f"{path.name} contains missing text or labels")
    if not set(frame["label"].astype(int).unique()).issubset({0, 1}):
        raise ValueError(f"{path.name} labels must be binary 0/1")
    if frame["text"].astype(str).str.strip().eq("").any():
        raise ValueError(f"{path.name} contains empty text")
    return frame


def audit_splits(frames: dict[str, pd.DataFrame]) -> dict[str, Any]:
    keys = {
        name: set(frame["text"].astype(str).map(normalized)) for name, frame in frames.items()
    }
    duplicates = {
        name: int(frame["text"].astype(str).map(normalized).duplicated().sum())
        for name, frame in frames.items()
    }
    overlaps = {
        f"{left}/{right}": len(keys[left] & keys[right])
        for index, left in enumerate(frames)
        for right in list(frames)[index + 1 :]
    }
    if any(duplicates.values()) or any(overlaps.values()):
        raise ValueError(f"normalized duplicate/overlap detected: {duplicates=}, {overlaps=}")
    return {
        "normalized_exact_duplicates_within_split": duplicates,
        "normalized_exact_overlap_between_splits": overlaps,
        "labels": {
            name: frame["label"].astype(int).value_counts().sort_index().to_dict()
            for name, frame in frames.items()
        },
        "rows": {name: len(frame) for name, frame in frames.items()},
        "label_mapping": {
            "jackhhao type jailbreak": 1,
            "jackhhao type benign": 0,
            "Lakera Gandalf rows (attack-only)": 1,
        },
        "limitations": [
            "Exact normalized text duplicates are checked; semantic or paraphrase overlap "
            "is not.",
            "Gandalf is attack-only and cannot estimate precision or false-positive rate.",
            "Support-benign prompts are a hand-written holdout, not a representative "
            "production sample.",
        ],
    }


def metrics(labels: list[int], predicted: list[bool]) -> dict[str, Any]:
    tp = sum(y == 1 and p for y, p in zip(labels, predicted, strict=True))
    fn = sum(y == 1 and not p for y, p in zip(labels, predicted, strict=True))
    fp = sum(y == 0 and p for y, p in zip(labels, predicted, strict=True))
    tn = sum(y == 0 and not p for y, p in zip(labels, predicted, strict=True))
    has_positive = tp + fn > 0
    has_negative = fp + tn > 0
    precision = tp / (tp + fp) if has_positive and has_negative and tp + fp else None
    recall = tp / (tp + fn) if has_positive else None
    fpr = fp / (fp + tn) if fp + tn else None
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision is not None and recall is not None and precision + recall > 0
        else (0.0 if has_positive and has_negative else None)
    )
    return {
        "confusion_matrix": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "fpr": fpr,
    }


def make_policy(threshold: float) -> SimpleNamespace:
    return SimpleNamespace(**POLICY_BASE, flag_threshold=threshold)


def threshold_candidates(name: str) -> list[float]:
    candidates = [round(value / 100, 2) for value in range(30, 96)]
    return [
        threshold
        for threshold in candidates
        if threshold <= BLOCK_THRESHOLD
        and (name != "gated_hybrid" or threshold < BLOCK_THRESHOLD)
    ]


def tune_threshold(
    name: str,
    observations: list[tuple[list[Any], list[Any]]],
    labels: list[int],
) -> dict[str, Any]:
    candidates = threshold_candidates(name)
    trials: list[tuple[float, float, float | None, dict[str, Any]]] = []
    for threshold in candidates:
        policy = make_policy(threshold)
        predicted: list[bool] = []
        for rule_findings, ml_findings in observations:
            rule_risk = score(rule_findings)
            if name == "rules_only":
                final = rule_findings
            elif name == "ml_every_request":
                final = ml_findings
            elif rule_risk >= policy.block_threshold or rule_risk < threshold:
                final = rule_findings
            else:
                final = [*rule_findings, *ml_findings]
            verdict = decide(final, policy, Direction.INBOUND)
            predicted.append(verdict.decision is not Decision.ALLOW)
        result = metrics(labels, predicted)
        fpr = result["fpr"]
        if fpr is not None and fpr <= VALIDATION_FPR_CAP:
            trials.append((result["recall"] or 0.0, threshold, result["precision"], result))
    if not trials:
        raise ValueError(
            f"no validation threshold for {name} meets FPR cap {VALIDATION_FPR_CAP}"
        )
    _recall, threshold, _precision, result = max(trials, key=lambda item: (item[0], item[1]))
    return {
        "flag_threshold": threshold,
        "validation_fpr_cap": VALIDATION_FPR_CAP,
        "validation_metrics": result,
        "selection_rule": "maximum validation recall within FPR cap; ties choose higher "
        "threshold",
    }


async def observe_validation(
    frame: pd.DataFrame, rules: InjectionRulesDetector, ml: TfidfInjectionDetector
) -> tuple[list[tuple[list[Any], list[Any]]], list[int]]:
    observations = []
    for text in frame["text"].astype(str):
        ctx = InspectionContext(text=text, direction=Direction.INBOUND)
        rule_findings = await rules.inspect(ctx)
        ml_findings = await ml.inspect(ctx)
        observations.append((rule_findings, ml_findings))
    return observations, frame["label"].astype(int).tolist()


async def run_config(
    pipeline: DetectionPipeline, texts: list[str], threshold: float
) -> tuple[list[bool], list[float], int]:
    policy = make_policy(threshold)
    predicted: list[bool] = []
    latencies: list[float] = []
    stage1_requests = 0
    for text in texts:
        verdict = await pipeline.inspect(
            inspection_context(text, Direction.INBOUND, policy), policy
        )
        predicted.append(verdict.decision is not Decision.ALLOW)
        latencies.append(verdict.latency_ms)
        stage1_requests += any(stage.startswith("stage1:") for stage in verdict.stages_run)
    return predicted, latencies, stage1_requests


def probability_diagnostics(
    detector: TfidfInjectionDetector, frame: pd.DataFrame
) -> dict[str, Any]:
    attacks = frame.loc[frame["label"].astype(int) == 1]
    values = [
        (str(row.text), detector.probability(str(row.text))) for row in attacks.itertuples()
    ]
    probabilities = [p for _, p in values if p is not None]
    lengths = [len(text[:4000]) for text, _ in values]
    return {
        "attack_rows": len(values),
        "mean_chars_after_4000_char_cap": statistics.mean(lengths) if lengths else None,
        "median_chars_after_4000_char_cap": statistics.median(lengths) if lengths else None,
        "mean_ml_probability": statistics.mean(probabilities) if probabilities else None,
        "median_ml_probability": statistics.median(probabilities) if probabilities else None,
        "recall_at_fixed_0.45": sum(p >= 0.45 for p in probabilities) / len(probabilities)
        if probabilities
        else None,
        "share_below_detector_min_probability_0.30": sum(
            p < ML_MIN_PROBABILITY for p in probabilities
        )
        / len(probabilities)
        if probabilities
        else None,
        "probability_quartiles": (
            {str(q): float(pd.Series(probabilities).quantile(q)) for q in (0.25, 0.5, 0.75)}
            if probabilities
            else None
        ),
    }


async def main_async(limit: int | None) -> int:
    if (PROC / "FALLBACK_USED.txt").exists():
        print(
            "ERROR: fallback marker exists; refusing to report fallback-data metrics.",
            file=sys.stderr,
        )
        return 2
    frames = {
        name: read_frame(name) for name in ["train", "val", *[f"test_{s}" for s in TEST_SETS]]
    }
    split_audit = audit_splits(frames)
    if limit is not None:
        frames = {
            name: frame.sample(n=min(limit, len(frame)), random_state=0).reset_index(drop=True)
            if name.startswith("test_")
            else frame
            for name, frame in frames.items()
        }

    ml = TfidfInjectionDetector()
    if not ml.available:
        print(
            "ERROR: model not found. Run scripts/train_classifier.py first.", file=sys.stderr
        )
        return 1
    await ml.warmup()
    rules = InjectionRulesDetector()
    observations, val_labels = await observe_validation(frames["val"], rules, ml)
    tuned = {
        name: tune_threshold(name, observations, val_labels)
        for name in ("rules_only", "ml_every_request", "gated_hybrid")
    }
    configs = {
        "rules_only": DetectionPipeline([rules]),
        "ml_every_request": DetectionPipeline([ml]),
        "gated_hybrid": DetectionPipeline([rules, ml]),
    }
    report: dict[str, Any] = {
        "fallback_data": (PROC / "FALLBACK_USED.txt").exists(),
        "threshold_selection_split": "val (jackhhao train partition, stratified 90/10)",
        "test_sets_touched_for_tuning": False,
        "split_audit": split_audit,
        "thresholds": tuned,
        "results": {},
        "latency_ms": {},
    }
    all_test_texts = [
        str(text) for name in TEST_SETS for text in frames[f"test_{name}"]["text"]
    ]
    latency_values: dict[str, list[float]] = {name: [] for name in configs}
    stage1_counts: dict[str, int] = dict.fromkeys(configs, 0)
    for cfg_name, pipeline in configs.items():
        threshold = tuned[cfg_name]["flag_threshold"]
        await pipeline.warmup()
        # Warm the code path before collecting latency, without recording this sample.
        if all_test_texts:
            await run_config(
                pipeline, all_test_texts[: min(10, len(all_test_texts))], threshold
            )
        for set_name in TEST_SETS:
            frame = frames[f"test_{set_name}"]
            labels = frame["label"].astype(int).tolist()
            predicted, latency, stage1_requests = await run_config(
                pipeline, frame["text"].astype(str).tolist(), threshold
            )
            latency_values[cfg_name].extend(latency)
            stage1_counts[cfg_name] += stage1_requests
            report["results"].setdefault(cfg_name, {})[set_name] = {
                "n": len(frame),
                "metrics": metrics(labels, predicted),
            }
    for cfg_name, values in latency_values.items():
        report["latency_ms"][cfg_name] = {
            "n_requests": len(values),
            "p50": statistics.median(values),
            "p95": percentile(values, 0.95),
            "max": max(values),
        }
    report["stage1_invocations"] = {
        name: {"requests": count, "total_test_requests": len(all_test_texts)}
        for name, count in stage1_counts.items()
    }
    report["recall_drop_diagnostics"] = {
        "test_jackhhao": probability_diagnostics(ml, frames["test_jackhhao"]),
        "test_gandalf": probability_diagnostics(ml, frames["test_gandalf"]),
    }

    lines = [
        "# VectorShield evaluation",
        "",
        "Validation thresholds were independently selected for each configuration to "
        "maximize recall",
        f"subject to validation FPR <= {VALIDATION_FPR_CAP:.0%}. "
        "Test sets were not used for tuning.",
        "",
        "| config | tuned flag threshold | test set | n | precision | recall | "
        "F1 | FPR | TP | FP | TN | FN |",
        "|---|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for cfg_name, sets in report["results"].items():
        for set_name, entry in sets.items():
            m = entry["metrics"]
            cm = m["confusion_matrix"]

            def show(value: float | None) -> str:
                return "n/a" if value is None else f"{value:.3f}"

            lines.append(
                f"| {cfg_name} | {tuned[cfg_name]['flag_threshold']:.2f} | "
                f"{set_name} | {entry['n']} | "
                f"{show(m['precision'])} | {show(m['recall'])} | "
                f"{show(m['f1'])} | {show(m['fpr'])} | "
                f"{cm['tp']} | {cm['fp']} | {cm['tn']} | {cm['fn']} |"
            )
    lines += [
        "",
        "## Latency per request (ms)",
        "",
        "| config | n | p50 | p95 | max |",
        "|---|---:|---:|---:|---:|",
    ]
    for cfg_name, value in report["latency_ms"].items():
        lines.append(
            f"| {cfg_name} | {value['n_requests']} | {value['p50']:.3f} | "
            f"{value['p95']:.3f} | {value['max']:.3f} |"
        )
    lines += [
        "",
        "## Stage 1 invocations",
        "",
        "| config | calls | total test requests |",
        "|---|---:|---:|",
    ]
    for cfg_name, value in report["stage1_invocations"].items():
        lines.append(f"| {cfg_name} | {value['requests']} | {value['total_test_requests']} |")
    lines += [
        "",
        "Gandalf is attack-only (precision/FPR unavailable); support_benign is "
        "benign-only (recall unavailable).",
        "The ML-on-every-request benchmark uses the same Stage 1 detector at evaluation "
        "Stage 0 only; this is an offline comparison, not the shipped gateway pipeline.",
    ]
    OUT.mkdir(exist_ok=True)
    (OUT / "eval_results.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (OUT / "eval_results.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print("\n".join(lines))
    print("\nRecall diagnostics:")
    print(json.dumps(report["recall_drop_diagnostics"], indent=2))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--limit", type=int, default=None, help="sample test sets (smoke tests only)"
    )
    args = parser.parse_args()
    return asyncio.run(main_async(args.limit))


if __name__ == "__main__":
    raise SystemExit(main())
