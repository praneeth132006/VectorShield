"""Train the stage 1 prompt-injection classifier.

    python -m training.train_classifier                 # all public sources
    python -m training.train_classifier --sources seed  # offline, no network

TF-IDF + Logistic Regression on purpose. It is fast enough to sit behind the
rule layer (single-digit milliseconds), it is interpretable -- you can print the
features that drove a decision -- and it gives an honest baseline for anything
heavier that replaces it later.
"""

from __future__ import annotations

import argparse
import json
import logging
import time
from pathlib import Path

import joblib
import numpy as np
from sklearn.calibration import CalibratedClassifierCV
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    average_precision_score,
    classification_report,
    confusion_matrix,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import FeatureUnion, Pipeline

from app.detectors.normalize import normalize
from training.corpus import load_corpus

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("train")

DEFAULT_OUTPUT = Path("models/injection_clf.joblib")


def preprocess(texts: list[str]) -> list[str]:
    """Apply the same normalization the gateway applies at inference time.

    Training on raw text while serving normalized text is a classic
    train/serve skew bug -- both paths go through app.detectors.normalize.
    """
    return [normalize(t).basic for t in texts]


def build_pipeline() -> Pipeline:
    return Pipeline(
        [
            (
                "features",
                FeatureUnion(
                    [
                        # Word n-grams catch phrasing: "ignore previous instructions".
                        (
                            "word",
                            TfidfVectorizer(
                                analyzer="word",
                                ngram_range=(1, 2),
                                min_df=2,
                                sublinear_tf=True,
                                strip_accents="unicode",
                            ),
                        ),
                        # Char n-grams survive typos, spacing tricks, and other languages.
                        (
                            "char",
                            TfidfVectorizer(
                                analyzer="char_wb",
                                ngram_range=(3, 5),
                                min_df=2,
                                sublinear_tf=True,
                            ),
                        ),
                    ]
                ),
            ),
            (
                "clf",
                # Calibrated so predict_proba is a usable confidence rather than
                # an arbitrary margin -- the Decision Engine consumes it directly.
                CalibratedClassifierCV(
                    LogisticRegression(
                        max_iter=2000, class_weight="balanced", C=4.0, solver="liblinear"
                    ),
                    method="sigmoid",
                    cv=3,
                ),
            ),
        ]
    )


def evaluate(model: Pipeline, texts: list[str], labels: list[int]) -> dict:
    probabilities = model.predict_proba(preprocess(texts))[:, 1]
    predictions = (probabilities >= 0.5).astype(int)
    truth = np.array(labels)

    tn, fp, fn, tp = confusion_matrix(truth, predictions, labels=[0, 1]).ravel()
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0

    started = time.perf_counter()
    model.predict_proba(preprocess(texts[:200]))
    per_item_ms = (time.perf_counter() - started) * 1000 / max(1, len(texts[:200]))

    return {
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        # The number that actually decides whether this ships in front of a
        # real product: how often it fires on legitimate traffic.
        "false_positive_rate": round(fp / (fp + tn), 4) if fp + tn else 0.0,
        "roc_auc": round(float(roc_auc_score(truth, probabilities)), 4),
        "average_precision": round(float(average_precision_score(truth, probabilities)), 4),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "inference_ms_per_item": round(per_item_ms, 3),
        "test_size": len(labels),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--sources",
        nargs="+",
        default=["seed", "deepset", "jailbreakbench"],
        help="datasets to train on (use 'seed' alone to run fully offline)",
    )
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--test-size", type=float, default=0.25)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    corpus = load_corpus(args.sources)
    if len(corpus) < 40:
        raise SystemExit(
            f"only {len(corpus)} examples loaded -- too few to train. "
            "Check network access or pass --sources seed."
        )
    logger.info(
        "corpus: %d examples (%d injection / %d benign) from %s",
        len(corpus),
        corpus.positives,
        corpus.negatives,
        ", ".join(sorted(set(corpus.sources))),
    )

    x_train, x_test, y_train, y_test = train_test_split(
        corpus.texts,
        corpus.labels,
        test_size=args.test_size,
        random_state=args.seed,
        stratify=corpus.labels,
    )

    model = build_pipeline()
    started = time.perf_counter()
    model.fit(preprocess(x_train), y_train)
    logger.info("trained in %.1fs on %d examples", time.perf_counter() - started, len(x_train))

    metrics = evaluate(model, x_test, y_test)
    logger.info(
        "\n%s",
        classification_report(
            y_test,
            (model.predict_proba(preprocess(x_test))[:, 1] >= 0.5).astype(int),
            target_names=["benign", "injection"],
            digits=4,
            zero_division=0,
        ),
    )
    logger.info("metrics: %s", json.dumps(metrics, indent=2))

    args.output.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(
        {
            "model": model,
            "metrics": metrics,
            "sources": sorted(set(corpus.sources)),
            "trained_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "n_train": len(x_train),
            "version": 1,
        },
        args.output,
    )
    logger.info("saved -> %s", args.output)

    metrics_path = args.output.with_suffix(".metrics.json")
    metrics_path.write_text(json.dumps(metrics, indent=2) + "\n", encoding="utf-8")
    logger.info("metrics -> %s", metrics_path)


if __name__ == "__main__":
    main()
