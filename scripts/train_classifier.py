"""Train the TF-IDF + Logistic Regression injection classifier.

Usage (from the repository root, after scripts/prepare_data.py):
    python scripts/train_classifier.py

Reads  data/processed/train.csv and val.csv   (columns: text,label)
Writes models/injection_clf.joblib            (loaded by app/detectors/ml.py)
       models/injection_clf.metrics.json      (validation metrics, in-distribution only)

Validation here is in-distribution. Use scripts/evaluate.py for the out-of-distribution
numbers you should report.
"""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path

import joblib
import pandas as pd
import sklearn
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, f1_score, precision_score, recall_score
from sklearn.pipeline import FeatureUnion, Pipeline

ROOT = Path(__file__).resolve().parents[1]
PROC = ROOT / "data" / "processed"
MODEL_DIR = ROOT / "models"
MAX_CHARS = 4000  # keep equal to app/detectors/ml.py


def make_pipeline(c_value: float, small_data: bool) -> Pipeline:
    word_min_df = 1 if small_data else 2
    char_min_df = 1 if small_data else 3
    features = FeatureUnion(
        [
            (
                "word",
                TfidfVectorizer(
                    ngram_range=(1, 2),
                    min_df=word_min_df,
                    max_features=100_000,
                    sublinear_tf=True,
                    strip_accents="unicode",
                ),
            ),
            (
                "char",
                TfidfVectorizer(
                    analyzer="char_wb",
                    ngram_range=(3, 5),
                    min_df=char_min_df,
                    max_features=200_000,
                    sublinear_tf=True,
                ),
            ),
        ]
    )
    clf = LogisticRegression(
        C=c_value, max_iter=2000, class_weight="balanced", solver="liblinear"
    )
    return Pipeline([("tfidf", features), ("lr", clf)])


def metrics_at(y_true: pd.Series, proba: list[float], threshold: float) -> dict[str, float]:
    pred = [1 if p >= threshold else 0 for p in proba]
    negatives = [(t, p) for t, p in zip(y_true, pred, strict=True) if t == 0]
    fpr = sum(p for _, p in negatives) / len(negatives) if negatives else float("nan")
    return {
        "precision": float(precision_score(y_true, pred, zero_division=0)),
        "recall": float(recall_score(y_true, pred, zero_division=0)),
        "f1": float(f1_score(y_true, pred, zero_division=0)),
        "fpr": float(fpr),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--c", type=float, nargs="+", default=[0.5, 1.0, 4.0, 16.0])
    args = parser.parse_args()

    train = pd.read_csv(PROC / "train.csv").dropna()
    val = pd.read_csv(PROC / "val.csv").dropna()
    x_train = train["text"].astype(str).str.slice(0, MAX_CHARS)
    x_val = val["text"].astype(str).str.slice(0, MAX_CHARS)
    small = len(train) < 500
    print(f"train={len(train)} val={len(val)} attack_share={train['label'].mean():.2f}")

    best: tuple[float, float, Pipeline] | None = None
    for c_value in args.c:
        model = make_pipeline(c_value, small)
        model.fit(x_train, train["label"])
        proba = model.predict_proba(x_val)[:, list(model.classes_).index(1)]
        ap = float(average_precision_score(val["label"], proba))
        print(f"C={c_value:<5} val PR-AUC={ap:.4f}")
        if best is None or ap > best[0]:
            best = (ap, c_value, model)
    assert best is not None
    ap, c_value, model = best

    proba = list(model.predict_proba(x_val)[:, list(model.classes_).index(1)])
    report = {
        "best_C": c_value,
        "val_pr_auc": ap,
        "val_at_0.45": metrics_at(val["label"], proba, 0.45),
        "val_at_0.85": metrics_at(val["label"], proba, 0.85),
        "n_train": len(train),
        "n_val": len(val),
        "trained_at": datetime.now(UTC).isoformat(),
        "sklearn_version": sklearn.__version__,
        "fallback_data": (PROC / "FALLBACK_USED.txt").exists(),
    }
    MODEL_DIR.mkdir(exist_ok=True)
    joblib.dump({"pipeline": model, "meta": report}, MODEL_DIR / "injection_clf.joblib")
    (MODEL_DIR / "injection_clf.metrics.json").write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))
    if report["fallback_data"]:
        print("WARNING: trained on the tiny fallback set. Smoke test only.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
