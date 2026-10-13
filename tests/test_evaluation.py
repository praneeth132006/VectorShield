"""Checks for offline evaluation integrity and expanded benign coverage."""

from __future__ import annotations

import pandas as pd
import pytest

from scripts._fallback import SUPPORT_BENIGN
from scripts.evaluate import (
    BLOCK_THRESHOLD,
    audit_splits,
    metrics,
    threshold_candidates,
    tune_threshold,
)


def test_support_benign_set_is_large_and_has_unique_prompts() -> None:
    normalized = [" ".join(text.lower().split()) for text in SUPPORT_BENIGN]
    assert len(SUPPORT_BENIGN) >= 150
    assert len(normalized) == len(set(normalized))


def test_split_audit_accepts_disjoint_data_and_reports_label_counts() -> None:
    frames = {
        "train": pd.DataFrame({"text": ["train attack"], "label": [1]}),
        "val": pd.DataFrame({"text": ["validation benign"], "label": [0]}),
    }

    audit = audit_splits(frames)

    assert audit["rows"] == {"train": 1, "val": 1}
    assert audit["normalized_exact_overlap_between_splits"]["train/val"] == 0
    assert audit["labels"]["train"] == {1: 1}


def test_split_audit_rejects_normalized_cross_split_duplicates() -> None:
    frames = {
        "train": pd.DataFrame({"text": ["Same  prompt"], "label": [1]}),
        "test": pd.DataFrame({"text": [" same prompt "], "label": [1]}),
    }

    with pytest.raises(ValueError, match="duplicate/overlap"):
        audit_splits(frames)


def test_metrics_reports_full_confusion_matrix() -> None:
    result = metrics([1, 1, 0, 0], [True, False, True, False])

    assert result["confusion_matrix"] == {"tp": 1, "fp": 1, "tn": 1, "fn": 1}
    assert result["precision"] == 0.5
    assert result["recall"] == 0.5
    assert result["f1"] == 0.5
    assert result["fpr"] == 0.5


def test_metrics_marks_single_class_precision_and_f1_unavailable() -> None:
    attack_only = metrics([1, 1], [True, False])
    benign_only = metrics([0, 0], [False, True])

    assert attack_only["precision"] is None
    assert attack_only["f1"] is None
    assert attack_only["recall"] == 0.5
    assert benign_only["precision"] is None
    assert benign_only["f1"] is None
    assert benign_only["recall"] is None
    assert benign_only["fpr"] == 0.5


@pytest.mark.parametrize("name", ["rules_only", "ml_every_request"])
def test_non_gated_threshold_candidates_include_block_boundary(name: str) -> None:
    candidates = threshold_candidates(name)

    assert candidates
    assert all(threshold <= BLOCK_THRESHOLD for threshold in candidates)
    assert max(candidates) == BLOCK_THRESHOLD


def test_gated_threshold_candidates_exclude_block_boundary() -> None:
    candidates = threshold_candidates("gated_hybrid")

    assert candidates
    assert all(threshold <= BLOCK_THRESHOLD for threshold in candidates)
    assert max(candidates) < BLOCK_THRESHOLD


@pytest.mark.parametrize(
    ("name", "expected_maximum"),
    [
        ("rules_only", BLOCK_THRESHOLD),
        ("ml_every_request", BLOCK_THRESHOLD),
        ("gated_hybrid", 0.84),
    ],
)
def test_tuning_cannot_select_an_invalid_threshold(name: str, expected_maximum: float) -> None:
    observations = [([], []), ([], [])]

    selected = tune_threshold(name, observations, [0, 1])

    assert selected["flag_threshold"] == expected_maximum
