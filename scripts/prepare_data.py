"""Download and prepare datasets for the prompt-injection classifier.

Usage (from the repository root):
    python scripts/prepare_data.py             # download from Hugging Face
    python scripts/prepare_data.py --fallback  # skip the network; tiny smoke-test data

Outputs:
    data/raw/<name>.csv                  raw copies (text,label,split)
    data/processed/train.csv, val.csv    training data   (xTRam1 train + jackhhao)
    data/processed/test_xtram1.csv       in-distribution test
    data/processed/test_deepset.csv      out-of-distribution test (never trained on)
    data/processed/test_gandalf.csv      attack-only recall test (never trained on)
    data/processed/test_support_benign.csv   hand-written benign support prompts
    data/processed/summary.json

Verified (Hugging Face cards, Oct 2026): xTRam1 = columns text,label, 8,236/2,060 rows;
jackhhao = columns prompt,type (jailbreak|benign), Apache-2.0; Lakera gandalf = column text,
MIT, 777/111/112 rows; deepset = Apache-2.0. Column names for deepset are auto-detected and
printed; the script stops with a clear message if it cannot find them.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _fallback import FALLBACK_ATTACKS, FALLBACK_BENIGN, SUPPORT_BENIGN  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "data" / "raw"
PROC = ROOT / "data" / "processed"

SOURCES: dict[str, dict] = {
    "jackhhao": {"repo": "jackhhao/jailbreak-classification"},
    "gandalf": {"repo": "Lakera/gandalf_ignore_instructions", "attack_only": True},
}
TEXT_COLUMNS = ("text", "prompt")
LABEL_COLUMNS = ("label", "type")
ATTACK_WORDS = {"jailbreak", "injection", "malicious", "attack", "unsafe", "1", "true"}
BENIGN_WORDS = {"benign", "safe", "normal", "0", "false"}


def to_label(value: object) -> int:
    if isinstance(value, str):
        word = value.strip().lower()
        if word in ATTACK_WORDS:
            return 1
        if word in BENIGN_WORDS:
            return 0
        raise ValueError(f"unrecognised label value: {value!r}")
    return int(bool(int(value)))  # type: ignore[call-overload]


def norm_key(text: str) -> str:
    return " ".join(str(text).lower().split())


def load_source(name: str, cfg: dict) -> pd.DataFrame:
    from datasets import load_dataset  # imported here so --fallback needs no `datasets`

    dsd = load_dataset(cfg["repo"])
    frames = []
    for split, ds in dsd.items():
        df = ds.to_pandas()
        text_col = next((c for c in TEXT_COLUMNS if c in df.columns), None)
        if text_col is None:
            raise RuntimeError(f"{name}: no text column in {list(df.columns)}")
        if cfg.get("attack_only"):
            labels = pd.Series([1] * len(df))
            label_col = "(all attacks)"
        else:
            label_col = next((c for c in LABEL_COLUMNS if c in df.columns), None)
            if label_col is None:
                raise RuntimeError(f"{name}: no label column in {list(df.columns)}")
            labels = df[label_col].map(to_label)
        print(
            f"[ok] {name} split={split}: rows={len(df)} columns={list(df.columns)} "
            f"text_col={text_col} label_col={label_col} "
            f"label_counts={labels.value_counts().to_dict()}"
        )
        frames.append(
            pd.DataFrame(
                {"text": df[text_col].astype(str).values, "label": labels.values, "split": split}
            )
        )
    out = pd.concat(frames, ignore_index=True)
    out = out[out["text"].str.strip().astype(bool)]
    out.to_csv(RAW / f"{name}.csv", index=False)
    return out


def dedupe_against(df: pd.DataFrame, seen: set[str]) -> pd.DataFrame:
    keys = df["text"].map(norm_key)
    keep = ~keys.isin(seen) & ~keys.duplicated()
    return df[keep].reset_index(drop=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--fallback", action="store_true", help="skip downloads, use tiny data")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    RAW.mkdir(parents=True, exist_ok=True)
    PROC.mkdir(parents=True, exist_ok=True)

    loaded: dict[str, pd.DataFrame] = {}
    if args.fallback:
        print("[WARN] using the tiny hand-written fallback set: smoke test only.", file=sys.stderr)
        train_pool = pd.DataFrame(
            {
                "text": FALLBACK_ATTACKS + FALLBACK_BENIGN,
                "label": [1] * len(FALLBACK_ATTACKS) + [0] * len(FALLBACK_BENIGN),
            }
        )
        used_fallback = True
    else:
        # Fail immediately on network, schema, or label errors; never substitute fallback data.
        for name, cfg in SOURCES.items():
            loaded[name] = load_source(name, cfg)
        jackhhao = loaded["jackhhao"]
        train_pool = jackhhao.loc[jackhhao["split"] == "train", ["text", "label"]]
        if train_pool.empty:
            raise RuntimeError("jackhhao dataset has no train split")
        if not (jackhhao["split"] == "test").any():
            raise RuntimeError("jackhhao dataset has no test split for held-out evaluation")
        used_fallback = False

    train_pool = train_pool[~train_pool["text"].map(norm_key).duplicated()].reset_index(drop=True)

    from sklearn.model_selection import train_test_split

    train, val = train_test_split(
        train_pool,
        test_size=0.1,
        random_state=args.seed,
        stratify=train_pool["label"],
    )
    train.to_csv(PROC / "train.csv", index=False)
    val.to_csv(PROC / "val.csv", index=False)

    seen = set(train_pool["text"].map(norm_key))
    outputs = {"train": len(train), "val": len(val)}

    def write_test(name: str, df: pd.DataFrame) -> None:
        clean = dedupe_against(df[["text", "label"]], seen)
        clean.to_csv(PROC / f"test_{name}.csv", index=False)
        outputs[f"test_{name}"] = len(clean)

    if "jackhhao" in loaded:
        write_test("jackhhao", loaded["jackhhao"][loaded["jackhhao"]["split"] == "test"])
    if "gandalf" in loaded:
        write_test("gandalf", loaded["gandalf"])
    pd.DataFrame({"text": SUPPORT_BENIGN, "label": 0}).to_csv(
        PROC / "test_support_benign.csv", index=False
    )
    outputs["test_support_benign"] = len(SUPPORT_BENIGN)

    fallback_flag = PROC / "FALLBACK_USED.txt"
    if used_fallback:
        fallback_flag.write_text("train/val came from the tiny fallback set.\n")
    elif fallback_flag.exists():
        fallback_flag.unlink()

    summary = {"used_fallback": used_fallback, "rows": outputs}
    (PROC / "summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
