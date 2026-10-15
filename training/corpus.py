"""Dataset loading for the stage 1 classifier.

Only public datasets are used, and nothing is vendored into the repo beyond a
small hand-written seed corpus for offline runs. Sources are fetched as parquet
straight from the Hugging Face CDN, so no heavyweight dataset library is needed.

    label 1 = prompt injection / jailbreak
    label 0 = benign
"""

from __future__ import annotations

import json
import logging
import random
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

DATA_DIR = Path(__file__).parent / "data"
SEED_CORPUS = Path(__file__).parent / "seed_corpus.jsonl"

HF_PARQUET = "https://huggingface.co/api/datasets/{repo}/parquet/{config}/{split}/0.parquet"


@dataclass(slots=True)
class Corpus:
    texts: list[str]
    labels: list[int]
    sources: list[str]

    def __len__(self) -> int:
        return len(self.texts)

    @property
    def positives(self) -> int:
        return sum(self.labels)

    @property
    def negatives(self) -> int:
        return len(self.labels) - self.positives

    def extend(self, texts: list[str], labels: list[int], source: str) -> None:
        self.texts.extend(texts)
        self.labels.extend(labels)
        self.sources.extend([source] * len(texts))

    def deduplicated(self) -> Corpus:
        """Drop exact duplicates -- they inflate accuracy and leak across splits."""
        seen: set[str] = set()
        out = Corpus([], [], [])
        for text, label, source in zip(self.texts, self.labels, self.sources, strict=True):
            key = " ".join(text.lower().split())
            if key in seen or not key:
                continue
            seen.add(key)
            out.extend([text], [label], source)
        return out

    def shuffled(self, seed: int = 42) -> Corpus:
        rows = list(zip(self.texts, self.labels, self.sources, strict=True))
        random.Random(seed).shuffle(rows)
        return Corpus([r[0] for r in rows], [int(r[1]) for r in rows], [r[2] for r in rows])


def _fetch_parquet(repo: str, split: str, config: str = "default"):
    """Download one split as a DataFrame, caching it under training/data/."""
    import pandas as pd

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    cache = DATA_DIR / f"{repo.replace('/', '__')}.{config}.{split}.parquet"

    if cache.exists():
        return pd.read_parquet(cache)

    url = HF_PARQUET.format(repo=repo, config=config, split=split)
    frame = pd.read_parquet(url)
    frame.to_parquet(cache)
    logger.info("cached %s/%s (%d rows) -> %s", repo, split, len(frame), cache.name)
    return frame


def load_deepset(corpus: Corpus) -> None:
    """deepset/prompt-injections -- labelled injection vs. benign, EN + DE."""
    import pandas as pd

    frames = []
    for split in ("train", "test"):
        try:
            frames.append(_fetch_parquet("deepset/prompt-injections", split))
        except Exception as exc:
            logger.warning("deepset %s split unavailable: %s", split, exc)
    if not frames:
        return

    frame = pd.concat(frames, ignore_index=True)
    texts = [str(t) for t in frame["text"].tolist()]
    labels = [int(v) for v in frame["label"].tolist()]
    corpus.extend(texts, labels, "deepset/prompt-injections")


def load_jailbreakbench(corpus: Corpus) -> None:
    """JailbreakBench behaviors -- harmful-content goals, all positive-class.

    NOT part of the default source set. These are requests for harmful *content*
    ("write a tutorial on X"), not attempts to subvert the system prompt. Module 1
    detects injection structure, so training on them teaches the classifier that
    harmful topics equal injection -- a different task, and one that costs
    precision on ordinary traffic. Kept available behind an explicit flag for
    anyone benchmarking content-policy detection.
    """
    for config in ("behaviors",):
        try:
            frame = _fetch_parquet("JailbreakBench/JBB-Behaviors", "harmful", config)
        except Exception as exc:
            logger.warning("JailbreakBench unavailable: %s", exc)
            return
        column = "Goal" if "Goal" in frame.columns else frame.columns[0]
        texts = [str(t) for t in frame[column].tolist()]
        corpus.extend(texts, [1] * len(texts), "JailbreakBench/JBB-Behaviors")


def load_seed(corpus: Corpus) -> None:
    """The small hand-written corpus committed to this repo.

    It exists so training, tests, and CI work with no network. It is far too
    small to train a good model on its own -- it is a floor, not a dataset.
    """
    if not SEED_CORPUS.exists():
        return
    with SEED_CORPUS.open(encoding="utf-8") as handle:
        rows = [json.loads(line) for line in handle if line.strip()]
    corpus.extend(
        [r["text"] for r in rows], [int(r["label"]) for r in rows], "vectorshield/seed"
    )


LOADERS = {
    "seed": load_seed,
    "deepset": load_deepset,
    "jailbreakbench": load_jailbreakbench,
}


def load_corpus(sources: list[str] | None = None) -> Corpus:
    corpus = Corpus([], [], [])
    for name in sources or list(LOADERS):
        loader = LOADERS.get(name)
        if loader is None:
            raise SystemExit(f"unknown source '{name}'. Known: {', '.join(LOADERS)}")
        before = len(corpus)
        loader(corpus)
        logger.info("%s: +%d examples", name, len(corpus) - before)
    return corpus.deduplicated().shuffled()
