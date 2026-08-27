"""Shared CSV loading + known-ID filtering for both IDSes."""
from __future__ import annotations

from pathlib import Path
from typing import Tuple

import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DBC_PATH = PROJECT_ROOT / "bmw.dbc"
DATA_DIR = PROJECT_ROOT / "dataset_new"
ARTIFACT_DIR = Path(__file__).resolve().parent / "artifacts"
ARTIFACT_DIR.mkdir(exist_ok=True)

# Frame IDs defined in bmw.dbc that we actually observe in the data.
KNOWN_IDS: tuple[int, ...] = (0x0BA, 0x0C4, 0x1A0, 0x1B4)
KNOWN_IDS_SET: frozenset[int] = frozenset(KNOWN_IDS)


def parse_can_id(raw) -> int | None:
    """Parse hex string ('0x1a0') or int to int; return None on failure."""
    if isinstance(raw, int):
        return raw
    sx = str(raw).strip().lower()
    if sx.startswith("0x"):
        sx = sx[2:]
        base = 16
    else:
        # CAN IDs in CSV are usually hex strings, e.g. "0C4"
        base = 16

    try:
        return int(sx, base)
    except ValueError:
        return None


def load_csv(csv_path: Path | str) -> pd.DataFrame:
    """Load an IDS-format CSV, add an int `cid` column, sort by timestamp."""
    df = pd.read_csv(csv_path)
    df["cid"] = df["can_id"].map(parse_can_id)
    df = df.sort_values("timestamp", kind="stable").reset_index(drop=True)
    return df


def filter_known_ids(df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.Series]:
    """Split into (known-ID rows, boolean mask of unknown-ID rows on the input).

    The unknown-ID rows are what the rule-based pre-filter flags as attacks
    without invoking the LSTM models.
    """
    is_known = df["cid"].isin(KNOWN_IDS_SET)
    return df[is_known].reset_index(drop=True), ~is_known


def load_train_benign() -> pd.DataFrame:
    """dataset1 benign + known-ID rows only; used to train both IDS branches."""
    df = load_csv(DATA_DIR / "dataset1.csv")
    df, _ = filter_known_ids(df)
    return df[df["label"] == "benign"].reset_index(drop=True)


def load_test_full() -> pd.DataFrame:
    """dataset2 full (benign+attack); used for batch evaluation."""
    return load_csv(DATA_DIR / "dataset2.csv")


def load_mixed_split(train_ratio: float = 0.8
                     ) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """Per-dataset sequential split.

    For each of dataset1, dataset2: the first `train_ratio` of rows go into
    `train_pool`; the remainder goes into `test_pool`. Both pools carry a
    `_source ∈ {"d1", "d2"}` column so downstream code can process each
    source as its own temporal stream (avoids spurious delta_per_id /
    carry-forward artifacts at the dataset boundary).
    """
    d1 = load_csv(DATA_DIR / "dataset1.csv")
    d2 = load_csv(DATA_DIR / "dataset2.csv")
    c1 = int(len(d1) * train_ratio)
    c2 = int(len(d2) * train_ratio)
    d1_tr, d1_te = d1.iloc[:c1].copy(), d1.iloc[c1:].copy()
    d2_tr, d2_te = d2.iloc[:c2].copy(), d2.iloc[c2:].copy()
    for chunk, src in ((d1_tr, "d1"), (d1_te, "d1"),
                       (d2_tr, "d2"), (d2_te, "d2")):
        chunk["_source"] = src
    train_pool = pd.concat([d1_tr, d2_tr], ignore_index=True)
    test_pool = pd.concat([d1_te, d2_te], ignore_index=True)
    return train_pool, test_pool
