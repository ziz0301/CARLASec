"""IDS 1 feature extraction: per-ID inter-arrival time + ID one-hot.

Streaming-friendly: a single FeatureBuilder instance carries the per-ID
last-timestamp state so the same code path works for training (batch over
benign frames) and inference (one frame at a time).
"""
from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np
import pandas as pd

from .preprocess import KNOWN_IDS, KNOWN_IDS_SET

FEATURE_DIM = 1 + len(KNOWN_IDS)  # delta_per_id + 4-dim one-hot = 5
ID_INDEX: dict[int, int] = {cid: i for i, cid in enumerate(KNOWN_IDS)}


@dataclass
class IDS1Scaler:
    """log1p + min-max scaler for the single delta_per_id feature."""
    delta_min: float = 0.0
    delta_max: float = 1.0

    @classmethod
    def fit(cls, deltas: np.ndarray) -> "IDS1Scaler":
        logd = np.log1p(np.clip(deltas, 0.0, None))
        return cls(delta_min=float(logd.min()),
                   delta_max=float(logd.max() if logd.max() > logd.min() else logd.min() + 1.0))

    def transform_one(self, delta_sec: float) -> float:
        x = math.log1p(max(delta_sec, 0.0))
        span = self.delta_max - self.delta_min
        if span <= 0:
            return 0.0
        return float(np.clip((x - self.delta_min) / span, 0.0, 1.0))

    def to_json(self) -> dict:
        return {"delta_min": self.delta_min, "delta_max": self.delta_max}

    @classmethod
    def from_json(cls, d: dict) -> "IDS1Scaler":
        return cls(delta_min=d["delta_min"], delta_max=d["delta_max"])


@dataclass
class FeatureBuilderIDS1:
    """Stateful per-frame feature emitter."""
    scaler: IDS1Scaler
    last_ts_per_id: dict[int, float] = field(default_factory=dict)

    def step(self, timestamp: float, cid: int) -> np.ndarray:
        """Return the 5-dim feature row for this frame and update state.

        Caller is responsible for ensuring `cid in KNOWN_IDS_SET`.
        """
        last = self.last_ts_per_id.get(cid)
        delta = 0.0 if last is None else max(timestamp - last, 0.0)
        self.last_ts_per_id[cid] = timestamp

        row = np.zeros(FEATURE_DIM, dtype=np.float32)
        row[0] = self.scaler.transform_one(delta)
        row[1 + ID_INDEX[cid]] = 1.0
        return row


# ---------- batch helpers (training) ----------

def collect_raw_deltas(df: pd.DataFrame) -> np.ndarray:
    """Return all per-ID inter-arrival times for known-ID rows in `df`."""
    last_ts: dict[int, float] = {}
    out: list[float] = []
    for ts, cid in zip(df["timestamp"].to_numpy(), df["cid"].to_numpy()):
        cid = int(cid)
        if cid not in KNOWN_IDS_SET:
            continue
        last = last_ts.get(cid)
        out.append(0.0 if last is None else max(ts - last, 0.0))
        last_ts[cid] = ts
    return np.asarray(out, dtype=np.float64)


def fit_scaler(df: pd.DataFrame) -> IDS1Scaler:
    return IDS1Scaler.fit(collect_raw_deltas(df))


def build_feature_matrix(df: pd.DataFrame, scaler: IDS1Scaler) -> np.ndarray:
    """Return shape (n_known_rows, 5) feature matrix, filtering unknown IDs."""
    builder = FeatureBuilderIDS1(scaler=scaler)
    rows = []
    for ts, cid in zip(df["timestamp"].to_numpy(), df["cid"].to_numpy()):
        cid = int(cid)
        if cid not in KNOWN_IDS_SET:
            continue
        rows.append(builder.step(float(ts), cid))
    return np.asarray(rows, dtype=np.float32)


def make_windows(matrix: np.ndarray, window: int = 32) -> np.ndarray:
    """Stride-1 windows over the feature matrix; shape (n_windows, window, F)."""
    n, f = matrix.shape
    if n < window:
        return np.empty((0, window, f), dtype=matrix.dtype)
    out = np.lib.stride_tricks.sliding_window_view(matrix, (window, f))
    return out.reshape(-1, window, f).copy()


def save_scaler(scaler: IDS1Scaler, path: Path) -> None:
    path.write_text(json.dumps(scaler.to_json(), indent=2))


def load_scaler(path: Path) -> IDS1Scaler:
    return IDS1Scaler.from_json(json.loads(path.read_text()))
