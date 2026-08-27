"""IDS 2 feature extraction: 27-dim decoded-signal vector with carry-forward.

Signal order is fixed by DBC message declaration order:
  GearSelectorSwitch (0x0BA) → SteeringWheelAngle (0x0C4)
  → EngineData (0x1A0) → InstrumentHandBrake (0x1B4)
Within each message the order follows the DBC's signal declaration.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

import cantools
import numpy as np
import pandas as pd

from .preprocess import DBC_PATH, KNOWN_IDS, KNOWN_IDS_SET

_db = cantools.database.load_file(str(DBC_PATH))
_MSGS_BY_ID = {m.frame_id: m for m in _db.messages if m.frame_id in KNOWN_IDS_SET}

# Build the canonical (msg_name, signal_name) order and quick reverse lookup.
SIGNAL_ORDER: list[tuple[str, str]] = []
SIGNAL_INDEX: dict[tuple[int, str], int] = {}  # (frame_id, sig_name) → column
for cid in KNOWN_IDS:
    msg = _MSGS_BY_ID[cid]
    for sig in msg.signals:
        SIGNAL_INDEX[(cid, sig.name)] = len(SIGNAL_ORDER)
        SIGNAL_ORDER.append((msg.name, sig.name))

FEATURE_DIM = len(SIGNAL_ORDER)  # 27 with the current dbc


def decode_payload(cid: int, payload_hex: str) -> dict[str, float] | None:
    """Return {sig_name: float_value} or None on any failure."""
    msg = _MSGS_BY_ID.get(cid)
    if msg is None:
        return None
    try:
        data = bytes.fromhex(str(payload_hex))
        if len(data) != msg.length:
            return None
        decoded = msg.decode(data, decode_choices=False, scaling=True)
    except Exception:
        return None
    out: dict[str, float] = {}
    for k, v in decoded.items():
        if isinstance(v, str):
            continue
        out[k] = float(v)
    return out


@dataclass
class IDS2Scaler:
    """Per-feature min-max scaler with safe-divide for constant features."""
    mins: np.ndarray  # shape (F,)
    maxs: np.ndarray  # shape (F,)
    means: np.ndarray  # shape (F,) — used for carry-forward cold start

    @classmethod
    def fit(cls, matrix: np.ndarray) -> "IDS2Scaler":
        return cls(
            mins=matrix.min(axis=0).astype(np.float64),
            maxs=matrix.max(axis=0).astype(np.float64),
            means=matrix.mean(axis=0).astype(np.float64),
        )

    def transform(self, x: np.ndarray) -> np.ndarray:
        span = np.maximum(self.maxs - self.mins, 1e-9)
        out = (x - self.mins) / span
        return np.clip(out, 0.0, 1.0).astype(np.float32)

    def to_json(self) -> dict:
        return {"mins": self.mins.tolist(), "maxs": self.maxs.tolist(),
                "means": self.means.tolist(),
                "signal_order": SIGNAL_ORDER}

    @classmethod
    def from_json(cls, d: dict) -> "IDS2Scaler":
        return cls(
            mins=np.asarray(d["mins"], dtype=np.float64),
            maxs=np.asarray(d["maxs"], dtype=np.float64),
            means=np.asarray(d["means"], dtype=np.float64),
        )


@dataclass
class FeatureBuilderIDS2:
    """Stateful per-frame builder with last-known-value carry-forward."""
    scaler: IDS2Scaler
    last_values_raw: np.ndarray = field(default=None)  # filled in __post_init__

    def __post_init__(self) -> None:
        if self.last_values_raw is None:
            self.last_values_raw = self.scaler.means.astype(np.float64).copy()

    def step(self, cid: int, payload_hex: str) -> np.ndarray:
        """Return the 27-dim normalized feature row and update state.

        Caller must guarantee `cid in KNOWN_IDS_SET`.
        """
        decoded = decode_payload(cid, payload_hex)
        if decoded is not None:
            for sig_name, value in decoded.items():
                idx = SIGNAL_INDEX.get((cid, sig_name))
                if idx is not None:
                    self.last_values_raw[idx] = value
        # Normalize the *full* current state vector (carries forward unseen sigs)
        return self.scaler.transform(self.last_values_raw)


# ---------- batch helpers (training) ----------

def collect_raw_matrix(df: pd.DataFrame, fill_means: np.ndarray | None = None) -> np.ndarray:
    """Walk the known-ID rows of `df` and emit raw (un-normalized) feature matrix.

    `fill_means` is used for cold-start carry-forward. If None, uses 0.0 — only
    appropriate when *fitting* the scaler (we then refit with the resulting means
    if needed, but in practice the cold-start prefix is small).
    """
    n_known = int(df["cid"].isin(KNOWN_IDS_SET).sum())
    out = np.zeros((n_known, FEATURE_DIM), dtype=np.float64)
    state = (fill_means.copy() if fill_means is not None
             else np.zeros(FEATURE_DIM, dtype=np.float64))
    i = 0
    for cid, payload in zip(df["cid"].to_numpy(), df["payload_hex"].to_numpy()):
        cid = int(cid)
        if cid not in KNOWN_IDS_SET:
            continue
        decoded = decode_payload(cid, payload)
        if decoded is not None:
            for sig_name, value in decoded.items():
                idx = SIGNAL_INDEX.get((cid, sig_name))
                if idx is not None:
                    state[idx] = value
        out[i] = state
        i += 1
    return out[:i]


def fit_scaler(df: pd.DataFrame) -> IDS2Scaler:
    """Fit min-max scaler on the carry-forward feature matrix of benign frames.

    Two-pass: first pass to estimate per-feature means, second pass uses those
    means for cold-start. Keeps the scaler self-consistent.
    """
    raw0 = collect_raw_matrix(df, fill_means=None)
    means0 = raw0.mean(axis=0)
    raw1 = collect_raw_matrix(df, fill_means=means0)
    return IDS2Scaler.fit(raw1)


def build_feature_matrix(df: pd.DataFrame, scaler: IDS2Scaler) -> np.ndarray:
    raw = collect_raw_matrix(df, fill_means=scaler.means)
    return scaler.transform(raw)


def make_windows(matrix: np.ndarray, window: int = 32) -> np.ndarray:
    n, f = matrix.shape
    if n < window:
        return np.empty((0, window, f), dtype=matrix.dtype)
    out = np.lib.stride_tricks.sliding_window_view(matrix, (window, f))
    return out.reshape(-1, window, f).copy()


def save_scaler(scaler: IDS2Scaler, path: Path) -> None:
    path.write_text(json.dumps(scaler.to_json(), indent=2))


def load_scaler(path: Path) -> IDS2Scaler:
    return IDS2Scaler.from_json(json.loads(path.read_text()))
