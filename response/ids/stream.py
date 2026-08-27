"""StreamingDetector: frame-by-frame online IDS inference.

CLI:
  python -m ids.stream --csv dataset_new/dataset1.csv --limit 200
  python -m ids.stream --benchmark
"""
from __future__ import annotations

import argparse
import time
from collections import deque
from pathlib import Path
from typing import Optional

import numpy as np
import torch

from . import features_ids1, features_ids2
from .model import BasePredictor, load_predictor, load_threshold
from .preprocess import ARTIFACT_DIR, KNOWN_IDS_SET, load_csv, parse_can_id


class StreamingDetector:
    """Frame-by-frame IDS: DBC-whitelist rule + two next-frame predictors."""

    def __init__(self, artifact_dir: Path = ARTIFACT_DIR):
        self.scaler1 = features_ids1.load_scaler(artifact_dir / "ids1_scaler.json")
        self.scaler2 = features_ids2.load_scaler(artifact_dir / "ids2_scaler.json")
        self.model1 = load_predictor(artifact_dir / "ids1_model.pt")
        self.model2 = load_predictor(artifact_dir / "ids2_model.pt")
        self.thr1 = load_threshold(artifact_dir / "ids1_threshold.json")
        self.thr2 = load_threshold(artifact_dir / "ids2_threshold.json")

        # Both IDS branches must share the same window
        assert self.model1.window == self.model2.window, \
            f"IDS1/IDS2 windows must match ({self.model1.window} vs {self.model2.window})"
        self.window = self.model1.window

        self.builder1 = features_ids1.FeatureBuilderIDS1(scaler=self.scaler1)
        self.builder2 = features_ids2.FeatureBuilderIDS2(scaler=self.scaler2)
        self.buf1: deque[np.ndarray] = deque(maxlen=self.window)
        self.buf2: deque[np.ndarray] = deque(maxlen=self.window)

    def reset(self) -> None:
        self.builder1 = features_ids1.FeatureBuilderIDS1(scaler=self.scaler1)
        self.builder2 = features_ids2.FeatureBuilderIDS2(scaler=self.scaler2)
        self.buf1.clear()
        self.buf2.clear()

    @torch.inference_mode()
    def _score(self, model: BasePredictor, buf: deque) -> float:
        # buf at WINDOW length; predict the last frame from frames 0..W-2,
        # score = MSE between the prediction and the actual last frame.
        win = np.stack(buf, axis=0)[None, ...]      # (1, W, F)
        x = torch.from_numpy(win)
        pred = model.predict_next(x[:, :-1, :])     # (1, F)
        actual = x[:, -1, :]
        return float(((pred - actual) ** 2).mean().item())

    def process_frame(self, timestamp: float, can_id_raw, payload_hex: str) -> dict:
        cid = parse_can_id(can_id_raw)
        out = {"rule": None, "ids1_score": None, "ids2_score": None,
               "alert": False, "reason": None}

        if cid is None or cid not in KNOWN_IDS_SET:
            out["rule"] = "unknown_id"
            out["alert"] = True
            out["reason"] = "unknown_id"
            return out

        self.buf1.append(self.builder1.step(float(timestamp), cid))
        self.buf2.append(self.builder2.step(cid, payload_hex))

        if len(self.buf1) < self.window or len(self.buf2) < self.window:
            return out  # cold start — no model decision yet

        s1 = self._score(self.model1, self.buf1)
        s2 = self._score(self.model2, self.buf2)
        out["ids1_score"] = s1
        out["ids2_score"] = s2
        if s1 > self.thr1:
            out["alert"] = True
            out["reason"] = "ids1_threshold"
        elif s2 > self.thr2:
            out["alert"] = True
            out["reason"] = "ids2_threshold"
        return out


# ---------- CLI ----------

def _run_csv(csv_path: Path, limit: Optional[int]) -> None:
    df = load_csv(csv_path)
    if limit is not None:
        df = df.head(limit)
    det = StreamingDetector()
    cold = alerts = 0
    n = len(df)
    print(f"streaming {n} frames from {csv_path.name} ...")
    for i, (ts, cid_raw, payload, label) in enumerate(
        zip(df["timestamp"], df["can_id"], df["payload_hex"], df["label"])
    ):
        r = det.process_frame(float(ts), cid_raw, str(payload))
        if r["ids1_score"] is None and r["reason"] is None:
            cold += 1
        if r["alert"]:
            alerts += 1
        if i < 35 or (i < 50 and r["alert"]):
            print(f"  [{i:>4d}] label={label:<6s} cid={cid_raw:<6s} "
                  f"alert={r['alert']} reason={r['reason']} "
                  f"ids1={r['ids1_score']} ids2={r['ids2_score']}")
    print(f"\nframes: {n}   cold-start (no decision): {cold}   alerts: {alerts}")


def _run_benchmark(n_frames: int = 5000) -> None:
    from .preprocess import DATA_DIR
    df = load_csv(DATA_DIR / "dataset1.csv")
    df = df[df["label"] == "benign"].head(n_frames)
    det = StreamingDetector()
    for ts, cid_raw, payload in zip(df["timestamp"].head(64), df["can_id"].head(64),
                                    df["payload_hex"].head(64)):
        det.process_frame(float(ts), cid_raw, str(payload))
    det.reset()
    t0 = time.perf_counter()
    for ts, cid_raw, payload in zip(df["timestamp"], df["can_id"], df["payload_hex"]):
        det.process_frame(float(ts), cid_raw, str(payload))
    dt = time.perf_counter() - t0
    print(f"benchmark: {len(df)} frames in {dt*1000:.1f} ms "
          f"=> {len(df)/dt:,.0f} fr/s ({dt/len(df)*1e6:.1f} µs/frame)")


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--csv", type=Path, help="stream this CSV through the detector")
    p.add_argument("--limit", type=int, default=None)
    p.add_argument("--benchmark", action="store_true")
    args = p.parse_args()
    if args.benchmark:
        _run_benchmark()
    elif args.csv is not None:
        _run_csv(args.csv, args.limit)
    else:
        p.print_help()


if __name__ == "__main__":
    main()
