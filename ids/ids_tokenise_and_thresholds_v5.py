#!/usr/bin/env python3
"""
compute_signal_value_entropy_per_id.py
Entropy of signal value distribution for each CAN ID (e.g., throttle, steering)
"""

import pandas as pd
import numpy as np
from scipy.stats import entropy
import json
from pathlib import Path
from collections import defaultdict

CSV_IN = "can_sniff_log_decoded.csv"
OUT_DIR = Path("ids_output_v3")
OUT_DIR.mkdir(exist_ok=True)

print("Loading benign dataset...")
df = pd.read_csv(CSV_IN)
df = df[df["label"].astype(str).str.lower().eq("benign")]

meta_cols = ["timestamp","can_id","dlc","payload_hex","label","attack_type","attack_id"]
signal_cols = [c for c in df.columns if c not in meta_cols]
df[signal_cols] = df[signal_cols].apply(pd.to_numeric, errors="coerce")

def norm_id(cid):
    try:
        cid = str(cid).strip().lower()
        return cid if cid.startswith("0x") else f"0x{cid}"
    except Exception:
        return None

df["can_id"] = df["can_id"].apply(norm_id)
df = df.dropna(subset=["can_id"])

baselines = {}

for cid, group in df.groupby("can_id"):
    values = group[signal_cols].values.flatten()
    values = values[~np.isnan(values)]
    if len(values) < 5:
        continue

    # Count occurrences of each rounded value
    rounded = np.round(values, 2)  # e.g., throttle=0.03 → 0.03
    unique, counts = np.unique(rounded, return_counts=True)
    probs = counts / counts.sum()
    H = entropy(probs, base=2)

    baselines[cid] = {
        "mu": float(H),
        "sigma": 0.0,  # can be updated later with per-window variation if desired
        "samples": len(values)
    }

# Optional global
allH = [b["mu"] for b in baselines.values()]
if allH:
    baselines["global"] = {"mu": float(np.mean(allH)), "sigma": float(np.std(allH))}

OUT_FILE = OUT_DIR / "baseline_signal_value_entropy.json"
with open(OUT_FILE, "w") as f:
    json.dump({"signal_value_entropy": baselines}, f, indent=4)

print(f"[DONE] Saved {OUT_FILE} with {len(baselines)} CAN IDs")
