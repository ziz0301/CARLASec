#!/usr/bin/env python3
"""
plot_can_entropy_evolution.py
Compute and plot evolution of CAN-ID entropy over time windows
of 1.0s, 0.5s, and 0.1s
"""

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from scipy.stats import entropy

CSV_IN = "can_sniff_log_decoded.csv"
WINDOWS = [215, 10, 5]  # seconds

print("Loading CSV...")
df = pd.read_csv(CSV_IN)
df["timestamp"] = pd.to_datetime(df["timestamp"], unit="s", errors="coerce")
df = df[df["label"].astype(str).str.lower() == "benign"].copy()

# Normalise CAN IDs
df["can_id"] = df["can_id"].apply(
    lambda x: f"0x{int(x):x}" if str(x).isdigit() else str(x).lower()
)

results = {}  # store entropy time series for each window

for W in WINDOWS:
    print(f"Processing window {W} s...")
    # assign each frame to time window index
    df["window_index"] = (df["timestamp"].view("int64") // int(W * 1e9)).astype(int)
    
    # count IDs per window
    counts = df.groupby(["window_index", "can_id"]).size().unstack(fill_value=0)
    probs = counts.div(counts.sum(axis=1), axis=0).fillna(0)
    H_series = probs.apply(lambda row: entropy(row.values, base=2), axis=1)

    # convert window index → approximate time (seconds)
    t = (H_series.index - H_series.index.min()) * W
    results[W] = pd.Series(H_series.values, index=t)

# --- Plot ---
plt.figure(figsize=(10, 5))
for W, series in results.items():
    plt.plot(series.index, series.values, label=f"Window {W:.1f}s", linewidth=1.2)

plt.title("Evolution of CAN-ID Entropy over Time")
plt.xlabel("Time [s]")
plt.ylabel("Entropy H (bits)")
plt.legend()
plt.grid(True, linestyle="--", alpha=0.6)
plt.tight_layout()
plt.savefig("can_entropy_evolution.png", dpi=200)
plt.show()

print("✅ Plot saved as can_entropy_evolution.png")
