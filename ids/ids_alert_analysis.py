#!/usr/bin/env python3
"""
ids_alert_analysis.py
-----------------------------------------------------
Analyses IDS alerts to see which detection module
(FSA, FREQ, INTERVAL, CUSUM, ENTROPY)
caused True Positives vs False Positives.
-----------------------------------------------------
"""

import pandas as pd

# === Load data ===
alerts = pd.read_csv("ids_output/ids_alert_log.csv")
events = pd.read_csv("ids_test_small.csv")

# Convert timestamps
alerts["time"] = pd.to_datetime(alerts["time"], errors="coerce")
events["timestamp"] = pd.to_datetime(events["timestamp"], unit="s", errors="coerce")

# === Match each alert to an attack window (±0.5s) ===
def is_true_positive(alert_time):
    window = events[
        (events["label"].str.lower() == "attack") &
        (events["timestamp"] >= alert_time - pd.Timedelta(seconds=0.5)) &
        (events["timestamp"] <= alert_time + pd.Timedelta(seconds=0.5))
    ]
    return len(window) > 0

alerts["is_TP"] = alerts["time"].apply(is_true_positive)
alerts["is_FP"] = ~alerts["is_TP"]

# === Count alerts per module ===
summary = (
    alerts.groupby(["type", "is_TP"])
    .size()
    .unstack(fill_value=0)
    .rename(columns={True: "TP", False: "FP"})
)

summary["total"] = summary["TP"] + summary["FP"]
summary["precision"] = (summary["TP"] / summary["total"]).round(2)

print("=== IDS Module Performance Summary ===")
print(summary)

# Save for reference
summary.to_csv("ids_output/module_precision_summary.csv")
print("\nSaved → ids_output/module_precision_summary.csv")
