#!/usr/bin/env python3
"""
ids_analysis.py
-------------------------------------------
Compare IDS alert log with labelled events
Compute TP, FN, FP (approximate matching)
-------------------------------------------
"""

import pandas as pd


# ======================
# Load files
# ======================
alerts = pd.read_csv("ids_alert_log_dedup.csv")
events = pd.read_csv("can_sniff_log_split/attack_log.csv")

# Convert timestamps to datetime (UNIX seconds → real time)
#alerts["time"] = pd.to_datetime(alerts["time"], errors="coerce")
#events["timestamp"] = pd.to_datetime(events["timestamp"], unit="s", errors="coerce")

# ======================
# Helper: was event detected near its timestamp?
# ======================
def was_detected(event_time):
    """Return True if any IDS alert occurred within ±0.5 s window."""
    window = alerts[
        (alerts["timestamp"] >= event_time - pd.Timedelta(seconds=0.5)) &
        (alerts["time"] <= event_time + pd.Timedelta(seconds=0.5))
    ]
    return len(window) > 0
    
def was_detected_2(event_time):
    """Return True if any IDS alert occurred within ±0.5 s window."""
    return alerts["timestamp"] == event_time
    

# ======================
# Evaluate detection
# ======================
events["detected"] = events.apply(
    lambda r: was_detected(r["timestamp"]) if str(r["label"]).lower() == "attack" else False,
    axis=1
)

# True Positives / False Negatives
tp = events[(events["label"].str.lower() == "attack") & (events["detected"])].shape[0]
fn = events[(events["label"].str.lower() == "attack") & (~events["detected"])].shape[0]

# Approximate FP: alerts not matched to any attack
fp = max(0, alerts.shape[0] - tp)

precision = tp / (tp + fp) if tp + fp > 0 else 0
recall = tp / (tp + fn) if tp + fn > 0 else 0
f1 = 2 * precision * recall / (precision + recall) if precision + recall > 0 else 0

print(f"TP: {tp}, FN: {fn}, FP: {fp}")
print(f"Precision: {precision:.2f}, Recall: {recall:.2f}, F1: {f1:.2f}")
