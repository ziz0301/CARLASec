#!/usr/bin/env python3
import importlib.util
import pandas as pd
import json, os, math

# --- Load your IDS class ---
IDS_FILE = "ids_runtime.py"
spec = importlib.util.spec_from_file_location("ids_runtime", IDS_FILE)
ids_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ids_module)

# --- Load thresholds ---
THRESHOLDS_FILE = getattr(ids_module, "THRESHOLDS_FILE", "ids_output_v3/entropy_baseline.json")
if os.path.exists(THRESHOLDS_FILE):
    with open(THRESHOLDS_FILE, "r") as f:
        thresholds = json.load(f)
else:
    thresholds = {}

ids = ids_module.IDS(thresholds)

# --- Input & Output ---
CSV_IN = "ids_test.csv"  # replace with your log file
OUT_CSV = "ids_test_with_alert.csv"

df = pd.read_csv(CSV_IN)
if "can_id" in df.columns:
    df.rename(columns={"can_id": "arbitration_id"}, inplace=True)

# --- Prepare output ---
alerts = []

for idx, row in df.iterrows():
    timestamp = float(row["timestamp"])
    # normalise CAN ID (strip 0x if string)
    can_id = row["arbitration_id"]
    if isinstance(can_id, str) and can_id.lower().startswith("0x"):
        can_id = int(can_id, 16)
    else:
        can_id = int(can_id)

    before = len(ids.alerts)
    ids.ids_module_entropyid_slidewindow_kl(can_id, timestamp)
    ids.ids_module_signal({}, None, timestamp)  # empty decoded data (if you don't have decoded fields)
    ids.ids_module_fsa({}, None, timestamp)
    after = len(ids.alerts)

    # If any alert triggered, get type(s)
    if after > before:
        new_alerts = ids.alerts[before:after]
        types = list({a["type"] for a in new_alerts})
        alert_type = ";".join(types)
    else:
        alert_type = ""

    alerts.append(alert_type)

# Append new column
df["ids_alert"] = alerts
df.to_csv(OUT_CSV, index=False)
print(f"[INFO] IDS results saved to {OUT_CSV}")
