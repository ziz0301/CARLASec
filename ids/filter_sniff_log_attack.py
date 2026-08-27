import pandas as pd
import os

# === CONFIGURATION ===
INPUT_FILE = "../ids_can_sniff_log.csv"
OUT_DIR = "can_sniff_log_split"

# Create output folder
os.makedirs(OUT_DIR, exist_ok=True)

# === Load and remove duplicate timestamps ===
df = pd.read_csv(INPUT_FILE)

# === Split by label ===
if "timestamp" not in df.columns:
    raise ValueError("CSV must have a 'timestamp' column")
if "label" not in df.columns:
    raise ValueError("CSV must have a 'label' column to split by")

for msg_type, group in df.groupby("label"):
    out_path = os.path.join(OUT_DIR, f"{msg_type}_log.csv")
    group.to_csv(out_path, index=False)
    print(f"[INFO] Extracted {msg_type} -> {out_path}")

print("[INFO] Done.")
