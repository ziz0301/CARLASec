import pandas as pd
import os

# === CONFIGURATION ===
INPUT_FILE = "ids_alert_log.csv"
DEDUP_FILE = "ids_alert_log_dedup.csv"
OUT_DIR = "ids_alert_log_split"

# Create output folder
os.makedirs(OUT_DIR, exist_ok=True)

# === Load and remove duplicate timestamps ===
df = pd.read_csv(INPUT_FILE)

if "timestamp" not in df.columns:
    raise ValueError("CSV must have a 'timestamp' column")

# Drop duplicate timestamps, keeping the first
df_dedup = df.drop_duplicates(subset="timestamp", keep="first")

# Save cleaned file
df_dedup.to_csv(DEDUP_FILE, index=False)
print(f"[INFO] Deduplicated log saved to: {DEDUP_FILE}")

# === Split by type ===
if "type" not in df.columns:
    raise ValueError("CSV must have a 'type' column to split by")

for msg_type, group in df.groupby("type"):
    out_path = os.path.join(OUT_DIR, f"{msg_type}_log.csv")
    group.to_csv(out_path, index=False)
    print(f"[INFO] Extracted {msg_type} -> {out_path}")

print("[INFO] Done.")
