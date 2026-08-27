#!/usr/bin/env python3
"""
decode_and_merge.py
Decodes raw CAN CSV (timestamp, can_id, dlc, payload_hex, label, attack_type, attack_id)
using a DBC file, and writes can_sniff_log_decoded.csv
"""
import cantools
import pandas as pd
from pathlib import Path

CSV_IN = "can_sniff_log.csv"
DBC_FILE = "carla_network.dbc"      # adjust to your DBC filename
CSV_OUT = "can_sniff_log_decoded.csv"

print("Loading DBC...")
db = cantools.database.load_file(DBC_FILE)

print("Reading CSV...")
df = pd.read_csv(
    CSV_IN,
    names=["timestamp", "can_id", "dlc", "payload_hex", "label", "attack_type", "attack_id"],
    header=0
)
if "can_id" not in df.columns:
    raise ValueError(f"Expected header missing: {df.columns.tolist()}")    

decoded_rows = []
for _, row in df.iterrows():
    canid = int(row["can_id"], 16) if isinstance(row["can_id"], str) else int(row["can_id"])
    payload = bytes.fromhex(str(row["payload_hex"]))
    decoded = {}
    try:
        msg = db.get_message_by_frame_id(canid)
        decoded = msg.decode(payload)
    except Exception:
        # ignore unknown or malformed frames
        pass

    row_dict = row.to_dict()
    row_dict.update(decoded)
    decoded_rows.append(row_dict)

df_decoded = pd.DataFrame(decoded_rows)
df_decoded.to_csv(CSV_OUT, index=False)
print(f"Decoded file saved: {Path(CSV_OUT).resolve()}")
