# make_test_csvs.py
import pandas as pd, time, json
base_time = time.time()
rows = []

# helper to format unix float timestamp
def ts(offset): return base_time + offset

# ----- 1) FSA violation: Forward -> Reverse without Idle -----
rows += [
    {"timestamp": ts(0.0), "can_id":"0x1a0", "dlc":8, "payload_hex":"080000f02030024a", "token":"Idle","label":"benign"},
    {"timestamp": ts(0.1), "can_id":"0x1a0", "dlc":8, "payload_hex":"080000f02030024a", "token":"Forward","label":"benign"},
    {"timestamp": ts(0.2), "can_id":"0x1a0", "dlc":8, "payload_hex":"080000f02030024a", "token":"Reverse","label":"attack","attack_type":"spoof","attack_id":"A1"}
]

# ----- 2) Frequency (DoS) test: rapid bursts for a single ID -----
for i in range(20):
    rows.append({"timestamp": ts(1.0 + i*0.01), "can_id":"0x1a0", "dlc":8, "payload_hex":"080000f02030024a", "token":"Forward","label":"attack","attack_type":"dos","attack_id":"A2"})

# ----- 3) Inter-arrival huge gap (timing-shift) -----
rows += [
    {"timestamp": ts(2.5), "can_id":"0xc4", "dlc":8, "payload_hex":"0000000000000000", "token":"Unknown","label":"benign"},
    {"timestamp": ts(5.5), "can_id":"0xc4", "dlc":8, "payload_hex":"0000000000000000", "token":"Unknown","label":"attack","attack_type":"timing","attack_id":"A3"}
]

# ----- 4) Payload fuzzing (high entropy) -----
rows += [
    {"timestamp": ts(6.0), "can_id":"0x24b", "dlc":8, "payload_hex":"0008000000000000", "token":"Unknown","label":"benign"},
    {"timestamp": ts(6.1), "can_id":"0x24b", "dlc":8, "payload_hex":"deafbeefcafebabe", "token":"Unknown","label":"attack","attack_type":"fuzz","attack_id":"A4"}
]

# ----- 5) Throttle jump (sudden big increase) -----
rows += [
    {"timestamp": ts(7.0), "can_id":"0x1a0", "dlc":8, "payload_hex":"010000f020300001", "token":"Forward","label":"benign"},
    {"timestamp": ts(7.05),"can_id":"0x1a0", "dlc":8, "payload_hex":"ff0000f020300002", "token":"Forward|ThrottleJump","label":"attack","attack_type":"spoof","attack_id":"A5"}
]

df = pd.DataFrame(rows)
df.to_csv("ids_test_small.csv", index=False)
print("Wrote ids_test_small.csv with", len(df), "rows")
