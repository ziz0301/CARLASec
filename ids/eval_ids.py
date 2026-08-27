import pandas as pd
import os

# === CONFIGURATION ===
ATTACK_LOG = "can_sniff_log_split/attack_log.csv"
ALERT_LOG  = "ids_alert_log_dedup.csv"
OUTPUT_DIR = "ids_evaluation_results"

# === SETUP ===
os.makedirs(OUTPUT_DIR, exist_ok=True)

# === LOAD FILES ===
attack_df = pd.read_csv(ATTACK_LOG)
alert_df  = pd.read_csv(ALERT_LOG)

# === VALIDATE COLUMNS ===
if "timestamp" not in attack_df.columns or "timestamp" not in alert_df.columns:
    raise ValueError("Both CSV files must contain a 'timestamp' column.")

# === STEP 1: Mark detected attacks ===
attack_df["detected"] = attack_df["timestamp"].isin(alert_df["timestamp"])

# === STEP 2: Compute confusion matrix ===
TP = int(attack_df["detected"].sum())                                 # attacks detected correctly
FN = int(len(attack_df) - TP)                                         # missed attacks
FP = int(len(alert_df[~alert_df["timestamp"].isin(attack_df["timestamp"])]))  # extra alerts not tied to attack
TN = 0                                                                # unknown (no benign samples)

# === STEP 3: Calculate metrics ===
precision = TP / (TP + FP) if (TP + FP) > 0 else 0.0
recall    = TP / (TP + FN) if (TP + FN) > 0 else 0.0
f1_score  = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
accuracy  = TP / (TP + FN) if (TP + FN) > 0 else 0.0  # no TN data, so same as recall here

# === STEP 4: Save detailed detection report ===
detection_report_path = os.path.join(OUTPUT_DIR, "detection_report.csv")
attack_df.to_csv(detection_report_path, index=False)

# === STEP 5: Save summary ===
summary_data = {
    "Metric": [
        "True Positive (Detected Attacks)",
        "False Negative (Missed Attacks)",
        "False Positive (Extra Alerts)",
        "True Negative (Unknown)",
        "Precision",
        "Recall",
        "F1-Score",
        "Accuracy"
    ],
    "Value": [TP, FN, FP, TN,
              round(precision, 3),
              round(recall, 3),
              round(f1_score, 3),
              round(accuracy, 3)]
}
summary_df = pd.DataFrame(summary_data)
summary_path = os.path.join(OUTPUT_DIR, "detection_summary.csv")
summary_df.to_csv(summary_path, index=False)

# === PRINT RESULTS ===
print("\n=== IDS Detection Evaluation Summary ===")
print(summary_df.to_string(index=False))
print(f"\nDetailed report saved to: {detection_report_path}")
print(f"Summary saved to: {summary_path}")
