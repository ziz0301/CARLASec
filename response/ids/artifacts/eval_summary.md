# IDS evaluation on dataset_new/dataset2.csv

- frames: **24886**  (benign=16105, attack=8781)
- cold-start frames with no decision: **31**
- FP context window: **±100 ms**

## 1. Strict metrics (per-source labeling)

| metric | value |
|---|---:|
| TP | 8581 |
| FP | 879 |
| TN | 15226 |
| FN | 200 |
| precision | 0.9071 |
| recall | 0.9772 |
| f1 | 0.9408 |
| accuracy | 0.9566 |

## 2. ROC AUC

| score | vs strict labels | vs context-aware labels |
|---|---:|---:|
| IDS1 prediction MSE | 0.9845 | — |
| IDS2 prediction MSE | 0.9069 | — |
| max(IDS1, IDS2) | 0.9845 | — |
| **full system (rule ∨ max)** | **0.9893** | **0.9979** |

## 3. Per-CAN-ID benign cadence (rationale for the ±100 ms window)

| stream | n | mean Δ (ms) | median Δ (ms) | freq (Hz) |
|---|---:|---:|---:|---:|
| `bus (all)` | 16105 | 83.32 | 46.53 | 12.00 |
| `0x0BA` | 4027 | 333.23 | 326.68 | 3.00 |
| `0x0C4` | 4022 | 333.65 | 328.05 | 3.00 |
| `0x1A0` | 4029 | 333.07 | 327.97 | 3.00 |
| `0x1B4` | 4027 | 333.24 | 327.59 | 3.00 |

_Each known CAN ID is sent at ≈ 3 Hz (~333 ms per-ID cycle). With 4 IDs interleaved the bus carries a frame every ~83 ms (≈ 12 Hz). The ±100 ms window is therefore ~1.2 × the bus inter-frame interval and ~30 % of one ID's cycle — it captures the immediate operational neighborhood of a frame (≈ 2–3 bus frames) without spanning across burst gaps (the attack scripts use 5–8 s pauses between bursts)._

## 4. FP categorisation (±100 ms window)

| category | definition | count | % of FPs |
|---|---|---:|---:|
| `same_cid_recent_attack` | at least one attack on the SAME CAN ID has a timestamp in (t−100 ms, t) | 347 | 39.5% |
| `near_diff_cid_only` | no same-CID attack in (t−100 ms, t), but at least one attack on any CAN ID within ±100 ms | 491 | 55.9% |
| `isolated` | no attack on any CAN ID within ±100 ms — truly false alarm | 41 | 4.7% |

## 5. Context-aware metrics

_A benign frame is relabeled to 'attack' if its FP-category is anything other than `isolated` — i.e., the bus was under attack within ±100 ms of that frame. This reflects an operator-facing view of bus compromise._

| metric | strict | context-aware | Δ |
|---|---:|---:|---:|
| TP | 8581 | 9419 | +838 |
| FP | 879 | 41 | -838 |
| TN | 15226 | 15226 | +0 |
| FN | 200 | 200 | +0 |
| precision | 0.9071 | 0.9957 | +0.0886 |
| recall | 0.9772 | 0.9792 | +0.0020 |
| f1 | 0.9408 | 0.9874 | +0.0465 |
| accuracy | 0.9566 | 0.9903 | +0.0337 |

## 6. Per-attack-type recall (strict labels)

| attack_type | detected / total | recall |
|---|---:|---:|
| dos | 1495 / 1495 | 1.000 |
| fuzz_edme | 616 / 616 | 1.000 |
| fuzz_eps | 1994 / 2053 | 0.971 |
| fuzz_random | 1250 / 1250 | 1.000 |
| spoof_brake | 403 / 425 | 0.948 |
| spoof_forward | 597 / 641 | 0.931 |
| spoof_reverse | 1051 / 1051 | 1.000 |
| spoof_steer | 1175 / 1250 | 0.940 |

## 7. Alert-source breakdown

| reason | count |
|---|---:|
| ids1_threshold | 6048 |
| unknown_id | 2745 |
| ids2_threshold | 667 |
