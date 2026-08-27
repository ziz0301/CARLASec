#!/usr/bin/env python3
"""
ids_runtime.py
------------------------------------------------------------
STEP 3 – IDS Runtime (Online Evaluation)
Implements:
 - Studnia et al. FSA sequence check
 - Frequency (z-score) anomaly detection
 - Inter-arrival time anomaly (3σ + CUSUM)
 - Payload entropy variation
 - Alert aggregation and logging
------------------------------------------------------------
Input : can_sniff_log_tokens.csv   (from Step 2)
         thresholds.json           (from Step 2)
Output: ids_alert_log.csv          (detection results)
------------------------------------------------------------
"""

# ========================
# [BLOCK 1]  Imports & Config
# ========================

import json
import pandas as pd
import numpy as np
from datetime import datetime
from scipy.stats import zscore, entropy
from collections import Counter

import os
import math
import can
import time
import cantools

import socket 
from attack_server import start_attack_server
import threading, queue



CSV_IN = "ids_test.csv"
THRESHOLDS_FILE = "ids_output_v3/entropy_baseline.json"
ALERT_LOG = "ids_alert_log.csv"
WINDOW_SEC = 0.75   # frequency window size (seconds) # old 1.0

# ========================
# [BLOCK 2]  Utility Functions
# ========================


def compute_kl(p_counter, baseline_q, eps=1e-4):
    # p_counter: Counter of IDs in current window
    total = float(sum(p_counter.values()))
    kl = 0.0
    for cid, c in p_counter.items():
        p = c / total
        q = baseline_q.get(int(cid), 0.0)
        q = q + eps
        kl += p * math.log2(p / q)
    return kl


# ========================
# [BLOCK 3]  IDS Class Definition
# ========================

class IDS:
    def __init__(self, thresholds):
        """
        Load baseline thresholds and initialise runtime state.
        """
        self.thresholds = thresholds
        self.last_timestamp = {}
        self.last_interarrival = {}
        self.freq_window = {}      # sliding window counts
        self.alerts = []

        # FSA sequence rules (Studnia-like)
        self.last_symbol = None
        self.last_steer = None
        self.last_speed = None
        self.valid_transitions = {
            "Idle": ["Idle","ForwardStart","ReverseStart","BrakeHold","HandbrakeActive","SteeringIdle", "Braking", "ChangeGearState"],
            "ForwardStart": ["ForwardRun","Braking","BrakeHold","Idle","SteeringWhileMoving", "SteeringIdle"],
            "ForwardRun": ["Braking","BrakeHold","Idle","SteeringWhileMoving","Conflict"],
            "ReverseStart": ["ReverseRun","Braking","BrakeHold","Idle","SteeringWhileMoving"],
            "ReverseRun": ["Braking","BrakeHold","Idle","SteeringWhileMoving","Conflict"],
            "Braking": ["BrakeHold","Idle","ForwardStart","ReverseStart","SteeringWhileMoving","SteeringIdle"],
            "BrakeHold": ["Idle","ForwardStart","ReverseStart","HandbrakeActive"],
            "HandbrakeActive": ["Idle","HandbrakeActive"],
            "Conflict": ["Idle"],
            "SteeringWhileMoving": ["ForwardRun","ReverseRun","Braking","Idle"],
            "SteeringIdle": ["Idle","BrakeHold","HandbrakeActive", "ChangeGearState"],
            "SpoofSpeedChange": ["Braking","Idle"],
            "SpoofSteeringChange": ["Idle","Braking"],
            "ChangeGearState" : ["Idle", "ForwardStart", "ForwardRun"]
        }
                
        # Sliding-window entropy IDS parameters
        self.entropy_window_sec = thresholds.get("entropy_window", WINDOW_SEC)
        self.entropy_buffer_sliding = []      # list of (timestamp, can_id)
        self.entropy_log_sliding = []         # store computed entropies
        
        signal_entropy_cfg = thresholds.get("0.5", {})
        self.baseline_mu = thresholds.get("mu", 2.76)
        self.baseline_sigma = thresholds.get("sigma", 0.24)
        self.k_sigma = thresholds.get("entropy_k", 4)  # detection sensitivity smaller means more sensetive # old 3

        #Add KL to IDS sliding window
        # load baseline per-ID distribution (from training)
        # baseline_counts should be a dict {can_id: count}
        self.baseline_counts = self.thresholds.get("baseline_counts", {}) # load JSON with counts
        if self.baseline_counts:
            total = sum(self.baseline_counts.values())
            self.baseline_q = {int(k): v/total for k,v in self.baseline_counts.items()}
        else:
            self.baseline_q = {}  # fallback
        self.kl_eps = thresholds.get("kl_eps", 1e-6)
        self.kl_threshold = thresholds.get("kl_threshold", 2.0)  # tune this 0.3 - change log: 1.0, 0.5, 0.3
        

    # ----------------------------------------------------
    # [BLOCK 3.1] Studnia FSA Sequence Check
    # ----------------------------------------------------
    def ids_module_fsa(self,data, timestamp):
        alert = None        
        
        # Safely extract, fallback to 0 if missing or None
        vehicle_speed = data.get("VehicleSpeed") or 0
        moving_forward = data.get("MovingForward") or 0
        moving_reverse = data.get("MovingReverse") or 0
        brake_pressed = data.get("BrakePressed") or 0
        brake_active = data.get("Brake_active") or 0
        handbrake_active = data.get("HandbrakeActive") or 0
        steering_pos = data.get("SteeringPosition") or 0
        manual_gear = data.get("ManualGear") or 0
        gear_state = data.get("GearState") or 0
        auto_gear = data.get("AutoGear") or 0
        brake_value = max(0.0, min(brake_pressed, 1.0))

        #print(f"Speed:{vehicle_speed:.1f} Fwd:{moving_forward} Rev:{moving_reverse} Brake:{brake_active} Press:{brake_value:.2f} Hand:{handbrake_active} #Steer:{steering_pos:.2f} M_Gear:{manual_gear} Gearstat:{gear_state}")
        #print(f"[DEBUG] Current speed: {vehicle_speed}, Last speed: {self.last_speed}")      
        
        if handbrake_active == 1:
            symbol = "HandbrakeActive"
        elif moving_forward == 1 and moving_reverse == 1:
            symbol = "Conflict"
        elif brake_active == 1 or brake_value > 0.05:
            if vehicle_speed > 20:
                symbol = "Braking"
            else:
                symbol = "BrakeHold"
        elif moving_forward == 1 and gear_state > 0:
            if vehicle_speed < 31:
                symbol = "ForwardStart"
            else:
                symbol = "ForwardRun"
        elif moving_reverse == 1 and gear_state < 0:
            if vehicle_speed < 31:
                symbol = "ReverseStart"
            else:
                symbol = "ReverseRun"
        elif abs(steering_pos) > 0.3 and vehicle_speed > 5:
            symbol = "SteeringWhileMoving"
        elif abs(steering_pos) > 0.3 and vehicle_speed <= 5:
            #print(f"abs(steering_pos){abs(steering_pos)}, vehicle_speed: {vehicle_speed}")
            symbol = "SteeringIdle"
        elif gear_state > 1:
            symbol = "ChangeGearState"
        else:
            symbol = "Idle"
        #print(f"self.last_symbol: {self.last_symbol } -- symbol: {symbol}")
                
        if self.last_symbol is not None:
            allowed = self.valid_transitions.get(self.last_symbol, [])
            if symbol not in allowed:
                alert = f"[FSA] Rule violation: {self.last_symbol}->{symbol}"
                print(f"[{datetime.now().strftime('%H:%M:%S')}] {alert}")
                self.alerts.append({"timestamp": f"{timestamp:.6f}", "type": "FSA", "detail": alert})
                self.send_alert_udp(alert)

        self.last_symbol = symbol
        self.last_speed = vehicle_speed
        self.last_steer = steering_pos

        return alert
    
    # ----------------------------------------------------
    # [BLOCK 3.2] Rulebase signal logic IDS
    # ----------------------------------------------------
    def ids_module_signal(self,data,timestamp):
        speed_delta = None  # define first for the entire function
        SPEED_JUMP_THRESHOLD = 20  # km/h sudden jump 10
        STEER_JUMP_THRESHOLD = 0.5  # steering ratio change 0.3
        
        vehicle_speed = data.get("VehicleSpeed") or 0   
        brake_active = data.get("Brake_active") or 0
        steering_pos = data.get("SteeringPosition") or 0
        
        if (vehicle_speed > 0 or brake_active == 1):
            if self.last_speed is not None:
                speed_delta = abs(vehicle_speed - self.last_speed)
                if speed_delta > SPEED_JUMP_THRESHOLD:
                    alert = f"[SignalLogic]Speed jump: prev={self.last_speed}, curr={vehicle_speed}, Δ={speed_delta}"
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] {alert}")
                    self.alerts.append({"timestamp": f"{timestamp:.6f}", "type": "Signal Logic", "detail": alert})
                    self.send_alert_udp(alert)
            self.last_speed = vehicle_speed
            
        if self.last_steer is not None:
            steer_delta = abs(steering_pos - self.last_steer)
            if steer_delta > STEER_JUMP_THRESHOLD:
                alert = f"[SignalLogic] Steering jump: prev={self.last_steer}, curr={steering_pos}, Δsteer={steer_delta}, Δspeed={steer_delta}"
                print(f"[{datetime.now().strftime('%H:%M:%S')}] {alert}")
                self.alerts.append({"timestamp": f"{timestamp:.6f}", "type": "Signal Logic", "detail": alert})
                self.send_alert_udp(alert)
        self.last_steer = steering_pos
        
    # ----------------------------------------------------
    # [BLOCK 3.3] ID Entropy IDS - Sliding windows version with KL
    # ----------------------------------------------------
    def ids_module_entropyid_slidewindow_kl(self, can_id, timestamp):
        kl = None
        # append and trim as before
        self.entropy_buffer_sliding.append((timestamp, can_id))
        cutoff = timestamp - self.entropy_window_sec
        self.entropy_buffer_sliding = [(t,c) for t,c in self.entropy_buffer_sliding if t >= cutoff]

        if len(self.entropy_buffer_sliding) < 20: # 20
            return

        ids = [cid for _, cid in self.entropy_buffer_sliding]
        cnt = Counter(ids)
        probs = np.array(list(cnt.values())) / len(ids)
        H = entropy(probs, base=2)

        # Shannon check
        mu, sigma = self.baseline_mu, self.baseline_sigma
        lower, upper = mu - self.k_sigma * sigma, mu + self.k_sigma * sigma
        #if H < lower or H > upper:
        self.entropy_log_sliding.append({"timestamp": timestamp, "entropy": H, "kl": kl if self.baseline_q else None}) # new
        # Keep only recent entries
        if len(self.entropy_log_sliding) > 50:
            self.entropy_log_sliding.pop(0)

        # --- Two-window confirmation for entropy anomalies ---
        if len(self.entropy_log_sliding) >= 2:
            last_two = [x["entropy"] for x in self.entropy_log_sliding[-2:]]
            if all((h < lower or h > upper) for h in last_two):
                alert = f"[ENTROPY-SLIDING] H={H:.2f} outside {mu:.2f}±{self.k_sigma}σ"
                self.alerts.append({"timestamp": f"{timestamp:.6f}", "type": "ENTROPY_SLIDING", "detail": alert})
                print(f"[{datetime.now().strftime('%H:%M:%S')}] {alert}")
                self.send_alert_udp(alert)

        # -------- KL check ----------
        if self.baseline_q:
            kl = compute_kl(cnt, self.baseline_q, eps=self.kl_eps)
            #print(f"[KL] kl={kl:.3f}")
            if kl > self.kl_threshold:
                alert = f"[KL] distribution change detected: KL={kl:.3f} > {self.kl_threshold}"
                self.alerts.append({"timestamp": f"{timestamp:.6f}", "type": "KL", "detail": alert})
                print(f"[{datetime.now().strftime('%H:%M:%S')}] {alert}")
                self.send_alert_udp(alert)

        # log
        self.entropy_log_sliding.append({"timestamp": timestamp, "entropy": H, "kl": kl if self.baseline_q else None})
    
    def send_alert_udp(self, message="IDS_ALERT"):
        """Send a short UDP alert packet to the CARLA vehicle."""
        UDP_IP = "127.0.0.1"    # or WSL2 host IP if running cross-platform
        UDP_PORT = 5005         # must match listener in CARLA
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(message.encode(), (UDP_IP, UDP_PORT))
            sock.close()
        except Exception as e:
            print(f"[WARN] Failed to send UDP alert: {e}")


# ========================
# [BLOCK 4]  Main Live Evaluation Loop
# ========================
    
def main():
    print("==============================================")
    print("   CARLASec Intrusion Detection System (Live)  ")
    print("==============================================")
    print(f"[INFO] Using thresholds from: {THRESHOLDS_FILE}")
    print(f"[INFO] Logging alerts to: {ALERT_LOG}")
    print(f"[INFO] Listening on CAN interface: vcan0\n")
    #start_attack_server(host='127.0.0.1', port=5001)
    # ------------------------------
    # Load baseline thresholds
    # ------------------------------
    with open(THRESHOLDS_FILE, "r") as f:
        thresholds = json.load(f)
    ids = IDS(thresholds)
    db = cantools.database.load_file("carla_network.dbc")

    # ------------------------------
    # Setup CAN interface
    # ------------------------------
    try:
        bus = can.interface.Bus(channel='vcan0', bustype='socketcan')
    except OSError as e:
        print(f"[ERROR] Cannot connect to vcan0: {e}")
        return

    print("[INFO] IDS is now running. Press Ctrl+C to stop.\n")

    # ------------------------------
    # Main detection loop
    # ------------------------------
    try:
        while True:
            msg = bus.recv(timeout=1.0)
            if msg is None:
                continue  # no message in this interval
            #timestamp = time.time()
            kernel_ts = getattr(msg, "timestamp", None)
            if kernel_ts is None:
                kernel_ts = time.time()
            authoritative_ts = float(kernel_ts)
            can_id = msg.arbitration_id
            try:
                data = db.decode_message(msg.arbitration_id, msg.data)
            except Exception:
                data = {}
                
            #print(msg); 
            
            ids.ids_module_entropyid_slidewindow_kl(can_id, authoritative_ts)
            ids.ids_module_signal(data,authoritative_ts)
            ids.ids_module_fsa(data, authoritative_ts)

    except KeyboardInterrupt:
        print("\n[INFO] Stopping IDS...")
        
    finally:
        pd.DataFrame(ids.alerts).to_csv(ALERT_LOG, index=False, float_format="%.6f")
        print(f"[INFO] Alerts saved to {ALERT_LOG}")
        try:
            bus.shutdown() 
            print("[INFO] CAN bus closed properly.")
        except Exception as e:
            print("[WARN] Error closing bus:", e)
        print("[INFO] IDS terminated.")

# ========================
# [BLOCK 5]  Entry Point
# ========================

if __name__ == "__main__":
    main()
