#!/usr/bin/env python3
"""
server_with_sniffer.py
- Accept JSON lines over TCP (one JSON per line) with keys:
  { "can_id": int, "payload_hex": "deadbeef...", "label": "benign"/"attack", "attack_type": "...", "attack_id": "..." }
- Forward each to vcan0
- Maintain last_label_map to attach labels to sniffed frames
- Sniffer thread reads kernel timestamp from vcan0 and appends to can_sniff_log.csv
"""

import socket
import threading
import json
import csv
import time
from datetime import datetime
import can
from threading import Lock

# Server config
HOST = "0.0.0.0"
PORT = 5000

# CAN config
VCAN_IFACE = "vcan0"

# CSV path
CAN_SNIFF_CSV = "ids_can_sniff_log.csv"
FORWARD_LOG_CSV = "forward_log.csv"  # optional record of sends

# Shared state
last_label_map = {}   # maps can_id -> (label, attack_type, attack_id, last_seen_send_ts)
label_lock = Lock()
log_lock = Lock()

def ensure_csv_header():
    # sniff CSV header: timestamp, can_id, dlc, data_hex, label, attack_type, attack_id, sniff_recv_iso
    try:
        with open(CAN_SNIFF_CSV, "x", newline="") as f:
            csv.writer(f).writerow(["timestamp","can_id","dlc","data_hex","label","attack_type","attack_id","sniff_recv_iso"])
    except FileExistsError:
        pass

def sniff_and_log(bus):
    """
    Continuously read messages from CAN bus and log their kernel timestamps + label.
    """
    print(f"[server] Sniffer started on {VCAN_IFACE} (listening for kernel timestamps).")
    ensure_csv_header()
    # open file in append mode and flush each write
    with open(CAN_SNIFF_CSV, "a", newline="") as f:
        writer = csv.writer(f)
        while True:
            try:
                msg = bus.recv(timeout=1.0)
            except Exception as e:
                print(f"[server.sniffer] recv error: {e}")
                time.sleep(0.1)
                continue
            if msg is None:
                continue
            #print(f"[IDS] got frame {hex(msg.arbitration_id)} {msg.data.hex()} at {msg.timestamp:.6f}")
            # kernel timestamp attached to received message
            ts = getattr(msg, "timestamp", time.time())
            can_id_hex = hex(msg.arbitration_id)
            dlc = getattr(msg, "dlc", len(msg.data))
            data_hex = msg.data.hex()

            # fetch label info if available (thread-safe)
            with label_lock:
                meta = last_label_map.get(msg.arbitration_id, ("attack", "", ""))
            label, attack_type, attack_id = meta[:3]

            sniff_iso = datetime.utcnow().isoformat() + "Z"
            # format timestamp to 6 decimals
            writer.writerow([f"{ts:.6f}", can_id_hex, dlc, data_hex, label, attack_type, attack_id, sniff_iso])
            f.flush()

def handle_client(conn, addr, bus):
    """
    Each client sends JSON lines. Example:
    {"can_id": 416, "payload_hex":"0011223344556677", "label":"benign", "attack_type":"", "attack_id":""}
    """
    with conn:
        buf = b""
        while True:
            try:
                data = conn.recv(4096)
                if not data:
                    break
                buf += data
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    try:
                        msg = json.loads(line.decode("utf-8"))
                    except Exception as e:
                        print(f"[server] JSON decode error from {addr}: {e}")
                        continue
                    process_message(msg, bus)
            except ConnectionResetError:
                break
            except Exception as e:
                print(f"[server] client {addr} error: {e}")
                break
    print(f"[server] connection closed {addr}")

def process_message(msg, bus):
    """
    Sends the message to vcan0. Also stores label metadata in last_label_map for sniffing.
    """
    try:
        can_id = int(msg.get("can_id"))
        payload_hex = msg.get("payload_hex", "")
        payload = bytes.fromhex(payload_hex)
        label = msg.get("label", "benign")
        attack_type = msg.get("attack_type", "")
        attack_id = msg.get("attack_id", "")

        # Record send_ts (server-side time when we called send)
        send_ts = time.time()
        # update last_label_map (so sniffer can attribute the label)
        with label_lock:
            last_label_map[can_id] = (label, attack_type, attack_id, send_ts)

        # Build and send CAN frame (do not set timestamp)
        can_msg = can.Message(arbitration_id=can_id, data=payload, is_extended_id=False)
        try:
            bus.send(can_msg)
        except can.CanError as e:
            print(f"[server] CAN send error: {e}")

        # Optionally log the forward action to a separate CSV
        with log_lock:
            with open(FORWARD_LOG_CSV, "a", newline="") as f:
                csv.writer(f).writerow([f"{send_ts:.6f}", hex(can_id), len(payload), payload_hex, label, attack_type, attack_id, datetime.utcnow().isoformat()+"Z"])

    except Exception as e:
        print(f"[server.process_message] error: {e}")

def main():
    # setup CAN bus
    try:
        #bus = can.interface.Bus(channel=VCAN_IFACE, interface='socketcan')
        bus_tx = can.interface.Bus(channel='vcan0', interface='socketcan')
        bus_rx = can.interface.Bus(channel='vcan0', interface='socketcan')
    except Exception as e:
        print(f"[server] failed to open {VCAN_IFACE}: {e}")
        return

    # start sniffer thread
    sniffer = threading.Thread(target=sniff_and_log, args=(bus_rx,), daemon=True)
    sniffer.start()

    # start TCP server to accept JSON clients
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen(5)
    print(f"[server] listening on {HOST}:{PORT} and forwarding to {VCAN_IFACE}")

    try:
        while True:
            conn, addr = s.accept()
            print(f"[server] client connected: {addr}")
            t = threading.Thread(target=handle_client, args=(conn, addr, bus_tx), daemon=True)
            t.start()
    except KeyboardInterrupt:
        print("[server] shutting down")
    finally:
        s.close()
        try:
            bus.shutdown()
        except Exception:
            pass

if __name__ == "__main__":
    main()