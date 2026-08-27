#!/usr/bin/env python3
"""
server.py
Simple TCP server that accepts JSON lines from clients:
Each line: {"can_id": <int>, "payload_hex": "deadbeef...", "label":"benign"|"attack",
            "attack_type": "...", "attack_id":"...","timestamp": <float>}
The server forwards each message to vcan0 and appends a CSV log row.
"""

import socket, threading, json, csv, time
import can
from datetime import datetime
from pathlib import Path
from threading import Lock

HOST = "0.0.0.0"
PORT = 5000
LOG_CSV = "ids_can_sniff_log.csv"
VCAN_IFACE = "vcan0"

log_lock = Lock()

def setup_bus():
    # socketcan interface
    bus = can.interface.Bus(channel=VCAN_IFACE, interface='socketcan')
    return bus

def ensure_log_header():
    if not Path(LOG_CSV).exists():
        with open(LOG_CSV, "w", newline='') as f:
            csv.writer(f).writerow(["timestamp","can_id","dlc","payload_hex","label","attack_type","attack_id","recv_time_iso"])

def handle_client(conn, addr, bus):
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
                        print(f"[{addr}] JSON decode error: {e}")
                        continue
                    process_message(msg, bus)
            except Exception as e:
                print(f"[{addr}] Connection error: {e}")
                break
    print(f"[{addr}] disconnected")

def process_message(msg, bus):
    """
    msg keys: can_id (int), payload_hex (str), label, attack_type, attack_id, timestamp (opt)
    """
    try:
        can_id = int(msg.get("can_id"))
        payload_hex = msg.get("payload_hex", "")
        payload = bytes.fromhex(payload_hex)
        timestamp = time.time()
        #timestamp = msg.get("timestamp", time.time())
        label = msg.get("label", "benign")
        attack_type = msg.get("attack_type", "")
        attack_id = msg.get("attack_id", "")

        # send to vcan
        can_msg = can.Message(arbitration_id=can_id, data=payload, is_extended_id=False, timestamp=timestamp)
        try:
            bus.send(can_msg)
        except can.CanError as e:
            print(f"[server] CAN send error: {e}")

        # append CSV
        recv_iso = datetime.utcnow().isoformat() + "Z"
        row = [timestamp, hex(can_id), len(payload), payload_hex, label, attack_type, attack_id, recv_iso]
        with log_lock:
            with open(LOG_CSV, "a", newline='') as f:
                csv.writer(f).writerow(row)

    except Exception as e:
        print(f"[process_message] error: {e}")

def main():
    ensure_log_header()
    bus = setup_bus()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen(5)
    print(f"[server] listening on {HOST}:{PORT}, forwarding to {VCAN_IFACE}")

    try:
        while True:
            conn, addr = s.accept()
            print(f"[server] connection from {addr}")
            t = threading.Thread(target=handle_client, args=(conn, addr, bus), daemon=True)
            t.start()
    except KeyboardInterrupt:
        print("[server] shutting down")
    finally:
        s.close()
        bus.shutdown()

if __name__ == "__main__":
    main()
