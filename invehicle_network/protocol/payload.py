import can
import time

RX_ID = 0x456  # ECU response ID
TX_ID = 0x123  # Tester sending back
SECURITY_SUBFUNCTION = 0x04  # Response to 0x03

def receive_isotp_seed(bus, timeout=5):
    print("[*] Waiting for ISO-TP response from ECU...")
    start_time = time.time()
    frames = []

    while time.time() - start_time < timeout:
        msg = bus.recv(timeout=0.1)
        if msg is None:
            continue
        if msg.arbitration_id != RX_ID:
            continue

        frames.append(msg)

        # If first frame, read length
        if msg.data[0] >> 4 == 0x1:
            total_len = ((msg.data[0] & 0x0F) << 8) + msg.data[1]
            expected_consec_frames = (total_len - 6 + 7) // 7
            print(f"[*] Expecting {expected_consec_frames + 1} ISO-TP frames.")
            while len(frames) < expected_consec_frames + 1:
                msg = bus.recv(timeout=1.0)
                if msg and msg.arbitration_id == RX_ID:
                    frames.append(msg)
            break

    if not frames:
        print("[!] No response received.")
        return None

    # Reassemble payload
    payload = bytearray()

    for frame in frames:
        if frame.data[0] >> 4 == 0x1:  # First frame
            payload.extend(frame.data[2:8])
        elif frame.data[0] >> 4 == 0x2:  # Consecutive frame
            payload.extend(frame.data[1:])
    return bytes(payload)

def compute_key(seed):
    seed_int = int.from_bytes(seed, byteorder='big')
    key_int = seed_int + 1
    return key_int.to_bytes(len(seed), byteorder='big')

def chunk_data(data):
    chunks = [data[i:i+7] for i in range(0, len(data), 7)]
    return chunks

def generate_cansend_commands(key_payload):
    full_payload = bytes([0x27, SECURITY_SUBFUNCTION]) + key_payload
    chunks = chunk_data(full_payload)

    cmds = []
    if len(full_payload) <= 7:
        data = bytes([len(full_payload)]) + full_payload
        cmds.append(f"cansend vcan0 {TX_ID:03X}#{data.hex()}")
    else:
        total_len = len(full_payload)
        first_frame = bytes([0x10 | (total_len >> 8), total_len & 0xFF]) + full_payload[:6]
        cmds.append(f"cansend vcan0 {TX_ID:03X}#{first_frame.hex()}")

        cmds.append(f"cansend vcan0 {TX_ID:03X}#300000")  # Flow Control frame

        consec_chunks = chunk_data(full_payload[6:])
        for i, chunk in enumerate(consec_chunks):
            pci = 0x21 + i
            frame = bytes([pci]) + chunk
            cmds.append(f"cansend vcan0 {TX_ID:03X}#{frame.hex()}")

    return cmds

def main():
    bus = can.interface.Bus(channel='vcan0', bustype='socketcan')
    seed_response = receive_isotp_seed(bus)

    if not seed_response:
        return

    if seed_response[0] != 0x67 or seed_response[1] != 0x03:
        print(f"[!] Unexpected UDS response: {seed_response.hex()}")
        return

    seed = seed_response[2:]
    print(f"[+] Received seed: {seed.hex()}")

    key = compute_key(seed)
    print(f"[+] Computed key: {key.hex()}")

    commands = generate_cansend_commands(key)
    print("\n[+] Manual cansend commands to respond with key:")
    for cmd in commands:
        print(cmd)

if __name__ == '__main__':
    main()
