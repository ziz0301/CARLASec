import subprocess
import time
import re
from datetime import datetime

# Define the CAN interface and message
interface = "vcan0"
message = "123#053101A964"

# Start sending messages in the background
send_process = subprocess.Popen(
    f"while true; do cansend {interface} {message}; done",
    shell=True,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL
)

# Function to parse the timestamp from candump output
def parse_timestamp(line):
    match = re.search(r"\((\d+\.\d+)\)", line)
    if match:
        return float(match.group(1))
    return None

try:
    # Start capturing the messages with candump
    candump_process = subprocess.Popen(
        ["candump", "-t", "a", interface],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True
    )

    # Capture timestamps of messages
    timestamps = []
    start_time = time.time()

    # Collect messages for a short duration to calculate bitrate
    while time.time() - start_time < 5:  # Collect for 5 seconds
        line = candump_process.stdout.readline()
        timestamp = parse_timestamp(line)
        if timestamp is not None:
            timestamps.append(timestamp)

    # Stop sending and candump processes
    send_process.terminate()
    candump_process.terminate()

    # Calculate messages per second
    if len(timestamps) > 1:
        time_diffs = [j - i for i, j in zip(timestamps[:-1], timestamps[1:])]
        avg_time_diff = sum(time_diffs) / len(time_diffs)
        messages_per_second = 1 / avg_time_diff
        message_size_bits = 128  # Standard CAN frame with 8 bytes of data
        bitrate = messages_per_second * message_size_bits

        print(f"Estimated Message Rate: {messages_per_second:.2f} messages/sec")
        print(f"Estimated Bitrate: {bitrate:.2f} bits/sec")
    else:
        print("Insufficient messages to calculate bitrate.")

except KeyboardInterrupt:
    pass
finally:
    send_process.terminate()
    candump_process.terminate()
