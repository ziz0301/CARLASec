import cantools
import struct

# Load DBC
db = cantools.database.load_file("bmw.dbc")
msg = db.get_message_by_name("EngineData")

# Craft two signals
signals_1 = {
    "VehicleSpeed": 6,
    "MovingForward": 0,
    "MovingReverse": 1,
    "BrakePressed": 0,  # physical value
    "Brake_active": 0,
    "Damping_rate_full_throttle": 0.15,
    "Damping_rate_zero_throttle_clutch_engaged": 2.0,
    "Damping_rate_zero_throttle_clutch_disengaged": 0.35,
    "Checksum_416": 0  # temp, we'll fill it later
}
data_1 = bytearray(msg.encode(signals_1))
checksum = sum(data_1[:7]) % 256
data_1[7] = checksum        

print("Message for BrakePressed = 0.5:")
print(" ".join(f"{b:02X}" for b in data_1))

decoded = msg.decode(data_1)
print("Decode for test:")
print(decoded)