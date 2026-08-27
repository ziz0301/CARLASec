#!/usr/bin/env python3

import socket

UDP_IP = "127.0.0.1"
UDP_PORT = 5005

print("====================================")
print(" Fake IDS Runtime ")
print("====================================")
print("Press:")
print("1 : DoS")
print("2 : Spoofing")
print("3 : Fuzzing")
print("q : Quit")

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

while True:

    cmd = input("> ")

    if cmd == "1":
        msg = "DoS"
        sock.sendto(msg.encode(), (UDP_IP, UDP_PORT))
        print("[IDS] DoS alert sent")

    elif cmd == "2":
        msg = "Spoofing"
        sock.sendto(msg.encode(), (UDP_IP, UDP_PORT))
        print("[IDS] Spoofing alert sent")

    elif cmd == "3":
        msg = "Fuzzing"
        sock.sendto(msg.encode(), (UDP_IP, UDP_PORT))
        print("[IDS] Fuzzing alert sent")

    elif cmd == "q":
        break

sock.close()