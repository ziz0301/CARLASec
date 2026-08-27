import argparse
import time
import random
import can
import logging
from threading import Thread


logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class UDSAttack:
    def __init__(self, can_interface, time_of_attack):
        self.can_interface = can_interface
        self.time_of_attack = time_of_attack
        self.bus = can.interface.Bus(can_interface, bustype='socketcan')

    def send_message(self, msg):
        try:
            self.bus.send(msg)
            logging.info(f"Sent CAN message: ID={msg.arbitration_id}, Data={msg.data}")
        except can.CanError as e:
            logging.error(f"CAN Error: {e}")

    def replay_attack(self, arbitrationid, data):
        #using udsoncan
        print("Replay attack")

    def fuzzing_attack(self):
        #fuzzing attack
        print("Fuzzing attack")

    def execute_attack(self, attack_type):
        release_time, duration, period = self.time_of_attack
        time.sleep(release_time)
        end_time = time.time() + duration
        while time.time() < end_time:
            if attack_type == 'can_replay':
                self.replay_attack('123456', 'ABCDEF')
            elif attack_type == 'can_dos':
                self.dos_attack()
            elif attack_type == 'can_fuzzing':
                self.fuzzing_attack()
            time.sleep(period)
