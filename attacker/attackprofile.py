import subprocess
import time


class Attacker:
    def __init__(self, t_start=5, t_interval=5, t_attack=5, t_wait=5, bus='vcan0', canid='123'):
        self.t_start = t_start
        self.t_interval = t_interval
        self.t_attack = t_attack
        self.t_wait = t_wait
        self.bus = bus
        self.canid = canid

    def run_attack(self, candata1, candata2):
        time.sleep(self.t_start)

        for cycle in range(1, self.t_interval + 1):
            # Send command 1 securely
            command1 = f'{self.bus} {self.canid}#{candata1}'
            print (f"command is {command1}")
            subprocess.run(['cansend'] + command1.split())
            time.sleep(self.t_attack)

            # Send command 2 securely
            command2 = f'{self.bus} {self.canid}#{candata2}'
            subprocess.run(['cansend'] + command2.split())
            time.sleep(self.t_wait)
