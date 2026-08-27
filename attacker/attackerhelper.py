import subprocess
import time
import os

def start_dbus():
    result = subprocess.run(['dbus-launch'], capture_output=True, text=True)
    dbus_env = {}
    for line in result.stdout.split('\n'):
        if 'DBUS_SESSION_BUS_ADDRESS' in line or 'DBUS_SESSION_BUS_PID' in line:
            key, value = line.split('=', 1)
            dbus_env[key] = value
            os.environ[key] = value
    return dbus_env

def start_gnome_terminal():
    return subprocess.run(['gnome-terminal', '--', 'bash', '--init-file', 'attacker.sh'])

def stop_dbus(dbus_env):
    dbus_pid = dbus_env.get('DBUS_SESSION_BUS_PID')
    if dbus_pid:
        subprocess.run(['kill', '-TERM', dbus_pid])