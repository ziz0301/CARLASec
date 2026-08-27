#!/usr/bin/env python3
"""
Run the attack server with the desired host/port.
"""

from attack_server import start_attack_server

def main():
    try:
        start_attack_server(host='127.0.0.1', port=5001)
    except Exception as e:
        # Friendly error message for troubleshooting
        print(f"Failed to start attack server: {e}")

if __name__ == "__main__":
    main()
