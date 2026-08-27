import os
import subprocess
import getpass

def virtual_shell():
    while True:
        command = input(f"headunit-shell> ")

        if command.startswith("play_music"):
            print("Playing music...")

        elif command.startswith("stop_music"):
            print("Music stopped...")

        elif command.startswith("cansend"):
            try:
                _, interface, message = command.split(maxsplit=2)
                os.system(f"cansend {interface} {message}")
                print(f"Sent CAN message on {interface}: {message}")
            except ValueError:
                print("Usage: cansend <interface> <message>")

        elif command.startswith("candump"):
            try:
                _, interface = command.split(maxsplit=1)
                os.system(f"candump {interface}")
            except ValueError:
                print("Usage: candump <interface>")

        elif command.startswith("ifconfig"):
            os.system("ifconfig")

        elif command.startswith("cd "):
            try:
                path = command.split(" ", 1)[1]
                os.chdir(path)
                current_path = os.getcwd()
            except Exception as e:
                print(f"Error: {e}")

        elif command.startswith("python "):
            try:
                script = command.split(" ", 1)[1]
                subprocess.run(["python", script])
            except Exception as e:
                print(f"Error: {e}")

        elif command.startswith("./"):
            try:
                script = command.split(" ", 1)[0]
                subprocess.run([script] + command.split()[1:])
            except Exception as e:
                print(f"Error: {e}")

        elif command == "pwd":
            print(os.getcwd())

        elif command == "whoami":
            print(getpass.getuser())

        elif command == "exit":
            break

        elif command == "help":
            command_list = {
                "play_music": "Start playing music",
                "stop_music": "Stop the music",
                "send_can <interface> <message>": "Send CAN message",
                "candump <interface>": "Dump CAN messages",
                "ifconfig": "Display network interfaces",
                "cd <path>": "Change directory",
                "python <script>": "Run Python script",
                "./<script>": "Execute shell script or binary",
                "pwd": "Display current directory",
                "whoami": "Display current user",
                "exit": "Exit the virtual shell",
                "help": "List available commands"
            }

            for cmd, description in command_list.items():
                print(f"{cmd:30} - {description}")
        else:
            print(f"Unknown command: {command}")

virtual_shell()
