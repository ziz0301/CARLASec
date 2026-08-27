import os
import sys
import time
import json
import can
import cantools
import pickle
import select
import threading
import isotp
import udsoncan
from udsoncan.connections import IsoTPSocketConnection
from udsoncan import services
from udsoncan.client import Client
from udsoncan import DidCodec
from udsoncan.exceptions import *

from flask import Flask, jsonify, request, render_template

try:
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))) + '/carla')
except IndexError:
    pass
from invehicle_network.ivn.bus import Bus
from invehicle_network.ivn.vul import Vul
from invehicle_network.protocol.uds_server import UDSServer
from invehicle_network.protocol.uds_client import UDSTester
#from attack_manager import attack_mgr
from invehicle_network.protocol.carla_can_control import CAN



db = cantools.database.load_file('bmw.dbc')

# Define class ECU which include nest class of Component and Service
class Ecu:
    all_ecus = []
    def __init__(self, name: str, ecutype: str, bus: 'Bus', components: list = None):
        self.name = name
        self.ecutype = ecutype if ecutype is not None else []
        self.bus = bus if bus is not None else []
        self.components = components if components is not None else []
        



    def addComponent(self, component): #Add Component to an ECU
        self.components.append(component)

    def to_dict(self): #Import from json file
        return {
            "name": self.name,
            "ecutype": self.ecutype,
            "bus": self.bus.to_dict(),
            "components": [c.to_dict() for c in self.components]
        }

    class Component:
        def __init__(self, name: str, os: str, connection: list = None, services: list = None):
            self.name = name
            self.os = os
            self.connection = connection
            self.services = services if services is not None else []

        def addService(self, service): #Add service to Component
            self.services.append(service)

        def addConn(self, other): #Add connection to this Component
            self.connection.append(other)

        def to_dict(self): #Import from json file
            return {
                "name": self.name,
                "os": self.os,
                "connection": self.connection,
                "services": [s.to_dict() for s in self.services]
            }


    class Service:
        def __init__(self, name: str, privilege: str, functionality: str, connection: list = None, vuls: list = None, can_obj=None,):
            self.name = name
            self.privilege = privilege
            self.functionality = functionality
            self.connection = connection
            self.vuls = vuls if vuls is not None else []
            self.door_count = 0        
            self.can_obj = can_obj if can_obj else CAN()   
            #new add for label uds attack
            self.last_uds_attack = None
            self.UDS_WINDOW = 1.5
            self._uds_lock = threading.Lock()    

        def addConn(self, other):
            self.connection.append(other)

        def to_dict(self):
            return {
                "name": self.name,
                "privilege": self.privilege,
                "functionality": self.functionality,
                "connection": self.connection,
                "vuls": [v.to_dict() for v in self.vuls]
            }        

        def firewall_filter(self, can_id=None, tester_id=None, dest_id=None, uds_mode=False):
            try:
                with open('whitelist.txt', 'r') as f:
                    rules = [line.strip().lower() for line in f if line.strip()]
            except FileNotFoundError:
                print("[FIREWALL] Whitelist file not found.")
                return False
            # --- Case 1: CAN frame filtering ---
            if not uds_mode and can_id is not None:
                can_id_hex = hex(can_id).lower()
                if can_id_hex in rules:
                    return True
                else:
                    # print(f"[FIREWALL] Blocked CAN frame {can_id_hex}")
                    return True
            # --- Case 2: UDS tester–destination filtering ---
            if uds_mode and tester_id is not None and dest_id is not None:
                pair = f"{hex(tester_id).lower()}->{hex(dest_id).lower()}"
                if pair in rules:
                    return True
                else:
                    print(f"[FIREWALL] Blocked UDS request {pair}")
                    return True
            return False
            
            

        # Set the GATEWAY listen to the KCAN4 BUS all the time
        def gateway_listener_kcan4(self, stop_event, can_queue):            
            with can.interface.Bus(bustype='socketcan', channel='kcan4') as kcan4:
                while not stop_event.is_set():
                    try:
                        msg1 = kcan4.recv(1.0)
                        if msg1 is not None:
                            '''
                            cur = attack_mgr.get_current_attack()
                            if cur:
                                label = "attack"; attack_type = cur['attack_type']; attack_id = cur['attack_id']
                            else:
                                label = "benign"; attack_type = ""; attack_id = ""
                            self.can_obj._log_message(msg1, label=label, attack_type=attack_type, attack_id=attack_id)
                            '''
                            if (self.firewall_filter(msg1.arbitration_id)):
                                can_queue.put((msg1.arbitration_id, time.time(), msg1))
                                #print(f"canqueue: {can_queue}")     
                    except Exception as e:
                        print(f"Exception in CAN Bus Listener: {e}")
                print("KCAN thread stop")


        # Set the GATEWAY listen to the VCAN0 BUS ALL THE TIME
        def gateway_listener_vcan0(self, stop_event, can_queue):
            with can.interface.Bus(bustype='socketcan', channel='vcan0') as vcan0:
                while not stop_event.is_set():
                    try:
                        msg1 = vcan0.recv(0.02)
                        if msg1 is not None:
                            '''
                            cur = attack_mgr.get_current_attack()
                            if cur:
                                label = "attack"; attack_type = cur['attack_type']; attack_id = cur['attack_id']
                            else:
                                label = "benign"; attack_type = ""; attack_id = ""
                            self.can_obj._log_message(msg1, label=label, attack_type=attack_type, attack_id=attack_id)
                            '''
                            if (self.firewall_filter(msg1.arbitration_id)):
                                #print(f"vcan0: {hex(msg1.arbitration_id)}")
                                can_queue.put((msg1.arbitration_id, time.time(), msg1))
                    except Exception as e:
                        print(f"Exception in CAN Bus Listener: {e}")

                print("VCAN thread stop")

        def ecu_uds_server(self, stop_event, control, vehicle, vehicledoor, attack_tracker, scenario):
            uds_server = UDSServer(attack_tracker)
            s = isotp.socket()
            s.set_fc_opts(stmin=5, bs=10)
            s.bind("vcan0", isotp.Address(rxid=0x7E0, txid=0x7E8))
            #print("Start Listening")

            while not stop_event.is_set():
                try:
                    request = s.recv()
                    if not request:
                        continue
                    # Firewall check for UDS request ID (tester)
                    #tester_id = 0x7E0 
                    #ecu_id   = 0x7E8
                    #if not self.firewall_filter(tester_id=tester_id, dest_id=ecu_id, uds_mode=True):
                    #    print(f"[FIREWALL] Blocked UDS request from tester ID {hex(tester_id)}, {len(request)} bytes, service 0x{request[0]:02X})")
                    #    continue
                    if request[0] == services.DiagnosticSessionControl._sid:
                        response = uds_server.handle_session_change(request)
                        s.send(response)
                    elif request[0] == services.SecurityAccess._sid:                        
                        response = uds_server.handle_security_access_rsa(request)
                        print(f"SecurityAccess Require, the response is: {response}")
                        s.send(response)
                    elif request[0] == services.WriteDataByIdentifier._sid:
                        response = uds_server.handle_write_data_by_identifier(request)
                        s.send(response)
                    elif request[0] == services.ReadDataByIdentifier._sid:
                        response = uds_server.handle_read_data_by_identifier(request)
                        s.send(response)
                    elif request[0] == services.InputOutputControlByIdentifier._sid:
                        response = uds_server.handle_input_output_control(request)
                        s.send(response)
                    elif request[0] == services.RoutineControl._sid:
                        response = uds_server.handle_routine_control(request, control, vehicle, vehicledoor, scenario)
                        self.door_count = uds_server.door_count
                        #print (f"Door count ecu side: {self.door_count}")
                        s.send(response)
                except Exception as e:
                    print (f"Error: {e}")
            print("UDS thread stop")


        #---------------------------------------------------------
        # FUNCTIONS TO DO THE UDS CONTROL
        #---------------------------------------------------------
        def get_door_count(self):
            return self.door_count

        def ecu_uds_tester(self):
            connection=IsoTPSocketConnection(interface='vcan0', rxid=0x456, txid=0x123, tpsock=isotp.socket())
            connection.open()
            uds_tester = UDSTester(connection)
            with Client(connection, request_timeout=10, config=uds_tester.client_config) as client:
                try:
                    #uds_tester.unlock_security_access(client)
                    #uds_tester.change_diagnostic_session(client)
                    #uds_tester.write_vin(client)
                    #uds_tester.read_vin(client)
                    #uds_tester.reset_ecu(client)
                    #uds_tester.test_input_output_control(client)
                    uds_tester.test_routine_control(client)
                except NegativeResponseException as e:
                    print(f'Server refused our request for service {e.response.service.get_name()} with code "{e.response.code_name}" (0x{e.response.code:02x})')
                except InvalidResponseException as e:
                    print(f'Server sent an invalid payload: {e.response.original_payload}')
                except UnexpectedResponseException as e:
                    print(f'Unexpected response from server: {e.response.original_payload}')

        def virtual_shell(self, stop_event):
            print(f"headunit-shell> ", end="", flush=True)
            while not stop_event.is_set():                
                ready, _, _ = select.select([sys.stdin], [], [], 0.1)                
                if ready:  # Only proceed if there's input
                    command = sys.stdin.readline().strip()
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
                else:
                    if stop_event.is_set():
                        print("Virtual shell thread stopping.")
                        break
                        
                        
        #---------------------------------------------------------
        # FUNCTIONS that not used - clean later
        #---------------------------------------------------------                        
                        
        def send_can_message(self, can_obj):
            print(f"{self.name} is sending a CAN message.")
            can_obj.control_wheelspeed(20, 1, 1, 0)

        def transfer_can_message(self, can_obj):
            print(f"{self.name} is transferring a CAN message.")
            can_obj.control_speed_from_can()

        def control_based_on_can_message(self, can_obj):
            print(f"{self.name} is controlling based on a CAN message.")
            can_obj.ecu_receiver()
            
        # Function to simulate ECU sending CAN messages
        def ecu_sender(self, name, can_id_list):
            bus = can.interface.Bus(bustype='socketcan', channel='vcan0')
            while True:
                try:
                    can_id = can_id_list.pop(0)
                    can_id_list.append(can_id)  # Rotate the list
                    message = can.Message(arbitration_id=can_id, data=[1,0,1,0,1,0,1,0])
                    print(f"{name} sending message with CAN ID: {hex(can_id)}")
                    bus.send(message)
                    time.sleep(2)
                except Exception as e:
                    print(f"Exception in {name}:{e}")

        # Function to simulate ECU receiving CAN messages
        def ecu_receiver(self, name, can_queue, can_obj, vehicle):
            print("ECU Receiver");
            while True:
                try:
                    if not can_queue.empty():
                        priority, message = can_queue.get()
                        print(f"{name} received {message} with CAN ID: {hex(message.arbitration_id)}")
                        # Check if CAN ID matches those of interest
                        can_id = message.arbitration_id
                        if can_id == 0x24B:  # Replace with the actual CAN ID for door open
                            decoded_msg = db.decode_message(can_id, message.data)
                            print(f"Successfully get msg with data: {decoded_msg}")
                            can_obj.control_door(vehicle, message)
                        elif can_id == 0x2F6:
                            decoded_msg = db.decode_message(can_id, message.data)
                            print(f"Successfully get msg with data: {decoded_msg}")
                            can_obj.control_light(vehicle, message)
                        else:
                            print(f"Receive message with ID != 0x1A0 and 0x2F6: {hex(message.arbitration_id)}")
                    time.sleep(0.5)
                except Exception as e:
                    print(f"Exception in {name}: {e}")


            # Function to simulate ECU receiving CAN messages
            def gateway_manage(self, name, can_obj, can_queue, vehicle):
                while True:
                    try:
                        if not can_queue.empty():
                            priority, message = can_queue.get()
                            print(f"{name} received {message} with CAN ID: {hex(message.arbitration_id)}")
                            # Check if CAN ID matches those of interest
                            can_id = message.arbitration_id
                            if can_id == 0x24B:  # Replace with the actual CAN ID for door open
                                decoded_msg = db.decode_message(can_id, message.data)
                                print(f"Successfully get msg with data: {decoded_msg}")
                                can_obj.control_door_seperate(vehicle, message)
                            elif can_id == 0xCE:
                                decoded_msg = db.decode_message(can_id, message.data)
                                print(f"Successfully get msg with data: {decoded_msg}")
                                can_obj.control_throttle_seperate(vehicle, message)
                            elif can_id == 0x1A0:
                                decoded_msg = db.decode_message(can_id, message.data)
                                print(f"Successfully get msg with data: {decoded_msg}")
                                can_obj.control_wheelspeed_seperate(vehicle, message)
                            else:
                                print(f"ALERT! Receive message with invalid ID!")
                        time.sleep(0.5)
                    except Exception as e:
                        print(f"Exception in {name}: {e}")                
        #---------------------------------------------------------
        # FUNCTIONS TO DO THE API CONTROL
        #---------------------------------------------------------

        app = Flask(__name__)
        @app.route('/api_control', methods=['GET', 'POST'])
        def api_control():
            data = request.json
            command = data.get('command')

            if command == 'open_door':
                try:
                    bus = can.interface.Bus(bustype='socketcan', channel='kcan4')
                    while True:
                        try:
                            can_id = 0x24B
                            message = can.Message(arbitration_id=can_id, data=[1,0,1,0,1,0,1,0])
                            bus.send(message)
                            return_str = f"Sending message to CAN bus with CAN ID: {hex(can_id)}"
                            return jsonify({'status': 'success', 'action': 'Door Open Successfully'}), 200
                        except Exception as e:
                            return jsonify({'action': str(e)}), 200
                except Exception as e:
                    return jsonify({'action': str(e)}), 500

            elif command == 'close_door':
                try:
                    bus = can.interface.Bus(bustype='socketcan', channel='kcan4')
                    while True:
                        try:
                            can_id = 0x24B
                            message = can.Message(arbitration_id=can_id, data=[0,0,0,0,0,0,0,0])
                            bus.send(message)
                            return_str = f"Sending message to CAN bus with CAN ID: {hex(can_id)}"
                            return jsonify({'status': 'success', 'action': 'Door Close Successfully'}), 200
                        except Exception as e:
                            return jsonify({'action': str(e)}), 200
                except Exception as e:
                    return jsonify({'action': str(e)}), 500

            elif command == 'turnon_highbeam':
                try:
                    bus = can.interface.Bus(bustype='socketcan', channel='kcan4')
                    while True:
                        try:
                            can_id = 0x2F6
                            message = can.Message(arbitration_id=can_id, data=[0,0,1,0,0,0,0,0])
                            bus.send(message)
                            return_str = f"Sending message to CAN bus with CAN ID: {hex(can_id)}"
                            return jsonify({'status': 'success', 'action': 'Turn on High Beam Successfully'}), 200
                        except Exception as e:
                            return jsonify({'action': str(e)}), 200
                except Exception as e:
                    return jsonify({'action': str(e)}), 500

            elif command == 'turnon_lowbeam':
                try:
                    bus = can.interface.Bus(bustype='socketcan', channel='kcan4')
                    while True:
                        try:
                            can_id = 0x2F6
                            message = can.Message(arbitration_id=can_id, data=[1,0,0,0,0,0,0,0])
                            bus.send(message)
                            return_str = f"Sending message to CAN bus with CAN ID: {hex(can_id)}"
                            return jsonify({'status': 'success', 'action': 'Turn on Low Beam Successfully'}), 200
                        except Exception as e:
                            return jsonify({'action': str(e)}), 200
                except Exception as e:
                    return jsonify({'action': str(e)}), 500

            elif command == 'turnoff_light':
                try:
                    bus = can.interface.Bus(bustype='socketcan', channel='kcan4')
                    while True:
                        try:
                            can_id = 0x2F6
                            message = can.Message(arbitration_id=can_id, data=[0,0,0,0,0,0,1,0])
                            bus.send(message)
                            return_str = f"Sending message to CAN bus with CAN ID: {hex(can_id)}"
                            return jsonify({'status': 'success', 'action': 'Turn off Light Successfully'}), 200
                        except Exception as e:
                            return jsonify({'action': str(e)}), 200
                except Exception as e:
                    return jsonify({'action': str(e)}), 500

            else:
                return jsonify({"action": "Invalid command"}), 400



        @app.route('/open_door', methods=['GET', 'POST'])
        def api_opendoor():
            if request.method == 'POST':
                try:
                    bus = can.interface.Bus(bustype='socketcan', channel='kcan4')
                    while True:
                        try:
                            #can_id = can_id_list.pop(0)
                            #can_id_list.append(can_id)  # Rotate the list
                            can_id = 0x24B
                            message = can.Message(arbitration_id=can_id, data=[1,0,1,0,1,0,1,0])
                            bus.send(message)
                            #time.sleep(2)
                            return_str = f"Sending message to CAN bus with CAN ID: {hex(can_id)}"
                            return jsonify({'message': return_str}), 200
                        except Exception as e:
                            return jsonify({'message': str(e)}), 200
                except Exception as e:
                    return jsonify({'message': str(e)}), 500
            else:
                return render_template("mobile.html")


        @app.route('/close_door', methods=['GET', 'POST'])
        def api_closedoor():
            if request.method == 'POST':
                try:
                    bus = can.interface.Bus(bustype='socketcan', channel='kcan4')
                    while True:
                        try:
                            #can_id = can_id_list.pop(0)
                            #can_id_list.append(can_id)  # Rotate the list
                            can_id = 0x24B
                            message = can.Message(arbitration_id=can_id, data=[0,0,0,0,0,0,0,0])
                            bus.send(message)
                            #time.sleep(2)
                            return_str = f"Sending message to CAN bus with CAN ID: {hex(can_id)}"
                            return jsonify({'message': return_str}), 200
                        except Exception as e:
                            return jsonify({'message': str(e)}), 200
                except Exception as e:
                    return jsonify({'message': str(e)}), 500
            else:
                return render_template("mobile.html")


        @app.route('/turnon_highbeam', methods=['GET', 'POST'])
        def api_turnon_highbeam():
            if request.method == 'POST':
                try:
                    bus = can.interface.Bus(bustype='socketcan', channel='kcan4')
                    while True:
                        try:
                            #can_id = can_id_list.pop(0)
                            #can_id_list.append(can_id)  # Rotate the list
                            can_id = 0x2F6
                            message = can.Message(arbitration_id=can_id, data=[0,0,1,0,0,0,0,0])
                            bus.send(message)
                            #time.sleep(2)
                            return_str = f"Sending message to CAN bus with CAN ID: {hex(can_id)}"
                            return jsonify({'message': return_str}), 200
                        except Exception as e:
                            return jsonify({'message': str(e)}), 200
                except Exception as e:
                    return jsonify({'message': str(e)}), 500
            else:
                return render_template("mobile.html")


        @app.route('/turnon_lowbeam', methods=['GET', 'POST'])
        def api_turnon_lowbeam():
            if request.method == 'POST':
                try:
                    bus = can.interface.Bus(bustype='socketcan', channel='kcan4')
                    while True:
                        try:
                            #can_id = can_id_list.pop(0)
                            #can_id_list.append(can_id)  # Rotate the list
                            can_id = 0x2F6
                            message = can.Message(arbitration_id=can_id, data=[1,0,0,0,0,0,0,0])
                            bus.send(message)
                            #time.sleep(2)
                            return_str = f"Sending message to CAN bus with CAN ID: {hex(can_id)}"
                            return jsonify({'message': return_str}), 200
                        except Exception as e:
                            return jsonify({'message': str(e)}), 200
                except Exception as e:
                    return jsonify({'message': str(e)}), 500
            else:
                return render_template("mobile.html")


        @app.route('/turnoff_light', methods=['GET', 'POST'])
        def api_turnoff_light():
            if request.method == 'POST':
                try:
                    bus = can.interface.Bus(bustype='socketcan', channel='kcan4')
                    while True:
                        try:
                            #can_id = can_id_list.pop(0)
                            #can_id_list.append(can_id)  # Rotate the list
                            can_id = 0x2F6
                            message = can.Message(arbitration_id=can_id, data=[0,0,0,0,0,0,1,0])
                            bus.send(message)
                            #time.sleep(2)
                            return_str = f"Sending message to CAN bus with CAN ID: {hex(can_id)}"
                            return jsonify({'message': return_str}), 200
                        except Exception as e:
                            return jsonify({'message': str(e)}), 200
                except Exception as e:
                    return jsonify({'message': str(e)}), 500
            else:
                return render_template("mobile.html")
