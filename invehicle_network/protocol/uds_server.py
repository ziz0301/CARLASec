#uds_server.py

import udsoncan
import isotp
import os
import time
import threading
from udsoncan import services
import pickle
import sys
from Crypto.Cipher import AES
import os
from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Hash import SHA256


try:
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))) + '/carla')
except IndexError:
    pass
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
from attacker.attack_tracker import AttackTracker


# Constants
SEED_LEN = 32                      # 256-bit seed
SEED_VALID_SECONDS = 5             # seed validity window
NVM_COUNTER_FILE = "/tmp/uds_incorrect_counter.bin"  # simulate NVM
PUBKEY_STORE_FILE = "/tmp/uds_pubkey.pem"           # store verification pubkey
MAX_INCORRECT_BEFORE_LOCKOUT = 2   # threshold for lockout
MAX_BACKOFF_SEC = 60               # cap backoff at 60s
ATTEMPT_LOG_FILE = "/tmp/uds_attempts.csv" 

class UDSServer:
    def __init__(self, attack_tracker=None):
        self.seed = None  # Initialize seed as None
        self.security_level = 0  # Initially no security access
        self.current_session = services.DiagnosticSessionControl.Session.defaultSession  # Default session on startup
        self.data_store = self.load_data_store()
        self.controlling_vehicle = False  # Flag to indicate if vehicle is being controlled
        self.stop_vehicle_control = False  # Flag to signal stopping vehicle control
        self.control_thread = None
        self.door_open = False
        self.door_count = 0
        self.tmp_door = False
        self.thread_throttle = None
        self.thread_steer = None
        self.thread_brake = None
        self.thread_gear = None
        self.attack_tracker = attack_tracker

        print(f"UDS INFORMATION - CURRENT SECURITY LEVEL:{self.security_level}")
        print(f"UDS INFORMATION - CURRENT SESSION:{self.current_session}")

    def load_data_store(self):
        if os.path.exists("data_store.pkl"):
            with open("data_store.pkl", "rb") as file:
                data = pickle.load(file)
                print(f"UDS INFORMATION - DATA INDENTIFIER: {data}")
                return data
        else:
            return {}

    def save_data_store(self):
        with open("data_store.pkl", "wb") as f:
            pickle.dump(self.data_store, f)

    def get_seed_based_on_subfunction(self, subfunction):        
        if subfunction in [0x01, 0x02]:
            return os.urandom(8)
        elif subfunction in [0x03, 0x04]:
            return os.urandom(16)
        elif subfunction in [0x05, 0x06]:
            return os.urandom(64)
            

    def _load_verification_pubkey(self):
        try:
            with open(PUBKEY_STORE_FILE, "rb") as f:
                return RSA.import_key(f.read())
        except Exception:
            return None
            
    def _save_verification_pubkey(self,raw_bytes):
        with open(PUBKEY_STORE_FILE, "wb") as f:
            f.write(raw_bytes)

    def send_positive_session_response(self, session_type):
        return bytes([0x50, session_type, 0x01, 0xF4, 0x03, 0xE8])
    
    def handle_security_access_old(self, request):
        subfunction = request[1]
        if subfunction in [0x01, 0x03, 0x05]:
            self.seed = self.get_seed_based_on_subfunction(subfunction)
            return bytes([0x67, subfunction]) + self.seed

        elif subfunction in [0x02, 0x04, 0x06]:
            if not self.seed:
                # If seed is not yet generated, return an error response
                return bytes([0x7F, services.SecurityAccess._sid, 0x12])

            received_key = int.from_bytes(request[2:], 'big')
            seed_as_integer = int.from_bytes(self.seed, 'big')
            expected_key = seed_as_integer + 1

            if received_key == expected_key:
                print(f"Update Security Level to:{subfunction // 2}")
                self.security_level = subfunction // 2
                return bytes([0x67, subfunction])
            else:
                return bytes([0x7F, services.SecurityAccess._sid, 0x33])

        else:
            return bytes([0x7F, services.SecurityAccess._sid, 0x12])
            
            
    def handle_security_access_xor(self, request):
        subfunction = request[1]
        FIXED_SEED = bytes(range(0x10))
        XOR_CONST = 0x35

        if subfunction in [0x01, 0x03, 0x05]:
            self.seed = FIXED_SEED
            return bytes([0x67, subfunction]) + self.seed
        elif subfunction in [0x02, 0x04, 0x06]:
            if not self.seed:
                return bytes([0x7F, services.SecurityAccess._sid, 0x12])
            received_key = bytes(request[2:])
            expected_key = bytes(b ^ XOR_CONST for b in self.seed)
            if received_key == expected_key:
                self.security_level = subfunction // 2
                print(f"Update Security Level to:{self.security_level} (fixed-seed XOR)")
                return bytes([0x67, subfunction])  # positive response (no extra data)
            else:
                return bytes([0x7F, services.SecurityAccess._sid, 0x33])
        else:
            return bytes([0x7F, services.SecurityAccess._sid, 0x12])

    def handle_security_access_weakaes(self, request):
        """
        Server-side: fixed 16-byte seed and expects AES-ECB(key, seed) as response.
        Mirrors the client's weak AES logic.
        """
        subfunction = request[1]
        FIXED_SEED = bytes(range(0x10))    # 00 01 02 ... 0F
        AES_KEY = bytes.fromhex("12341234123412341234123412341234")  # same example key

        
        if subfunction in (0x01, 0x03, 0x05):
            self.seed = FIXED_SEED
            return bytes([0x67, subfunction]) + self.seed
        elif subfunction in (0x02, 0x04, 0x06):
            if not self.seed:
                return bytes([0x7F, services.SecurityAccess._sid, 0x12])  # request sequence error

            received_key = bytes(request[2:])
            if len(self.seed) != 16:
                return bytes([0x7F, services.SecurityAccess._sid, 0x12])
            cipher = AES.new(AES_KEY, AES.MODE_ECB)
            expected_key = cipher.encrypt(self.seed)
            if received_key == expected_key:
                self.security_level = subfunction // 2
                print(f"Update Security Level to:{self.security_level} (weak-AES)")
                return bytes([0x67, subfunction])  # positive response
            else:
                return bytes([0x7F, services.SecurityAccess._sid, 0x33])  # invalid key
        else:
            return bytes([0x7F, services.SecurityAccess._sid, 0x12])  # subfunction not supported
        
             
        
    def handle_security_access_rsa(self, request):
        """
        Simplified SecurityAccess handler with RSA-PSS verification.
        Only handles seed request, key verification, and pubkey provisioning.
        """

        subfunction = request[1]

        # Ensure lock if multithreaded
        if not hasattr(self, "_uds_rsa_lock"):
            self._uds_rsa_lock = threading.Lock()

        with self._uds_rsa_lock:
            # Load stored public key if not already loaded
            if not hasattr(self, "_rsa_pubkey"):
                self._rsa_pubkey = self._load_verification_pubkey()
                if self._rsa_pubkey:
                    print("[SERVER DEBUG] RSA public key loaded for verification.")
                else:
                    print("[SERVER DEBUG] No RSA public key found; verification will fail.")

            # Handle pubkey provisioning (lab only)
            if subfunction == 0x0A:
                pubkey_bytes = bytes(request[2:])
                try:
                    pk = RSA.import_key(pubkey_bytes)
                    self._rsa_pubkey = pk
                    self._save_verification_pubkey(pubkey_bytes)
                    print("[SERVER DEBUG] New RSA pubkey provisioned and saved.")
                    return bytes([0x67, subfunction])
                except Exception as e:
                    print(f"[SERVER DEBUG] Failed to import provided pubkey: {e}")
                    return bytes([0x7F, services.SecurityAccess._sid, 0x12])  # format error

            # Seed request
            if subfunction in (0x01, 0x03, 0x05):
                self._rsa_seed = os.urandom(SEED_LEN)
                print(f"[SERVER DEBUG] Generated new RSA seed ({SEED_LEN} bytes).")
                return bytes([0x67, subfunction]) + self._rsa_seed

            # Key submission
            elif subfunction in (0x02, 0x04, 0x06):
                if not hasattr(self, "_rsa_seed") or self._rsa_seed is None:
                    print("[SERVER DEBUG] No seed available for verification.")
                    return bytes([0x7F, services.SecurityAccess._sid, 0x12])

                if not self._rsa_pubkey:
                    print("[SERVER DEBUG] No public key available; cannot verify.")
                    return bytes([0x7F, services.SecurityAccess._sid, 0x12])

                received_sig = bytes(request[2:])
                h = SHA256.new(self._rsa_seed)
                verifier = pss.new(self._rsa_pubkey)
                try:
                    verifier.verify(h, received_sig)
                    self.security_level = subfunction // 2
                    print(f"[SERVER DEBUG] RSA-PSS verified. Security level set to {self.security_level}")
                    self._rsa_seed = None
                    return bytes([0x67, subfunction])
                except (ValueError, TypeError):
                    print("[SERVER DEBUG] RSA-PSS verification FAILED.")
                    return bytes([0x7F, services.SecurityAccess._sid, 0x35])  # invalid key

            # Unsupported subfunction
            else:
                return bytes([0x7F, services.SecurityAccess._sid, 0x12])
    
      



      
    def handle_session_change(self, request):
        session_type = request[1]
        supported_sessions = [
            services.DiagnosticSessionControl.Session.defaultSession,
            services.DiagnosticSessionControl.Session.extendedDiagnosticSession,
            services.DiagnosticSessionControl.Session.programmingSession,
            services.DiagnosticSessionControl.Session.safetySystemDiagnosticSession
        ]

        if session_type in supported_sessions:
            self.current_session = session_type
            print(f"Update Diagnostic Session to:{session_type}")
            return self.send_positive_session_response(session_type)
        else:
            return bytes([0x7F, services.DiagnosticSessionControl._sid, 0x11])

    def handle_input_output_control(self, request):
        did_bytes = request[1:3]
        control_param = request[3]
        control_data = request[4:]

        if did_bytes in self.data_store:
            if control_param == udsoncan.services.InputOutputControlByIdentifier.ControlParam.returnControlToECU:
                #control = carla.VehicleControl(throttle=0.0)
                #self.carla_vehicle.apply_control(control)
                pass
            elif control_param == udsoncan.services.InputOutputControlByIdentifier.ControlParam.resetToDefault:
                #control = carla.VehicleControl(throttle=0.0)
                #self.carla_vehicle.apply_control(control)
                pass
            elif control_param == udsoncan.services.InputOutputControlByIdentifier.ControlParam.freezeCurrentState:
                pass
            elif control_param == udsoncan.services.InputOutputControlByIdentifier.ControlParam.shortTermAdjustment:
                #throttle_value = float(control_data)
                #control = carla.VehicleControl(throttle=throttle_value)
                #self.carla_vehicle.apply_control(control)
                pass
            else:
                # If the control parameter is not supported, return a negative response
                return bytes([0x7F, services.InputOutputControlByIdentifier._sid, 0x31])
            return bytes([services.InputOutputControlByIdentifier._sid + 0x40]) + request[1:4]
        else:
            return bytes([0x7F, services.InputOutputControlByIdentifier._sid, 0x31])

    def handle_routine_control(self, request, control, vehicle, vehicledoor,scenario):
    #def handle_routine_control(self, request):
        '''
        ALLOWED_SESSIONS_FOR_WRITE = [
            services.DiagnosticSessionControl.Session.extendedDiagnosticSession,
            services.DiagnosticSessionControl.Session.programmingSession
        ]
        if self.current_session not in ALLOWED_SESSIONS_FOR_WRITE:
            print(f"[INFO]Diagnostic session NOTPASS")
            return bytes([0x7F, services.WriteDataByIdentifier._sid, 0x7E])
        else:
            print(f"[INFO]Diagnostic session PASS")
        '''
                
        control_type = request[1]
        routine_id = int.from_bytes(request[2:4], 'big')

        if routine_id == 0x01A9:  # Routine Identifiers for diagnostic Throttle
            attack_out_of_range = scenario.attack_out_of_range
            if attack_out_of_range:
                if self.controlling_vehicle:
                    self.controlling_vehicle = False
                    self.stop_vehicle_control = True
                    self.thread_throttle.join()
                    print("DIAGNOSTIC ROUTINE STOPPED: Attacker out of range")
                return bytes([services.RoutineControl._sid + 0x40, services.RoutineControl.ControlType.stopRoutine]) + request[2:4]
            
            if control_type == services.RoutineControl.ControlType.startRoutine:
                data = request[4:5]
                if not data:
                    return bytes([0x7F, services.RoutineControl._sid, 0x13])  # Incorrect message length or invalid format
                throttle_int_value = int.from_bytes(data, 'big')
                if throttle_int_value < 0 or throttle_int_value > 100:
                    return bytes([0x7F, services.RoutineControl._sid, 0x31])  # Request out of range
                throttle_value = throttle_int_value / 100 # Convert the integer throttle value to the float range [0.0, 1.0]                
                self.attack_tracker.update_path("Throttle")  
                self.attack_tracker.print_path()                
                print(f"Send diagnostic with throttle value {throttle_value}")
                if self.thread_throttle is not None and self.thread_throttle.is_alive(): # If previous thread still alive then set the flag to false then stop it
                    self.controlling_vehicle = False
                    self.thread_throttle.join()
                if not self.controlling_vehicle: # Create a new thread
                    self.controlling_vehicle = True
                    self.thread_throttle = threading.Thread(target=self.control_vehicle_throttle, args=(control, vehicle, throttle_value))
                    self.thread_throttle.start()
                return bytes([services.RoutineControl._sid + 0x40, control_type]) + request[2:4] #Return the server response

            elif control_type == services.RoutineControl.ControlType.stopRoutine: # If the vehicle is currently being controlled, set the flag to stop it
                if self.controlling_vehicle:
                    self.controlling_vehicle = False
                    self.stop_vehicle_control = True
                    self.thread_throttle.join()
                    print("FINISH DIAGNOSTIC THROTTLE ROUTINE")
                return bytes([services.RoutineControl._sid + 0x40, control_type]) + request[2:4]

        if routine_id == 0x04F1:  # Routine Identifiers for diagnostic Steer
            if control_type == services.RoutineControl.ControlType.startRoutine:
                data = request[4:5]
                if not data:
                    return bytes([0x7F, services.RoutineControl._sid, 0x13])  # Incorrect message length or invalid format
                steering_int_value = int.from_bytes(data, 'big', signed=True) # Validate and use the data as needed
                if steering_int_value < -100 or steering_int_value > 100:
                    return bytes([0x7F, services.RoutineControl._sid, 0x31])  # Request out of range
                steering_value = steering_int_value / 100 # Convert the integer throttle value to the float range [0.0, 1.0]
                self.attack_tracker.update_path("Steering")  
                self.attack_tracker.print_path()  
                print(f"Send diagnostic with steering value {steering_value}")
                if self.thread_steer is not None and self.thread_steer.is_alive(): # If previous thread still alive then set the flag to false then stop it
                    self.controlling_vehicle = False
                    self.thread_steer.join()
                if not self.controlling_vehicle: # Create a new thread
                    self.controlling_vehicle = True
                    self.thread_steer = threading.Thread(target=self.control_vehicle_steering, args=(control, vehicle, steering_value))
                    self.thread_steer.start()
                return bytes([services.RoutineControl._sid + 0x40, control_type]) + request[2:4] #Return the server response

            elif control_type == services.RoutineControl.ControlType.stopRoutine: # If the vehicle is currently being controlled, set the flag to stop it
                if self.controlling_vehicle:
                    self.controlling_vehicle = False
                    self.stop_vehicle_control = True
                    self.thread_steer.join()
                    print("FINISH DIAGNOSTIC STEER ROUTINE")
                return bytes([services.RoutineControl._sid + 0x40, control_type]) + request[2:4]


        if routine_id == 0x0205:  # Routine Identifiers for diagnostic Brake
            if control_type == services.RoutineControl.ControlType.startRoutine:
                data = request[4:5]
                if not data:
                    return bytes([0x7F, services.RoutineControl._sid, 0x13])  # Incorrect message length or invalid format
                brake_int_value = int.from_bytes(data, 'big') # Validate and use the data as needed
                if brake_int_value < 0 or brake_int_value > 100:
                    return bytes([0x7F, services.RoutineControl._sid, 0x31])  # Request out of range
                brake_value = brake_int_value / 100 # Convert the integer throttle value to the float range [0.0, 1.0]
                self.attack_tracker.update_path("Brake")  
                self.attack_tracker.print_path()  
                print(f"Send diagnostic with breaking value {brake_value}")
                if self.thread_brake is not None and self.thread_brake.is_alive(): # If previous thread still alive then set the flag to false then stop it
                    self.controlling_vehicle = False
                    self.thread_brake.join()
                if not self.controlling_vehicle: # Create a new thread
                    self.controlling_vehicle = True
                    self.thread_brake = threading.Thread(target=self.control_vehicle_brake, args=(control, vehicle, brake_value))
                    self.thread_brake.start()
                return bytes([services.RoutineControl._sid + 0x40, control_type]) + request[2:4] #Return the server response

            elif control_type == services.RoutineControl.ControlType.stopRoutine: # If the vehicle is currently being controlled, set the flag to stop it
                if self.controlling_vehicle:
                    self.controlling_vehicle = False
                    self.stop_vehicle_control = True
                    self.thread_brake.join()
                    print("FINISH DIAGNOSTIC STEER ROUTINE")
                return bytes([services.RoutineControl._sid + 0x40, control_type]) + request[2:4]


        if routine_id == 0x04F5:  # Routine Identifiers for diagnostic Gear
            if control_type == services.RoutineControl.ControlType.startRoutine:
                data = request[4:5]
                if not data:
                    return bytes([0x7F, services.RoutineControl._sid, 0x13])  # Incorrect message length or invalid format
                gear_int_value = int.from_bytes(data, 'big', signed=True) # Validate and use the data as needed
                if gear_int_value < -1 or gear_int_value > 127:
                    return bytes([0x7F, services.RoutineControl._sid, 0x31])  # Request out of range
                #gear_value = gear_int_value / 100 # Convert the integer throttle value to the float range [0.0, 1.0]
                self.attack_tracker.update_path("Gear")  
                self.attack_tracker.print_path()  
                print(f"Send diagnostic with gear value {gear_int_value}")
                if self.thread_gear is not None and self.thread_gear.is_alive(): # If previous thread still alive then set the flag to false then stop it
                    self.controlling_vehicle = False
                    self.thread_gear.join()
                if not self.controlling_vehicle: # Create a new thread
                    self.controlling_vehicle = True
                    self.thread_gear = threading.Thread(target=self.control_vehicle_gear, args=(control, vehicle, gear_int_value))
                    self.thread_gear.start()
                return bytes([services.RoutineControl._sid + 0x40, control_type]) + request[2:4] #Return the server response

            elif control_type == services.RoutineControl.ControlType.stopRoutine: # If the vehicle is currently being controlled, set the flag to stop it
                if self.controlling_vehicle:
                    self.controlling_vehicle = False
                    self.stop_vehicle_control = True
                    self.thread_gear.join()
                    print("FINISH DIAGNOSTIC STEER ROUTINE")
                return bytes([services.RoutineControl._sid + 0x40, control_type]) + request[2:4]


        if routine_id == 0x0203:  # Control Door
            #print (f"Door count_uds side: {self.door_count}")
            if control_type == services.RoutineControl.ControlType.startRoutine:
                data = request[4:5]
                if not data:
                    return bytes([0x7F, services.RoutineControl._sid, 0x13])  # Incorrect message length or invalid format
                # Validate and use the data as needed
                door_int_value = int.from_bytes(data, 'big')
                if door_int_value != 0 and door_int_value != 100:
                    return bytes([0x7F, services.RoutineControl._sid, 0x31])  # Request out of range
                # Convert the integer throttle value to the float range [0.0, 1.0]
                door_value = door_int_value / 100
                
                self.attack_tracker.update_path("Door")  
                self.attack_tracker.print_path()  
                print(f"Send diagnostic with door value {door_value}")
                
                if not self.controlling_vehicle:
                    self.controlling_vehicle = True
                    if door_value == 1:
                        vehicle.open_door(vehicledoor.All)
                        #print (f"How about this value {vehicle.open_door(vehicledoor.All)}")
                        if self.tmp_door == False:
                            self.door_count += 1
                            self.door_open = True
                            self.tmp_door = True
                    else:
                        vehicle.close_door(vehicledoor.All)
                    #self.control_thread = threading.Thread(target=self.control_vehicle_door, args=(vehicledoor, vehicle, door_value))
                    #self.control_thread.start()
                    #print(f"This is start {self.control_thread}")
                    #self.control_thread.join()
                    #print(f"This is end {self.control_thread}")
                return bytes([services.RoutineControl._sid + 0x40, control_type]) + request[2:4]

            elif control_type == services.RoutineControl.ControlType.stopRoutine:
                # If the vehicle is currently being controlled, set the flag to stop it
                if self.controlling_vehicle:
                    vehicle.close_door(vehicledoor.All)
                    if self.tmp_door == True:
                        self.door_close = False
                        self.tmp_door = False
                    self.controlling_vehicle = False
                    self.stop_vehicle_control = True
                    print("VEL TEST ____ STOP CONTROL")
                return bytes([services.RoutineControl._sid + 0x40, control_type]) + request[2:4]
        else:
            return bytes([0x7F, services.RoutineControl._sid, 0x11])

    def control_vehicle_throttle(self, control, vehicle, throttle_value):
        while self.controlling_vehicle:
            control.throttle = throttle_value
            vehicle.apply_control(control)
        self.controlling_vehicle = False
        self.stop_vehicle_control = False
        control.throttle = 0
        vehicle.apply_control(control)

    def control_vehicle_steering(self, control, vehicle, steering_value):
        while self.controlling_vehicle:
            control.steer = steering_value
            vehicle.apply_control(control)
        self.controlling_vehicle = False
        self.stop_vehicle_control = False
        control.steer = 0
        vehicle.apply_control(control)

    def control_vehicle_brake(self, control, vehicle, brake_value):
        while self.controlling_vehicle:
            control.brake = brake_value
            vehicle.apply_control(control)
        self.controlling_vehicle = False
        self.stop_vehicle_control = False
        control.brake = 0
        vehicle.apply_control(control)

    def control_vehicle_gear(self, control, vehicle, gear_value):
        while self.controlling_vehicle:
            control.manual_gear_shift  = True
            control.gear = gear_value
            vehicle.apply_control(control)
        self.controlling_vehicle = False
        self.stop_vehicle_control = False
        control.gear = 0
        vehicle.apply_control(control)

    def control_vehicle_door(self, vehicledoor, vehicle, door_value):
        while self.controlling_vehicle:
            if door_value == 1:
                vehicle.open_door(vehicledoor.All)
            else:
                vehicle.close_door(vehicledoor.All)
        vehicle.close_door(vehicledoor.All)
        self.controlling_vehicle = False
        self.stop_vehicle_control = False
        print("close")


    def handle_write_data_by_identifier(self, request):
        '''
        if self.security_level < 2:
            print(f"[INFOR]Security Level NOTPASS")
            return bytes([0x7F, services.WriteDataByIdentifier._sid, 0x33])
        else:
            print(f"[INFO]Security Level PASS")
        ALLOWED_SESSIONS_FOR_WRITE = [
            services.DiagnosticSessionControl.Session.extendedDiagnosticSession,
            services.DiagnosticSessionControl.Session.programmingSession
        ]
        if self.current_session not in ALLOWED_SESSIONS_FOR_WRITE:
            print(f"[INFO]Diagnostic session NOTPASS")
            return bytes([0x7F, services.WriteDataByIdentifier._sid, 0x7E])
        else:
            print(f"[INFO]Diagnostic session PASS")
        '''
        #did_int = int.from_bytes(request[1:3], 'big')
        did_bytes = request[1:3]
        if did_bytes in self.data_store:
            self.data_store[did_bytes] = request[3:]
            print(f"Update the {request[1:3]} to {request[3:]}")
            self.save_data_store()
            #did_bytes = did_int.to_bytes(2, 'big')
            return bytes([services.WriteDataByIdentifier._sid +0x40]) + did_bytes
        else:
            return bytes([0x7F, services.WriteDataByIdentifier._sid, 0x31])



    def handle_read_data_by_identifier(self, request):
        did_bytes = request[1:3]
        if did_bytes in self.data_store:
            data = self.data_store[did_bytes]
            return bytes([services.ReadDataByIdentifier._sid + 0x40]) + request[1:3] + data
        else:
            print(f"Sending negative response")
            return bytes([0x7F, services.ReadDataByIdentifier._sid, 0x31])


    
def main():
    uds_server = UDSServer()
    s = isotp.socket()
    s.set_fc_opts(stmin=5, bs=10)
    s.bind("vcan0", isotp.Address(rxid=0x7E0, txid=0x7E8))
    print("Start Listening")

    while True:
        request = s.recv()
        if not request:
            continue

        if request[0] == services.DiagnosticSessionControl._sid:
            response = uds_server.handle_session_change(request)
            s.send(response)
        elif request[0] == services.SecurityAccess._sid:
            response = uds_server.handle_security_access_weakaes(request)
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
            response = uds_server.handle_routine_control(request)
            s.send(response)
        else:
            response = bytes([0x7F, request[0], 0x11]) #return not support
            s.send(response)

if __name__ == '__main__':
    main()
