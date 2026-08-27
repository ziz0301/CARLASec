import udsoncan
import isotp
import os
import threading
from udsoncan import services
import pickle

class UDSServer:
    def __init__(self):
        self.seed = None  # Initialize seed as None
        self.security_level = 0  # Initially no security access
        self.current_session = services.DiagnosticSessionControl.Session.defaultSession  # Default session on startup
        self.data_store = self.load_data_store()
        self.controlling_vehicle = False  # Flag to indicate if vehicle is being controlled
        self.stop_vehicle_control = False  # Flag to signal stopping vehicle control
        print(f"Current Security Level:{self.security_level}")
        print(f"Current Session:{self.current_session}")

    def load_data_store(self):
        if os.path.exists("data_store.pkl"):
            with open("data_store.pkl", "rb") as file:
                data = pickle.load(file)
                print(f"Current data from file: {data}")
                return data
        else:
            return {}

    def save_data_store(self):
        with open("data_store.pkl", "wb") as f:
            pickle.dump(self.data_store, f)

    def get_seed_based_on_subfunction(self, subfunction):
        seed = bytes([0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F])
        return seed
        if subfunction in [0x01, 0x02]:
            return os.urandom(8)
        elif subfunction in [0x03, 0x04]:
            return os.urandom(16)
        elif subfunction in [0x05, 0x06]:
            return os.urandom(64)

    def send_positive_session_response(self, session_type):
        return bytes([0x50, session_type, 0x01, 0xF4, 0x03, 0xE8])

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

    def handle_routine_control(self, request):
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

        if routine_id == 0x01A9:  # Control Stop for example
            if control_type == services.RoutineControl.ControlType.startRoutine:
                data = request[4:]
                if not data:
                    return bytes([0x7F, services.RoutineControl._sid, 0x13])  # Incorrect message length or invalid format

                # Validate and use the data as needed
                throttle_int_value = int.from_bytes(data, 'big')
                if throttle_int_value < 0 or throttle_int_value > 100:
                    return bytes([0x7F, services.RoutineControl._sid, 0x31])  # Request out of range
                # Convert the integer throttle value to the float range [0.0, 1.0]
                throttle_value = throttle_int_value / 100
                if not self.controlling_vehicle:
                    self.controlling_vehicle = True
                    print (f"Successfull control vehicle with throttle value: {throttle_value}")
                    #control_thread = threading.Thread(target=self.control_vehicle_throttle, args=(control, vehicle, throttle_value))
                    #control_thread.start()
                return bytes([services.RoutineControl._sid + 0x40, control_type]) + request[2:4]

            elif control_type == services.RoutineControl.ControlType.stopRoutine:
                # If the vehicle is currently being controlled, set the flag to stop it
                if self.controlling_vehicle:
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


    def handle_security_access(self, request):
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

def main():
    uds_server = UDSServer()
    s = isotp.socket()
    s.set_fc_opts(stmin=0xF1, bs=10)
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
            response = uds_server.handle_security_access(request)
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
