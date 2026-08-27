#uds_client.py

import udsoncan
import isotp
import time
from udsoncan.connections import IsoTPSocketConnection
from udsoncan.client import Client
from udsoncan.exceptions import *
from udsoncan.services import *
from udsoncan import DidCodec

class UDSTester:
    def __init__(self, connection):
        udsoncan.setup_logging()
        self.client_config = {
            'security_algo': self.security_algorithm,
            'exception_on_negative_response': False,
            'exception_on_invalid_response': True,
            'data_identifiers': {0xF190: self.VINCodec()},
            'security_level': 3,
            'input_output': {
                0xF192: {
                    'codec': self.VINCodec(),
                    'mask': {
                        'maskName1': 0x0F,
                        'maskName2': 0xF0,
                    },
                    'mask_size': 1
                }
            }
        }
        self.connection = connection

    @staticmethod
    def security_algorithm(seed: bytes) -> bytes:
        seed_value = int.from_bytes(seed, 'big')
        key_value = seed_value + 1
        return key_value.to_bytes(len(seed), 'big')

    class VINCodec(DidCodec):
        def encode(self, did_value):
            return (did_value + ' ' * 17)[:17].encode('ascii')

        def decode(self, did_payload):
            return did_payload.decode('ascii').strip()

        def __len__(self):
            return 17

    def unlock_security_access(self, client):
        client.unlock_security_access(self.client_config['security_level'])

    def change_diagnostic_session(self, client):
        client.change_session(DiagnosticSessionControl.Session.extendedDiagnosticSession)

    def write_vin(self, client):
        client.write_data_by_identifier(udsoncan.DataIdentifier.VIN, '2T3RFREV7DW108177')
        #client.write_data_by_identifier(udsoncan.DataIdentifier.VIN, '2T3RFREV7DW108988')

    def read_vin(self, client):
        vin = client.read_data_by_identifier(0xF190)
        print(f'Vehicle Identification Number: {vin}')

    def reset_ecu(self, client):
        client.ecu_reset(ECUReset.ResetType.hardReset)

    def test_input_output_control(self, client):
        io_control_did = 0xF192
        control_param = udsoncan.services.InputOutputControlByIdentifier.ControlParam.resetToDefault
        response = client.io_control(io_control_did, control_param)

    def test_routine_control1(self, client):
        routine_id_01A1 = 0x01A9
        control_type_start = udsoncan.services.RoutineControl.ControlType.startRoutine
        control_type_stop = udsoncan.services.RoutineControl.ControlType.stopRoutine
        datacontrol_01A1 = b'\x64'
        response_01A1 = client.routine_control(routine_id_01A1, control_type_start, datacontrol_01A1)
        time.sleep(2)
        response_01A1 = client.routine_control(routine_id_01A1, control_type_stop, datacontrol_01A1)

        #response_01A1 = client.routine_control(routine_id_01A1, control_type_stop)


    def test_routine_control2(self, client):
        routine_id_04F1 = 0x04F1
        control_type_start = udsoncan.services.RoutineControl.ControlType.startRoutine
        control_type_stop = udsoncan.services.RoutineControl.ControlType.stopRoutine
        datacontrol_04F1= b'\x5F'
        response_04F1 = client.routine_control(routine_id_04F1, control_type_start, datacontrol_04F1)
        time.sleep(2)
        response_04F1 = client.routine_control(routine_id_04F1, control_type_stop, datacontrol_04F1)

    def test_routine_control3(self, client):
        routine_id_0203= 0x0203
        control_type_start = udsoncan.services.RoutineControl.ControlType.startRoutine
        control_type_stop = udsoncan.services.RoutineControl.ControlType.stopRoutine
        datacontrol_0203= b'\x64'
        response_0203 = client.routine_control(routine_id_0203, control_type_start, datacontrol_0203)
        time.sleep(2)
        response_0203 = client.routine_control(routine_id_0203, control_type_stop, datacontrol_0203)

def main():
    with IsoTPSocketConnection(interface='vcan0', rxid=0x7E8, txid=0x7E0, tpsock=isotp.socket()) as connection:
        connection.open()
        uds_tester = UDSTester(connection)
        with Client(connection, request_timeout=10, config=uds_tester.client_config) as client:
            try:
                uds_tester.unlock_security_access(client)
                #uds_tester.change_diagnostic_session(client)
                #uds_tester.write_vin(client)
                #uds_tester.read_vin(client)
                #uds_tester.reset_ecu(client)
                #uds_tester.test_input_output_control(client)
                #uds_tester.test_routine_control3(client)
            except NegativeResponseException as e:
                print(f'Server refused our request for service {e.response.service.get_name()} with code "{e.response.code_name}" (0x{e.response.code:02x})')
            except InvalidResponseException as e:
                print(f'Server sent an invalid payload: {e.response.original_payload}')
            except UnexpectedResponseException as e:
                print(f'Unexpected response from server: {e.response.original_payload}')

if __name__ == "__main__":
 main()
