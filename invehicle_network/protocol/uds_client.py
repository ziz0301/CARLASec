#uds_client.py

import udsoncan
import isotp
import time
from udsoncan.connections import IsoTPSocketConnection
from udsoncan.client import Client
from udsoncan.exceptions import *
from udsoncan.services import *
from udsoncan import DidCodec
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Hash import SHA256
import os
from typing import Optional



class UDSTester:
    def __init__(self, connection):
        udsoncan.setup_logging()
        self.client_config = {
            'security_algo': self.security_algorithm_rsa,
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
        self.found_key = None
        self._rsa_privkey = None

    @staticmethod
    def security_algorithm_old(seed: bytes) -> bytes:
        seed_value = int.from_bytes(seed, 'big')
        key_value = seed_value + 1
        return key_value.to_bytes(len(seed), 'big')
        
    @staticmethod
    def security_algorithm_xor(seed: bytes) -> bytes:
        """
        Compute key = seed XOR 0x35 for each byte.
        udsoncan will call this automatically when unlocking.
        """
        if not isinstance(seed, (bytes, bytearray)):
            raise TypeError("seed must be bytes")
        return bytes(b ^ 0x35 for b in seed)
        
    @staticmethod
    def security_algorithm_weakaes(seed: bytes) -> bytes:
        """
        Compute key = AES-128-ECB(WEAK_AES_KEY, seed).
        Seed must be 16 bytes (no padding).
        """
        WEAK_AES_KEY = bytes.fromhex("12341234123412341234123412341234")  # example key (attacker knows it)
        if not isinstance(seed, (bytes, bytearray)):
            raise TypeError("seed must be bytes")
        if len(seed) != 16:
            raise ValueError("seed must be 16 bytes for this simple scheme")
        cipher = AES.new(WEAK_AES_KEY, AES.MODE_ECB)
        return cipher.encrypt(seed)   # 16-byte ciphertext
    
    
    
        
    # Helper: load RSA private key from PEM file (optionally encrypted)
    def load_rsa_private_key_from_file(self, pem_path: str, passphrase: Optional[str] = None):
        """
        Load RSA private key from PEM file into self._rsa_privkey.
        passphrase may be None for unencrypted PEMs, or a string for encrypted PEMs.
        """
        with open(pem_path, "rb") as f:
            raw = f.read()
        try:
            self._rsa_privkey = RSA.import_key(raw, passphrase=passphrase)
        except Exception as e:
            raise RuntimeError(f"Failed to import RSA private key: {e}")
    # (Optional) convenience to load private key from raw bytes (for tests)
    def load_rsa_private_key_from_bytes(self, pem_bytes: bytes, passphrase: Optional[str] = None):
        try:
            self._rsa_privkey = RSA.import_key(pem_bytes, passphrase=passphrase)
        except Exception as e:
            raise RuntimeError(f"Failed to import RSA private key from bytes: {e}")
            
            
    # The callable that udsoncan will call (bound method). It MUST accept 'seed' as keyword arg.
    def security_algorithm_rsa(self, seed: bytes) -> bytes:
        """
        Sign the provided seed with RSA-PSS (SHA-256) and return signature bytes.

        udsoncan will call this with keyword: security_algo(seed=bytes(...))
        """
        if seed is None or not isinstance(seed, (bytes, bytearray)):
            raise RuntimeError("security_algorithm_rsa expects a 'seed' bytes argument")

        if self._rsa_privkey is None:
            raise RuntimeError("No RSA private key loaded (set self._rsa_privkey with load_rsa_private_key_from_file)")

        # Optional sanity: check seed length (server expects SEED_LEN, e.g., 32)
        # if len(seed) != 32:
        #     raise RuntimeError(f"Unexpected seed length: {len(seed)}")

        # Create SHA-256 hash of seed and sign with RSA-PSS
        h = SHA256.new(seed)
        signer = pss.new(self._rsa_privkey)

        try:
            signature = signer.sign(h)
        except (ValueError, TypeError) as e:
            raise RuntimeError(f"RSA-PSS signing failed: {e}")

        # signature length == key_size_in_bytes (e.g., 384 for 3072-bit key)
        return signature
    
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
        #time.sleep(2)
        #response_01A1 = client.routine_control(routine_id_01A1, control_type_stop, datacontrol_01A1)

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
        
# Add these imports near top of file if not present
import time
import statistics
from typing import Callable, List

# ---- small helpers ----

def measure_compute_time_ms(seed: bytes, alg: Callable[[bytes], bytes], repeats: int = 5) -> float:
    """
    Measure pure local computation time for alg(seed) in milliseconds.
    Returns median ms over `repeats` runs (default 5).
    """
    if not isinstance(seed, (bytes, bytearray)):
        raise TypeError("seed must be bytes")
    if repeats < 1:
        repeats = 1
    samples: List[float] = []
    for _ in range(repeats):
        t0 = time.perf_counter_ns()
        _ = alg(seed)
        t1 = time.perf_counter_ns()
        samples.append((t1 - t0) / 1_000_000.0)
    return statistics.median(samples)


def measure_unlock_roundtrip_ms(client, security_level: int, repeats: int = 10) -> dict:
    """
    Measure full client.unlock_security_access(...) round-trip time (ms).
    Returns dict with median, mean and all samples.
    NOTE: this measures the whole udsoncan call (network + compute + server verify).
    """
    if repeats < 1:
        repeats = 1
    samples: List[float] = []
    for i in range(repeats):
        t0 = time.perf_counter_ns()
        # call the udsoncan convenience method (this blocks until done or times out)
        client.unlock_security_access(security_level)
        t1 = time.perf_counter_ns()
        samples.append((t1 - t0) / 1_000_000.0)
        # tiny pause to avoid hammering the server too fast
        time.sleep(0.05)
    return {
        "samples_ms": samples,
        "median_ms": statistics.median(samples),
        "mean_ms": statistics.mean(samples),
        "min_ms": min(samples),
        "max_ms": max(samples)
    }

def main():       
    with IsoTPSocketConnection(interface='vcan0', rxid=0x7E8, txid=0x7E0, tpsock=isotp.socket()) as connection:
        connection.open()
        uds_tester = UDSTester(connection)
        uds_tester.load_rsa_private_key_from_file("tester_key.pem", passphrase=None)    
        with Client(connection, request_timeout=10, config=uds_tester.client_config) as client:
            try:
                uds_tester.unlock_security_access(client)  
                #uds_tester.test_routine_control1(client)

                # 1) measure pure computation time for XOR using server-provided seed length sample
                #seed_example = bytes(range(0x10))  # same as server FIXED_SEED used in your XOR handler
                #comp_ms = measure_compute_time_ms(seed_example, uds_tester.security_algorithm_xor, repeats=10)
                #print(f"Local compute time (XOR) median: {comp_ms:.3f} ms")

                # 2) measure full unlock round-trip (this actually performs unlocking on ECU)
                rt = measure_unlock_roundtrip_ms(client, uds_tester.client_config['security_level'], repeats=6)
                print(f"Unlock roundtrip samples (ms): {rt['samples_ms']}")
                print(f"Unlock roundtrip median: {rt['median_ms']:.3f} ms, mean: {rt['mean_ms']:.3f} ms")

            except NegativeResponseException as e:
                print(f'Server refused our request for service {e.response.service.get_name()} with code "{e.response.code_name}" (0x{e.response.code:02x})')
            except InvalidResponseException as e:
                print(f'Server sent an invalid payload: {e.response.original_payload}')
            except UnexpectedResponseException as e:
                print(f'Unexpected response from server: {e.response.original_payload}')

if __name__ == "__main__":
 main()
                #uds_tester.change_diagnostic_session(client)
                #uds_tester.write_vin(client)
                #uds_tester.read_vin(client)
                #uds_tester.reset_ecu(client)
                #uds_tester.test_input_output_control(client)
                #uds_tester.test_routine_control3(client)