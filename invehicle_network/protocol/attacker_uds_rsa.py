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


class UDSTester:
    def __init__(self, connection):
        udsoncan.setup_logging()
        self.client_config = {
            'security_algo': self.security_algorithm_bruteforce_rsa,
            'exception_on_negative_response': False,
            'exception_on_invalid_response': True,
            'security_level': 3
        }
        self.connection = connection
        self.found_key = None
        self._rsa_privkey = None
    def unlock_security_access(self, client):
        client.unlock_security_access(self.client_config['security_level'])    
    def security_algorithm_bruteforce_rsa(self,
                                          seed: bytes,
                                          candidate_len: Optional[int] = None,
                                          max_seconds: float = 10.0,
                                          max_attempts: Optional[int] = None,
                                          mode: str = "random") -> bytes:
        """
        Simulate an attacker attempting many candidate signatures by random guessing.

        - seed: the seed bytes provided by the server (kept only for API compatibility).
        - candidate_len: number of bytes per candidate signature. If None, use
          key_size_in_bytes stored on the client (if available) or default to 256 bytes.
        - max_seconds: run time budget for the generator (wall clock). Use a small value
          for demos (e.g., 10). For demonstration of infeasibility, keep it short.
        - max_attempts: optional hard cap on attempts (stops early if reached).
        - mode: "random" (default) — produce cryptographically-random candidates;
                "zeros" — produce a sequence of zero-filled signatures (fast, deterministic);
                "increment" — produce incrementing integer-like byte sequences (useful to show counts).
        Returns the last candidate signature bytes generated (to submit to server).
        NOTE: this does NOT perform any cryptanalysis; it only generates guesses.
        """

        if seed is None or not isinstance(seed, (bytes, bytearray)):
            raise RuntimeError("security_algorithm_bruteforce_rsa expects a seed (bytes)")

        # Decide candidate length
        if candidate_len is None:
            # Try to infer from available private key attribute (if present), otherwise default
            key_size_bytes = getattr(self, "_rsa_privkey_size_bytes", None)
            if key_size_bytes:
                candidate_len = key_size_bytes
            else:
                # reasonable default for demonstration (e.g. 2048-bit key => 256 bytes)
                candidate_len = 256

        start = time.time()
        last_candidate = b"\x00" * candidate_len
        attempts = 0

        # choose generator according to mode
        if mode == "random":
            gen = lambda: secrets.token_bytes(candidate_len)
        elif mode == "zeros":
            gen = lambda: b"\x00" * candidate_len
        elif mode == "increment":
            # returns big-endian incrementing bytes (wraps around)
            counter = 0
            def inc():
                nonlocal counter
                b = counter.to_bytes(candidate_len, "big", signed=False)
                counter = (counter + 1) & ((1 << (candidate_len*8)) - 1)
                return b
            gen = inc
        else:
            raise ValueError("Unknown mode; choose 'random', 'zeros', or 'increment'")

        # Generate candidates until time or attempt limit
        while True:
            if max_attempts is not None and attempts >= max_attempts:
                break
            now = time.time()
            if (now - start) >= max_seconds:
                break

            candidate = gen()
            last_candidate = candidate
            attempts += 1

        # For demonstration, you may want to log attempts
        try:
            print(f"[BRUTE_SIM] Mode={mode}, attempts={attempts}, duration={time.time()-start:.3f}s")
        except Exception:
            pass

        return last_candidate



def estimate_bruteforce_feasibility(key_bits: int = 2048,
                                    attempts_per_second: float = 1e9,
                                    demo_seconds: float = 2*3600):
    import math
    log10_space = key_bits * math.log10(2)
    attempts_demo = attempts_per_second * demo_seconds
    log10_attempts_demo = math.log10(attempts_demo) if attempts_demo > 0 else float("-inf")
    log10_prob = (log10_attempts_demo - log10_space)
    seconds_per_year = 3600 * 24 * 365
    log10_years_to_exhaust = log10_space - math.log10(attempts_per_second) - math.log10(seconds_per_year)

    print("\n=== Brute-force feasibility estimate ===")
    print(f"Key size: {key_bits} bits")
    print(f"Search space ≈ 2^{key_bits} (log10 ≈ {log10_space:.3f}) -> ~10^{log10_space:.3f} possibilities")
    print(f"Attempts in demo (duration={demo_seconds} s at {attempts_per_second:.0f}/s): {attempts_demo:.3e} (log10 ≈ {log10_attempts_demo:.3f})")
    print(f"Approx success probability ≈ 10^{log10_prob:.3f} (practically zero)")
    print(f"Time to exhaust entire space at {attempts_per_second:.0f}/s ≈ 10^{log10_years_to_exhaust:.3f} years")
    print("========================================\n")

    return {
        "key_bits": key_bits,
        "log10_space": log10_space,
        "attempts_demo": attempts_demo,
        "log10_attempts_demo": log10_attempts_demo,
        "log10_prob": log10_prob,
        "log10_years_to_exhaust": log10_years_to_exhaust,
    }

# small tweak: make bruteforce run-time configurable via instance attribute
# (you can keep your existing function; this just reads attribute if present)
def _ensure_bruteforce_config(uds_tester):
    # set default per-call seconds if not present
    if not hasattr(uds_tester, "bruteforce_seconds"):
        uds_tester.bruteforce_seconds = 1.0  # default 1 second per unlock attempt
    if not hasattr(uds_tester, "bruteforce_mode"):
        uds_tester.bruteforce_mode = "random"

# Put this main in your file (replace previous main)
def main():
    # --- CONFIGURE THESE ---
    TOTAL_SECONDS = 2 * 3600        # 7200 = 2 hours; set smaller for testing (e.g. 30)
    SLEEP_BETWEEN_ATTEMPTS = 0.0    # 0.0 => no delay between attempts; set small pause if desired
    ESTIMATOR_KEY_BITS = 2048
    ESTIMATOR_ATTEMPTS_PER_SEC = 1e9
    # ------------------------

    start_time = time.time()
    deadline = start_time + TOTAL_SECONDS
    attempt = 0
    success = False
    total_attempts_submitted = 0

    with IsoTPSocketConnection(interface='vcan0', rxid=0x7E8, txid=0x7E0, tpsock=isotp.socket()) as connection:
        connection.open()
        uds_tester = UDSTester(connection)

        # configure per-call brute forcing time and mode (tune for demo / real runs)
        uds_tester.bruteforce_seconds = 1.0   # how long each security_algorithm_bruteforce_rsa runs (seconds)
        uds_tester.bruteforce_mode = "random" # "random", "zeros", or "increment"

        # helper to ensure attributes exist
        _ensure_bruteforce_config(uds_tester)

        # ensure the client_config points to a wrapper that passes our per-call options
        # We'll wrap the method so udsoncan passes only seed and our wrapper supplies configured args.
        def security_wrapper(seed: bytes) -> bytes:
            # pass configured per-call params into the bruteforce function
            return uds_tester.security_algorithm_bruteforce_rsa(
                seed,
                candidate_len=None,
                max_seconds=getattr(uds_tester, "bruteforce_seconds", 1.0),
                max_attempts=None,
                mode=getattr(uds_tester, "bruteforce_mode", "random"),
            )

        uds_tester.client_config['security_algo'] = security_wrapper

        # create client once and reuse it
        with Client(connection, request_timeout=10, config=uds_tester.client_config) as client:
            print(f"[MAIN] Starting continuous unlock attempts for up to {TOTAL_SECONDS} seconds.")
            while time.time() < deadline:
                attempt += 1
                attempt_start = time.time()
                print(f"[MAIN] Attempt #{attempt} (elapsed {time.time()-start_time:.1f}s) - requesting SecurityAccess...")

                try:
                    resp = client.unlock_security_access(uds_tester.client_config['security_level'])
                    if hasattr(resp, "code") and resp.code == 0x67:
                        # real positive response (0x67 = positive SecurityAccess)
                        print(f"[MAIN] SUCCESS: server accepted SecurityAccess on attempt #{attempt}")
                        success = True
                        break
                    else:
                        # any other or negative response — continue brute-forcing
                        print(f"[MAIN] Attempt #{attempt} failed or rejected. Response: {getattr(resp, 'code_name', resp)}")


                except NegativeResponseException as e:
                    code_name = getattr(e.response, "code_name", "UNKNOWN")
                    code = getattr(e.response, "code", None)
                    print(f"[MAIN] NegativeResponse: code=0x{code:02X} name={code_name}")
                except InvalidResponseException as e:
                    print(f"[MAIN] InvalidResponse: {e}")
                except UnexpectedResponseException as e:
                    print(f"[MAIN] UnexpectedResponse: {e}")
                except Exception as e:
                    print(f"[MAIN] Exception during attempt #{attempt}: {e}")

                # approximate 1 submission per loop iteration
                total_attempts_submitted += 1

                attempt_time = time.time() - attempt_start
                print(f"[MAIN] Attempt #{attempt} finished (dur {attempt_time:.3f}s).")
                if SLEEP_BETWEEN_ATTEMPTS:
                    time.sleep(SLEEP_BETWEEN_ATTEMPTS)

            total_elapsed = time.time() - start_time
            print(f"[MAIN] Finished loop. success={success}, attempts={attempt}, elapsed={total_elapsed:.2f}s")

    # final feasibility printed using your chosen attacker rate and the actual demo duration
    estimate_results = estimate_bruteforce_feasibility(
        key_bits=ESTIMATOR_KEY_BITS,
        attempts_per_second=ESTIMATOR_ATTEMPTS_PER_SEC,
        demo_seconds=TOTAL_SECONDS
    )

    print("Summary:")
    if success:
        print(f"  - SecurityAccess unlocked after {attempt} unlock attempts in {total_elapsed:.2f}s")
    else:
        print(f"  - Failed to unlock within {TOTAL_SECONDS}s after {attempt} attempts.")
    print(f"  - Feasibility estimator log10_prob = {estimate_results['log10_prob']:.3f}")
    print("Done.")

if __name__ == "__main__":
    main()
