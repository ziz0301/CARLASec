# attack_manager.py
import threading
import time

class AttackManager:
    def __init__(self):
        self._lock = threading.Lock()
        self._current = None  # dict or None

    def start_attack(self, attack_id, attack_type, duration_sec):
        end_ts = time.time() + float(duration_sec)
        with self._lock:
            self._current = {
                "attack_id": str(attack_id),
                "attack_type": str(attack_type),
                "start_ts": time.time(),
                "end_ts": end_ts
            }

    def stop_attack(self):
        with self._lock:
            self._current = None

    def get_current_attack(self):
        with self._lock:
            cur = self._current
            if not cur:
                return None
            if time.time() > cur["end_ts"]:
                self._current = None
                return None
            return dict(cur)  # return a copy

# module-level singleton
attack_mgr = AttackManager()
