# attack_range.py

import math

class AttackRange:
    """
    A class to model attack range and compute success probability
    based on attacker proximity to the vehicle.
    """

    def __init__(self, attack_type="wifi"):
        self.attack_type = attack_type.lower()
        self.range_config = {
            "pats": {"range_m": 0.1, "base_success_prob": 1.0},
            "tpms": {"range_m": 1.0, "base_success_prob": 0.9},
            "rke":  {"range_m": 15.0, "base_success_prob": 0.8},
            "bluetooth": {"range_m": 10.0, "base_success_prob": 0.85},
            "wifi": {"range_m": 60.0, "base_success_prob": 0.7},
            "cellular": {"range_m": float("inf"), "base_success_prob": 0.95}
        }

        if self.attack_type not in self.range_config:
            raise ValueError(f"Unsupported attack type: {attack_type}")

    def get_range(self):
        """Return the maximum range of the selected attack type."""
        return self.range_config[self.attack_type]["range_m"]
        
    def distance_between_attacker_vehicle(self, vehicle_location, attacker_location):
        return self._calculate_distance(vehicle_location, attacker_location)

    @staticmethod
    def _calculate_distance(loc1, loc2):
        return math.sqrt((loc2.x - loc1.x)**2 + (loc2.y - loc1.y)**2)


    def compute_success_probability(self, distance, max_range):
        if distance <= 0.9 * max_range:
                print(f"{attack_type.capitalize()} attack succeeded (within reliable range).")
                # Inject UDS or spoof payload here
        # Unreliable edge: 90% < distance ≤ 100%
        elif distance <= max_range:
            if random.random() < 0.5:  # 50% chance near the boundary
                print(f"{attack_type.capitalize()} attack succeeded (barely in range).")
                # Payload delivered
            else:
                print(f"{attack_type.capitalize()} attack failed (weak signal near limit).")

        # Out of range
        else:
            print(f"{attack_type.capitalize()} attack failed (out of range).")
