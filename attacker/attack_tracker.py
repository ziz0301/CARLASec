# attack_tracker.py
class AttackTracker:
    def __init__(self):
        self.attack_path = "A"

    def update_path(self, new_step):
        self.attack_path += f"->{new_step}"

    def get_path(self):
        return self.attack_path
        
    def print_path(self):
        print(f"Attack Path: {self.attack_path}")
