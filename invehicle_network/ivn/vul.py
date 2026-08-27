class Vul:
    def __init__(self, name: str, accessvector: str, probability: float, impact: float):
        self.name = name
        self.accessvector = accessvector
        self.probability = probability
        self.impact = impact

    def to_dict(self):
        return {
            "name": self.name,
            "accessvector": self.accessvector,
            "probability": self.probability,
            "impact": self.impact
        }
