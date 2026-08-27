class Bus:
    def __init__(self, name: str, protocol: str):
        self.name = name
        self.protocol = protocol

    def to_dict(self):
        return {
            "name": self.name,
            "protocol": self.protocol
        }
