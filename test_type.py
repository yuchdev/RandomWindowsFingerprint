import enum

class TestType(enum.IntEnum):
    telemetry_fingerprint = 0
    network_fingerprint = 1
    windows_fingerprint = 2
    hardware_fingerprint = 3
    font_fingerprint = 4
