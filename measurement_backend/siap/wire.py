"""Canonical 54-byte envelope + payload + raw 97-byte SM9 signature."""
from dataclasses import dataclass
import struct

HEADER = struct.Struct('>BBHHHIII16sQQH')
ID = struct.Struct('>III16sBH')
ID_PREFIX, MSG_PREFIX = b'V2XSM9ID2', b'V2XSM9MSG2'
MAX_PAYLOAD, SIGNATURE_SIZE = 1200, 97
MAX_PACKET = HEADER.size + MAX_PAYLOAD + SIGNATURE_SIZE

@dataclass(frozen=True)
class Message:
    domain: int
    key_version: int
    epoch: int
    pid: bytes
    timestamp_us: int
    counter: int
    payload: bytes
    policy: int = 1
    suite: int = 1

    def identity(self):
        if len(self.pid) != 16: raise ValueError('pid length')
        return ID_PREFIX + ID.pack(self.domain, self.key_version, self.epoch, self.pid, self.suite, self.policy)

    def body(self):
        if len(self.pid) != 16 or len(self.payload) > MAX_PAYLOAD: raise ValueError('length')
        if self.suite not in (1,2) or self.policy != 1: raise ValueError('unsupported suite/policy')
        return HEADER.pack(2, self.suite, 1, self.policy, 0, self.domain, self.key_version,
                           self.epoch, self.pid, self.timestamp_us, self.counter, len(self.payload)) + self.payload

    def signed_bytes(self): return MSG_PREFIX + self.body()

    def encode(self, signature):
        if len(signature) != SIGNATURE_SIZE: raise ValueError('signature length')
        return self.body() + signature

def decode(packet):
    if not HEADER.size + SIGNATURE_SIZE <= len(packet) <= MAX_PACKET: raise ValueError('packet length')
    v, suite, kind, policy, flags, d, k, e, pid, ts, c, n = HEADER.unpack_from(packet)
    if (v, suite, kind, policy, flags) != (2, 1, 1, 1, 0): raise ValueError('unsupported header')
    if n > MAX_PAYLOAD or len(packet) != HEADER.size + n + SIGNATURE_SIZE: raise ValueError('noncanonical length')
    return Message(d, k, e, pid, ts, c, packet[HEADER.size:HEADER.size+n], policy, suite), packet[-97:]
