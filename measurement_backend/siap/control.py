"""Pinned SM9 authority signs bounded canonical JSON snapshots."""
import json
from .crypto import sign

CONTROL_ID = b'V2XSM9-CONTROL-v1'
PREFIX = b'V2XSM9CONTROL1'
MAX_CONTROL = 1024 * 1024

def canonical(data): return json.dumps(data, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()

def signed_snapshot(data, authority_key):
    raw = canonical(data)
    return canonical({'snapshot': data, 'signature': sign(authority_key, PREFIX + raw).hex()})

def parse_snapshot(raw, verifier):
    if not 0 < len(raw) <= MAX_CONTROL: raise ValueError('control size')
    envelope = json.loads(raw)
    if canonical(envelope) != raw: raise ValueError('noncanonical control')
    data = envelope['snapshot']; signature = bytes.fromhex(envelope['signature'])
    if not verifier.verify(CONTROL_ID, PREFIX + canonical(data), signature): raise ValueError('control signature')
    required = {'version', 'issued_us', 'expires_us', 'domain', 'key_version', 'public_key', 'epochs', 'revoked'}
    if set(data) != required: raise ValueError('control fields')
    for name in ('version', 'issued_us', 'expires_us', 'domain', 'key_version'):
        if type(data[name]) is not int or not 0 <= data[name] < 2**63: raise ValueError('control integer')
    if data['version'] == 0 or data['expires_us'] < data['issued_us']: raise ValueError('control interval')
    if len(bytes.fromhex(data['public_key'])) != 129: raise ValueError('master key')
    if not isinstance(data['epochs'], dict) or not 1 <= len(data['epochs']) <= 1024: raise ValueError('epoch bound')
    for e, interval in data['epochs'].items():
        if str(int(e)) != e or not 0 <= int(e) < 2**32: raise ValueError('epoch')
        if not isinstance(interval, list) or len(interval) != 2: raise ValueError('epoch interval')
        a, b = interval
        if type(a) is not int or type(b) is not int or not 0 <= a <= b < 2**63: raise ValueError('epoch range')
    if not isinstance(data['revoked'], list) or len(data['revoked']) > 8192: raise ValueError('revocation bound')
    if len(set(data['revoked'])) != len(data['revoked']): raise ValueError('duplicate revocation')
    for identity in data['revoked']:
        decoded=bytes.fromhex(identity)
        if len(decoded) != 40 or decoded.hex() != identity: raise ValueError('noncanonical revocation ID')
    return data
