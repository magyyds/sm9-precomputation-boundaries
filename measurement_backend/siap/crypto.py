"""Small explicit ctypes ABI; no fake crypto fallback."""
import ctypes as C
import os
from pathlib import Path

_lib = None

def lib():
    global _lib
    if _lib is None:
        path = os.environ.get('SIAP_CRYPTO_LIB', str(Path(__file__).resolve().parents[1] / 'build/libsiap_crypto.so'))
        _lib = C.CDLL(path)
        specs = {
            'lab_q_size': ([], C.c_size_t), 'lab_verifier_size': ([], C.c_size_t),
            'lab_miller_size': ([], C.c_size_t),
            'lab_master_generate': ([C.c_void_p, C.c_void_p], C.c_int),
            'lab_extract': ([C.c_char_p, C.c_char_p, C.c_size_t, C.c_void_p], C.c_int),
            'lab_sign': ([C.c_char_p, C.c_char_p, C.c_size_t, C.c_void_p], C.c_int),
            'lab_verifier_new': ([C.c_char_p], C.c_void_p),
            'lab_verifier_free': ([C.c_void_p], None),
            'lab_build': ([C.c_void_p, C.c_char_p, C.c_size_t, C.c_void_p], C.c_int),
            'lab_verify': ([C.c_void_p, C.c_char_p, C.c_size_t, C.c_char_p, C.c_size_t, C.c_char_p, C.c_void_p], C.c_int),
            'lab_verify_reference': ([C.c_void_p, C.c_char_p, C.c_size_t, C.c_char_p, C.c_size_t, C.c_char_p], C.c_int),
        }
        specs['lab_build_miller']=specs['lab_build'];specs['lab_verify_miller']=specs['lab_verify']
        for name, (args, result) in specs.items():
            f = getattr(_lib, name); f.argtypes = args; f.restype = result
    return _lib

def keygen():
    sk, pk = C.create_string_buffer(32), C.create_string_buffer(129)
    if lib().lab_master_generate(sk, pk) != 1: raise RuntimeError('SM9 key generation failed')
    return sk.raw, pk.raw

def extract(secret, identity):
    if len(secret) != 32 or not identity: raise ValueError('invalid secret or identity')
    out = C.create_string_buffer(194)
    if lib().lab_extract(secret, identity, len(identity), out) != 1: raise ValueError('SM9 extract failed')
    return out.raw

def sign(key, message):
    if len(key) != 194: raise ValueError('invalid signing key')
    out = C.create_string_buffer(97)
    if lib().lab_sign(key, message, len(message), out) != 1: raise ValueError('SM9 sign failed')
    return out.raw

class Verifier:
    def __init__(self, public, precompute='q'):
        if precompute not in ('q','miller'):raise ValueError('precomputation mode')
        self.precompute=precompute
        if len(public) != 129: raise ValueError('invalid public key length')
        self.public = public
        self.handle = lib().lab_verifier_new(public)
        if not self.handle: raise ValueError('invalid SM9 public key')
        self.q_size = lib().lab_miller_size() if precompute=='miller' else lib().lab_q_size()

    def build(self, identity, out=None):
        out = out if out is not None else C.create_string_buffer(self.q_size)
        if C.sizeof(out) < self.q_size: raise ValueError('Q buffer too small')
        build=lib().lab_build_miller if self.precompute=='miller' else lib().lab_build
        if build(self.handle, identity, len(identity), out) != 1: raise ValueError('invalid identity material')
        return out

    def verify(self, identity, message, signature, q=None, reference=False):
        if len(signature) != 97 or not identity: return False
        if q is not None and C.sizeof(q) < self.q_size: raise ValueError('Q buffer too small')
        args = (self.handle, identity, len(identity), message, len(message), signature)
        verify=lib().lab_verify_miller if self.precompute=='miller' else lib().lab_verify
        return (lib().lab_verify_reference(*args) if reference else verify(*args, q)) == 1

    def close(self):
        if self.handle: lib().lab_verifier_free(self.handle); self.handle = None

    def __del__(self):
        if getattr(self, 'handle', None): self.close()
