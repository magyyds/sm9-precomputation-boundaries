"""SM2 signatures using GmSSL, real X.509 chains verified using OpenSSL 3.

SM2 wire extension: common envelope + payload + raw64 + cert_len_u16 + DER.
The CA root is pinned out of band. Leaf CN is SHA256(full canonical identity).
"""
import ctypes as C
import hashlib
import json
import struct
import subprocess
import time
from pathlib import Path
from .crypto import lib
from .wire import HEADER, Message, MAX_PAYLOAD

_x=None

def xlib():
    global _x
    if _x is None:
        _x=C.CDLL(str(Path(__file__).resolve().parents[1]/'build/libsiap_x509.so'))
        for name,args,ret in [
            ('lab_ca_new',[C.c_char_p,C.c_size_t],C.c_void_p),
            ('lab_ca_free',[C.c_void_p],None),
            ('lab_cert_verify',[C.c_void_p,C.c_char_p,C.c_size_t,C.c_int64,C.c_char_p,C.c_size_t,C.c_void_p,C.c_void_p],C.c_int),
            ('lab_pem_secret',[C.c_char_p,C.c_void_p],C.c_int),
            ('lab_openssl_sm2_verify',[C.c_char_p,C.c_char_p,C.c_size_t,C.c_char_p,C.c_size_t,C.c_char_p],C.c_int)]:
            f=getattr(_x,name);f.argtypes=args;f.restype=ret
        for name,args in [
            ('lab_sm2_generate',[C.c_void_p,C.c_void_p]),
            ('lab_sm2_sign',[C.c_char_p,C.c_char_p,C.c_size_t,C.c_char_p,C.c_size_t,C.c_void_p]),
            ('lab_sm2_verify',[C.c_char_p,C.c_char_p,C.c_size_t,C.c_char_p,C.c_size_t,C.c_char_p])]:
            f=getattr(lib(),name);f.argtypes=args;f.restype=C.c_int
    return _x

def keygen():
    xlib();secret=C.create_string_buffer(32);pub=C.create_string_buffer(65)
    if lib().lab_sm2_generate(secret,pub)!=1: raise ValueError('SM2 keygen')
    return secret.raw,pub.raw

def sign(secret,identity,message):
    if len(secret)!=32: raise ValueError('SM2 secret length')
    xlib();out=C.create_string_buffer(64)
    if lib().lab_sm2_sign(secret,identity,len(identity),message,len(message),out)!=1: raise ValueError('SM2 sign')
    return out.raw

def verify(public,identity,message,signature,independent=False):
    if len(public)!=65 or len(signature)!=64: return False
    xlib()
    f=xlib().lab_openssl_sm2_verify if independent else lib().lab_sm2_verify
    return f(public,identity,len(identity),message,len(message),signature)==1

class CA:
    def __init__(self,der):
        self.handle=xlib().lab_ca_new(der,len(der))
        if not self.handle: raise ValueError('invalid trust root')
    def leaf(self,der,identity,now):
        out=C.create_string_buffer(65);validity=(C.c_int64*2)()
        status=xlib().lab_cert_verify(self.handle,der,len(der),now,identity,len(identity),out,validity)
        if status!=1: raise ValueError(f'certificate chain/identity/time rejected ({status})')
        return out.raw,tuple(validity)
    def close(self):
        if self.handle: xlib().lab_ca_free(self.handle);self.handle=None
    def __del__(self):
        if getattr(self,'handle',None): self.close()

def make_pki(folder,identities):
    folder=Path(folder);folder.mkdir(parents=True,exist_ok=False)
    def openssl(*args):
        subprocess.run(['openssl',*map(str,args)],check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    root=folder/'ca.key.pem';pem=folder/'ca.pem'
    openssl('genpkey','-algorithm','SM2','-out',root)
    openssl('req','-new','-x509','-key',root,'-sm3','-days','2','-subj','/CN=SIAP-Lab-CA','-out',pem,
            '-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign',
            '-addext','subjectKeyIdentifier=hash')
    openssl('x509','-in',pem,'-outform','DER','-out',folder/'ca.der')
    ext=folder/'leaf.ext'
    ext.write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n')
    result={}
    for n,identity in enumerate(identities,1):
        path=folder/f'leaf-{n:05d}';name=hashlib.sha256(identity).hexdigest()
        openssl('genpkey','-algorithm','SM2','-out',str(path)+'.key.pem')
        openssl('req','-new','-key',str(path)+'.key.pem','-sm3','-subj','/CN='+name,'-out',str(path)+'.csr')
        openssl('x509','-req','-in',str(path)+'.csr','-CA',pem,'-CAkey',root,'-set_serial',n,'-days','2',
                '-sm3','-extfile',ext,'-out',str(path)+'.pem')
        openssl('x509','-in',str(path)+'.pem','-outform','DER','-out',str(path)+'.der')
        secret=C.create_string_buffer(32)
        if xlib().lab_pem_secret((str(path)+'.key.pem').encode(),secret)!=1: raise ValueError('SM2 private key import')
        result[identity]=(secret.raw,Path(str(path)+'.der').read_bytes())
    return (folder/'ca.der').read_bytes(),result

def encode(message,signature,certificate=b''):
    if message.suite!=2 or len(signature)!=64 or len(certificate)>2048: raise ValueError('SM2 encoding')
    return message.body()+signature+struct.pack('>H',len(certificate))+certificate

def decode(packet):
    if not 120<=len(packet)<=HEADER.size+MAX_PAYLOAD+64+2+2048: raise ValueError('SM2 packet length')
    v,suite,kind,policy,flags,d,k,e,pid,ts,c,n=HEADER.unpack_from(packet)
    if (v,suite,kind,policy,flags)!=(2,2,1,1,0) or n>MAX_PAYLOAD: raise ValueError('SM2 header')
    tail=HEADER.size+n
    if len(packet)<tail+66: raise ValueError('SM2 truncated')
    certlen=struct.unpack_from('>H',packet,tail+64)[0]
    if certlen>2048 or len(packet)!=tail+66+certlen: raise ValueError('SM2 certificate framing')
    return Message(d,k,e,pid,ts,c,packet[HEADER.size:tail],policy,suite),packet[tail:]

class CertificateVerifier:
    """Fixed-capacity validated leaf cache; authorization is rechecked at commit."""
    q_size=1
    def __init__(self,context_public,ca_der,budget=262144,clock=None):
        self.public=context_public;self.ca=CA(ca_der)
        self.binding=hashlib.sha256(ca_der).digest();self.clock=clock or (lambda:time.time_ns()//1000)
        class Entry(C.Structure):
            _fields_=[('used',C.c_uint8),('identity',C.c_ubyte*40),('public',C.c_ubyte*65),
                      ('digest',C.c_ubyte*32),('start',C.c_int64),('end',C.c_int64),('last',C.c_uint64)]
        self.entries=(Entry*(budget//C.sizeof(Entry)))()
        if len(self.entries)<1: raise ValueError('certificate budget')
        self.validations=self.hits=self.cert_cpu_ns=0
    def find(self,identity): return next((s for s in self.entries if s.used and bytes(s.identity)==identity),None)
    def authorized(self,identity,now):
        s=self.find(identity)
        return s is not None and s.start<=now//1000000<=s.end
    def verify(self,identity,message,signature,q=None):
        if len(signature)<66: return False
        sig=signature[:64];n=int.from_bytes(signature[64:66],'big');cert=signature[66:]
        if len(cert)!=n or n>2048: return False
        now=self.clock()//1000000;s=self.find(identity)
        cold=(s is None or not s.start<=now<=s.end or (cert and bytes(s.digest)!=hashlib.sha256(cert).digest()))
        if cold:
            if not cert:return False
            start=time.thread_time_ns()
            try: pub,validity=self.ca.leaf(cert,identity,now)
            except ValueError: return False
            finally: self.cert_cpu_ns+=time.thread_time_ns()-start;self.validations+=1
        else: pub=bytes(s.public);self.hits+=1
        if not verify(pub,identity,message,sig): return False
        if cold:
            if s is None: s=next((s for s in self.entries if not s.used),None)
            if s is None: s=min(self.entries,key=lambda e:(e.last,bytes(e.identity)))
            s.identity[:]=identity;s.public[:]=pub;s.digest[:]=hashlib.sha256(cert).digest()
            s.start,s.end=validity;s.used=1
        s.last=self.clock();return True
    def metrics(self):
        return {'certificate_validations':self.validations,'certificate_hits':self.hits,
                'certificate_cpu_ns':self.cert_cpu_ns,'certificate_array_bytes':C.sizeof(self.entries),
                'certificate_capacity':len(self.entries)}
    def close(self): self.ca.close()
