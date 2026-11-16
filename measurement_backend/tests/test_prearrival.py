import ctypes as C
import tempfile
import threading
import time
import unittest
from pathlib import Path
from siap.crypto import keygen,extract,sign
from siap.control import CONTROL_ID,signed_snapshot
from siap.receiver import Receiver
from siap.wire import Message
from siap import sm2,workload

class PreparationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sk,cls.pk=keygen();cls.ask,cls.apk=keygen();cls.ak=extract(cls.ask,CONTROL_ID)

    def fixture(self,**kwargs):
        now=time.time_ns()//1000
        d={'version':1,'issued_us':now,'expires_us':now+2_000_000,'domain':1,'key_version':1,
           'public_key':self.pk.hex(),'epochs':{'1':[now-1000000,now+1000000]},'revoked':[]}
        r=Receiver(self.pk,self.apk,clock=lambda:now,**kwargs);r.install(signed_snapshot(d,self.ak))
        self.addCleanup(r.close)
        def packet(c,pid=1):
            m=Message(1,1,1,pid.to_bytes(16,'big'),now,c,b'x')
            return m.encode(sign(extract(self.sk,m.identity()),m.signed_bytes()))
        return r,d,packet

    def test_async_same_equation(self):
        r,d,packet=self.fixture(build_mode='async',threshold=1)
        r.process(packet(0));r.process(packet(1));r.drain_builds()
        self.assertEqual(r.cache.builds,1)
        self.assertTrue(r.process(packet(2))['cache_hit'])

    def test_async_revoke_discards_build(self):
        entered=threading.Event();release=threading.Event()
        def hook(stage,r,m):
            if stage=='build_started': entered.set();release.wait(3)
        r,d,packet=self.fixture(build_mode='async',threshold=1,hook=hook)
        r.process(packet(0));r.process(packet(1));self.assertTrue(entered.wait(2))
        identity=next(bytes(x.identity).hex() for x in r.cache.slots if x.state)
        r.install(signed_snapshot({**d,'version':2,'revoked':[identity]},self.ak))
        release.set();r.drain_builds()
        self.assertIsNone(r.cache.lookup(bytes.fromhex(identity)))
        self.assertEqual(r.cache.build_cancelled,1)

    def test_async_one_job_and_evicted_generation(self):
        entered=threading.Event();release=threading.Event()
        def hook(stage,r,m):
            if stage=='build_started': entered.set();release.wait(3)
        r,d,packet=self.fixture(build_mode='async',threshold=1,a_budget=400,hook=hook)
        r.process(packet(0));r.process(packet(1));self.assertTrue(entered.wait(2))
        r.process(packet(0,2));r.process(packet(1,2))
        self.assertEqual(r.cache.build_requests,1)
        release.set();r.drain_builds()
        self.assertEqual(r.cache.build_cancelled,1)
        r.process(packet(2,2));r.drain_builds()
        self.assertTrue(r.process(packet(3,2))['cache_hit'])

    def test_schedule_determinism_churn_and_envelope(self):
        for pattern in ('periodic','poisson','burst'):
            a=workload.generate(100,10,51,pattern,churn=30)
            self.assertEqual(a,workload.generate(100,10,51,pattern,churn=30))
            self.assertGreater(len({x['pid'] for x in a}),8)
            self.assertEqual(sorted(x['offset_us'] for x in a),[x['offset_us'] for x in a])
            self.assertGreaterEqual(workload.identity_envelope(a,30)['required_sigma_observed'],1)

    def test_sm2_openssl_independent_verify(self):
        secret,pub=sm2.keygen();identity=b'Alice';m=b'SM2 independent verification'
        sig=sm2.sign(secret,identity,m)
        self.assertTrue(sm2.verify(pub,identity,m,sig))
        self.assertTrue(sm2.verify(pub,identity,m,sig,True))
        self.assertFalse(sm2.verify(pub,b'Bob',m,sig,True))
        self.assertFalse(sm2.verify(pub,identity,m+b'x',sig,True))

    def test_sm2_real_chain_and_hot_cache(self):
        now=time.time_ns()//1000;m=Message(1,1,1,b'\x01'*16,now,0,b'sm2',suite=2)
        with tempfile.TemporaryDirectory() as tmp:
            ca,issued=sm2.make_pki(Path(tmp)/'pki',[m.identity()])
            now=time.time_ns()//1000
            m=Message(1,1,1,m.pid,now,0,b'sm2',suite=2)
            secret,der=issued[m.identity()];store=sm2.CA(ca)
            pub,validity=store.leaf(der,m.identity(),now//1000000)
            with self.assertRaises(ValueError): store.leaf(der,b'wrong',now//1000000)
            with self.assertRaises(ValueError): store.leaf(der,m.identity(),validity[1]+1)
            with self.assertRaises(ValueError): store.leaf(der+b'tail',m.identity(),now//1000000)
            store.close()
            backend=sm2.CertificateVerifier(self.pk,ca,clock=lambda:now)
            r,d,packet=self.fixture(method='cold',signature_backend=backend)
            sig=sm2.sign(secret,m.identity(),m.signed_bytes())
            wire=sm2.encode(m,sig,der)
            self.assertEqual(sm2.decode(wire)[0],m)
            self.assertEqual(r.process(wire)['reason'],'delivered')
            self.assertEqual(r.process(wire)['reason'],'replay_reject')
            m2=Message(1,1,1,m.pid,now,1,b'sm2',suite=2)
            hot=sm2.encode(m2,sm2.sign(secret,m2.identity(),m2.signed_bytes()))
            self.assertEqual(r.process(hot)['reason'],'delivered')
            self.assertEqual(backend.validations,1)
            self.assertEqual(r.metrics()['r_active'],1)

    def test_sm2_untrusted_root_and_invalid_signature_do_not_cache(self):
        now=time.time_ns()//1000;m=Message(1,1,1,b'\x02'*16,now,0,b'test',suite=2)
        with tempfile.TemporaryDirectory() as tmp:
            ca,issued=sm2.make_pki(Path(tmp)/'pki',[m.identity()])
            other,_=sm2.make_pki(Path(tmp)/'other',[])
            secret,der=issued[m.identity()];now=time.time_ns()//1000
            store=sm2.CA(other)
            with self.assertRaises(ValueError):store.leaf(der,m.identity(),now//1000000)
            store.close()
            backend=sm2.CertificateVerifier(self.pk,ca,clock=lambda:now);self.addCleanup(backend.close)
            tail=b'\0'*64+len(der).to_bytes(2,'big')+der
            self.assertFalse(backend.verify(m.identity(),m.signed_bytes(),tail))
            self.assertIsNone(backend.find(m.identity()))
            with self.assertRaises(ValueError):sm2.decode(sm2.encode(m,b'\0'*64,der)+b'tail')

    def test_mobility_contact_conversion(self):
        from siap.mobility import convert
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'fcd.xml'
            path.write_text('<fcd-export><timestep time="0"><vehicle id="v1" x="0" y="0"/><vehicle id="far" x="90" y="90"/></timestep><timestep time="0.1"><vehicle id="v1" x="1" y="0"/></timestep><timestep time="0.5"><vehicle id="v1" x="2" y="0"/></timestep></fcd-export>')
            trace=convert(path,radius=10,center=(0,0),interval=.5)
            self.assertEqual(trace['messages'],[{'offset_us':0,'pid':1},{'offset_us':500000,'pid':1}])
            self.assertEqual(trace['vehicles_in_contact'],1)

    def test_trace_input_rejects_unsorted_time(self):
        import json
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'trace.json';path.write_text(json.dumps({'schema':1,'messages':[{'offset_us':2,'pid':1},{'offset_us':1,'pid':1}]}))
            with self.assertRaises(ValueError):workload.generate(2,1,trace=path)

if __name__=='__main__':unittest.main()
