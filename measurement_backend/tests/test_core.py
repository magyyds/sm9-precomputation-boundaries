import concurrent.futures
import ctypes as C
import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from siap.crypto import keygen, extract, sign, Verifier
from siap.wire import Message, decode, HEADER
from siap.control import CONTROL_ID, canonical, signed_snapshot
from siap.receiver import Receiver
from siap.state import Record, advance
from siap.cache import Cache

class CoreTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sk, cls.pk = keygen()
        cls.ask, cls.apk = keygen()
        cls.ak = extract(cls.ask, CONTROL_ID)

    def setUp(self):
        self.now = 1_000_000
        self.data = {'version': 1, 'issued_us': self.now, 'expires_us': self.now+2_000_000,
                     'domain': 1, 'key_version': 1, 'public_key': self.pk.hex(),
                     'epochs': {'1': [0, 2_000_000]}, 'revoked': []}
        self.receivers = []

    def tearDown(self):
        for r in self.receivers:
            if not r.closed: r.close()

    def receiver(self, **kwargs):
        r = Receiver(self.pk, self.apk, clock=lambda: self.now, **kwargs)
        self.receivers.append(r)
        if r.control is None: r.install(signed_snapshot(self.data, self.ak))
        return r

    def msg(self, counter=0, pid=1, **kwargs):
        return Message(1,1,1,pid.to_bytes(16,'big'),self.now,counter,b'payload',**kwargs)

    def packet(self, m): return m.encode(sign(extract(self.sk, m.identity()), m.signed_bytes()))

    def test_wire_exact(self):
        m = self.msg(); p = self.packet(m)
        self.assertEqual(HEADER.size, 54); self.assertEqual(len(m.identity()), 40)
        self.assertEqual(len(p), len(m.payload)+151)
        self.assertEqual(decode(p)[0], m)

    def test_wire_negative_matrix(self):
        p = self.packet(self.msg())
        variants = [p[:n] for n in (0, 1, 53, 54, 100, len(p)-1)] + [p+b'x', p+b'x'*2000]
        for index in (0,1,3,5,7,52,53):
            v=bytearray(p); v[index] ^= 0x40; variants.append(bytes(v))
        r=self.receiver()
        for v in variants: self.assertEqual(r.process(v)['reason'], 'parse_reject')
        self.assertEqual(r.metrics()['r_active'], 0)

    def test_sm9_cold_hot_reference(self):
        v = Verifier(self.pk); self.addCleanup(v.close)
        for i in range(12):
            m = self.msg(i, i%3+1); s=sign(extract(self.sk,m.identity()),m.signed_bytes())
            q=v.build(m.identity())
            for msg, expected in ((m.signed_bytes(),True),(m.signed_bytes()+b'X',False)):
                self.assertEqual(v.verify(m.identity(),msg,s),expected)
                self.assertEqual(v.verify(m.identity(),msg,s,q),expected)
                self.assertEqual(v.verify(m.identity(),msg,s,reference=True),expected)
            self.assertFalse(v.verify(b'wrong',m.signed_bytes(),s))

    def test_upstream_published_extract_vector(self):
        # Pinned GmSSL tests/sm9test.c: hex_ks, hex_ds, identity Alice.
        secret=bytes.fromhex('000130E78459D78545CB54C587E02CF480CE0B66340F319F348A1D5B1F2DC5F4')
        expected=bytes.fromhex('04A5702F05CF1315305E2D6EB64B0DEB923DB1A0BCF0CAFF90523AC8754AA69820'
                               '78559A844411F9825C109F5EE3F52D720DD01785392A727BB1556952B2B013D3')
        key=extract(secret,b'Alice')
        self.assertEqual(key[129:],expected)
        v=Verifier(key[:129]); self.addCleanup(v.close)
        sig=sign(key,b'Chinese IBS standard')
        self.assertTrue(v.verify(b'Alice',b'Chinese IBS standard',sig))
        self.assertTrue(v.verify(b'Alice',b'Chinese IBS standard',sig,v.build(b'Alice')))

    def test_signature_invalid_scalars_points(self):
        r=self.receiver(); m=self.msg(); p=self.packet(m); sig=p[-97:]
        invalid=[b'\0'*32+sig[32:], b'\xff'*32+sig[32:], sig[:32]+b'\0'*65,
                 sig[:32]+b'\x04'+b'\xff'*64, sig[:32]+b'\x02'+sig[33:]]
        for s in invalid:
            self.assertEqual(r.process(m.encode(s))['reason'],'signature_reject')
        self.assertEqual(r.metrics()['r_active'],0); self.assertEqual(r.metrics()['builds'],0)

    def test_replay_and_eviction(self):
        r=self.receiver(method='immediate',a_budget=400)
        p=self.packet(self.msg()); self.assertEqual(r.process(p)['reason'],'delivered')
        self.assertEqual(r.process(self.packet(self.msg(pid=2)))['reason'],'delivered')
        self.assertGreater(r.cache.evictions,0)
        self.assertEqual(r.process(p)['reason'],'replay_reject')

    def test_window_boundaries(self):
        high,bits=1000,1
        for c in (999,745): self.assertIsNotNone(advance(high,bits,c,256))
        for c in (1000,744): self.assertIsNone(advance(high,bits,c,256))
        self.assertEqual(advance(1000,1,1001,256),(1001,3))
        self.assertEqual(advance(0,1,2**64-1,256),(2**64-1,1))
        self.assertIsNone(advance(0,1,2**64,256))
        self.assertEqual(advance(None,0,0,256),(0,1))

    def test_out_of_order_once(self):
        r=self.receiver()
        for c, expected in [(1000,'delivered'),(999,'delivered'),(745,'delivered'),(744,'replay_reject'),(999,'replay_reject')]:
            self.assertEqual(r.process(self.packet(self.msg(c)))['reason'],expected)

    def test_duplicate_concurrency(self):
        r=self.receiver(); p=self.packet(self.msg())
        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
            events=list(pool.map(r.process,[p]*16))
        self.assertEqual(sum(e['accepted_ns'] is not None for e in events),1)
        self.assertEqual(sum(e['handed_off_ns'] is not None for e in events),1)

    def test_same_counter_different_signatures(self):
        r=self.receiver(); m=self.msg()
        self.assertEqual(r.process(self.packet(m))['reason'],'delivered')
        self.assertEqual(r.process(self.packet(replace(m,payload=b'other')))['reason'],'replay_reject')

    def test_full_ledger_preserves_existing(self):
        r=self.receiver(r_budget=C.sizeof(Record))
        p=self.packet(self.msg())
        self.assertEqual(r.process(p)['reason'],'delivered')
        self.assertEqual(r.process(self.packet(self.msg(pid=2)))['reason'],'ledger_capacity')
        self.assertEqual(r.process(p)['reason'],'replay_reject')
        self.assertEqual(r.process(self.packet(self.msg(1)))['reason'],'delivered')

    def test_siap_sunk_first_and_auth_only(self):
        r=self.receiver(threshold=2)
        p=self.packet(self.msg())
        r.process(p); self.assertEqual(r.cache.metrics()['a_active'],0)
        r.process(self.packet(self.msg(1))); self.assertEqual(r.cache.builds,0)
        r.process(p); self.assertEqual(r.cache.builds,0)
        q=bytearray(self.packet(self.msg(2))); q[-1]^=1
        r.process(bytes(q)); self.assertEqual(r.cache.builds,0)
        r.process(self.packet(self.msg(2))); self.assertEqual(r.cache.builds,1)
        self.assertTrue(r.process(self.packet(self.msg(3)))['cache_hit'])

    def test_tinylfu_only_unique_authenticated(self):
        r=self.receiver(method='tinylfu')
        p=self.packet(self.msg()); r.process(p); r.process(p)
        self.assertEqual(r.cache.auth_events,1)
        self.assertEqual(len(r.cache.sketch),4096)

    def test_revocation_between_verify_accept(self):
        def hook(stage,r,m):
            if stage=='verified':
                data={**self.data,'version':2,'revoked':[m.identity().hex()]}
                r.install(signed_snapshot(data,self.ak))
        r=self.receiver(hook=hook)
        e=r.process(self.packet(self.msg()))
        self.assertEqual(e['reason'],'revoked_reject'); self.assertIsNone(e['accepted_ns'])

    def test_expire_during_persist_consumes_but_no_accept(self):
        def hook(stage,r,m):
            if stage=='consumed': self.now+=100001
        r=self.receiver(hook=hook)
        e=r.process(self.packet(self.msg()))
        self.assertIsNotNone(e['consumed_ns']); self.assertIsNone(e['accepted_ns'])
        self.assertEqual(e['reason'],'stale_reject')

    def test_control_signature_version_epoch_revocation(self):
        r=self.receiver(); raw=signed_snapshot(self.data,self.ak)
        with self.assertRaises(ValueError): r.install(raw)
        bad=json.loads(raw); bad['snapshot']['version']=2
        with self.assertRaises(ValueError): r.install(canonical(bad))
        d={**self.data,'version':2,'epochs':{'1':[0,3_000_000]}}
        with self.assertRaises(ValueError): r.install(signed_snapshot(d,self.ak))
        d={**self.data,'version':2,'revoked':[self.msg().identity().hex()]}
        r.install(signed_snapshot(d,self.ak))
        with self.assertRaises(ValueError): r.install(signed_snapshot({**self.data,'version':3},self.ak))

    def test_control_expiry_clock_rollback_context(self):
        r=self.receiver(); p=self.packet(self.msg())
        self.assertEqual(r.process(self.packet(replace(self.msg(),domain=2)))['reason'],'context_reject')
        self.now-=1; self.assertEqual(r.process(p)['reason'],'clock_or_storage_reject')
        self.now=3_000_001; self.assertEqual(r.process(p)['reason'],'control_expired')

    def test_persistent_recovery_replay_and_control_floor(self):
        with tempfile.TemporaryDirectory() as d:
            db=str(Path(d)/'ledger.db'); r=self.receiver(db=db); p=self.packet(self.msg())
            e=r.process(p); self.assertIsNotNone(e['durably_consumed_ns']); r.close()
            recovered=self.receiver(db=db)
            self.assertEqual(recovered.process(p)['reason'],'replay_reject')
            with self.assertRaises(ValueError): recovered.install(signed_snapshot(self.data,self.ak))
            self.now-=1
            self.assertEqual(recovered.process(p)['reason'],'clock_or_storage_reject')
            recovered.close()

    def test_crash_after_consume(self):
        # Exception injection: abrupt OS process kill is additionally in test_crash.py.
        with tempfile.TemporaryDirectory() as d:
            db=str(Path(d)/'ledger.db')
            def hook(stage,r,m):
                if stage=='consumed': raise RuntimeError('crash')
            r=self.receiver(db=db,hook=hook); p=self.packet(self.msg())
            with self.assertRaises(RuntimeError): r.process(p)
            r.close(); recovered=self.receiver(db=db)
            self.assertEqual(recovered.process(p)['reason'],'replay_reject'); recovered.close()

    def test_application_failure_is_not_retried(self):
        def fail(m): raise RuntimeError('app failure')
        r=self.receiver(handoff=fail); p=self.packet(self.msg())
        e=r.process(p); self.assertIsNotNone(e['accepted_ns']); self.assertIsNone(e['handed_off_ns'])
        self.assertEqual(r.process(p)['reason'],'replay_reject')

    def test_two_receivers_cannot_share_live_database(self):
        with tempfile.TemporaryDirectory() as d:
            db=str(Path(d)/'ledger.db'); r=self.receiver(db=db)
            with self.assertRaises(ValueError): self.receiver(db=db)
            r.close()

    def test_memory_budgets(self):
        for method in Cache.METHODS:
            r=self.receiver(method=method)
            for n in range(8): r.process(self.packet(self.msg(n)))
            self.assertLessEqual(r.metrics()['a_allocated_bytes'],262144)
            self.assertLessEqual(r.metrics()['r_allocated_bytes'],262144)

if __name__=='__main__': unittest.main()
