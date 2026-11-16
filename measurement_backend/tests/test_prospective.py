import ctypes as C
import unittest
from siap.prospective_cache import ProspectiveCache,History
from siap.crypto import keygen,extract,sign
from siap.receiver import Receiver
from siap.control import CONTROL_ID,signed_snapshot
from siap.wire import Message
from dataclasses import replace

def ident(i):return i.to_bytes(40,'big')
class Fake:
    q_size=14816
    def build(self,identity,out):out[:]=bytes(len(out));return out

class PredictionTests(unittest.TestCase):
    def cache(self,variant='gain',**kw):return ProspectiveCache(Fake(),variant,build_ns=2,delta_ns=1,**kw)
    def accept(self,c,i,now):
        identity=ident(i);c.accepted(identity,False,c.lookup(identity) is not None,now,100000)
    def test_memory_equal_four_tables(self):
        self.assertEqual(C.sizeof(History),72)
        for v in ProspectiveCache.VARIANTS:
            c=self.cache(v);self.assertEqual(c.capacity,4);self.assertEqual(c.allocated_bytes,64224)
    def test_prepare_is_readonly(self):
        c=self.cache();self.accept(c,1,1)
        before=(bytes(c.history),bytes(c.slots),c.events)
        self.assertIsNone(c.prepare(ident(1),True,2,100))
        c.lookup(ident(1));self.assertEqual(before,(bytes(c.history),bytes(c.slots),c.events))
    def test_second_close_accept_can_build_without_reserved_credit(self):
        c=self.cache();self.accept(c,1,1);self.assertEqual(c.builds,0)
        self.accept(c,1,2);self.assertEqual(c.builds,1);self.assertIsNotNone(c.lookup(ident(1)))
    def test_long_distance_fails_build_cost_gate(self):
        c=self.cache();self.accept(c,1,0)
        for i in range(2,33):self.accept(c,i,i)
        self.accept(c,1,34)
        self.assertIsNone(c.lookup(ident(1)));self.assertEqual(c.cost_rejects,1)
    def test_cost_ablation_is_distinct(self):
        c=self.cache('gain_no_cost');self.accept(c,1,0)
        for i in range(2,33):self.accept(c,i,i)
        self.accept(c,1,34);self.assertIsNotNone(c.lookup(ident(1)))
    def test_victim_opportunity_cost_preserves_hot_resident(self):
        c=self.cache(budget=19512)
        for n,i in enumerate([1,1,2,1,2]):self.accept(c,i,n)
        self.assertIsNotNone(c.lookup(ident(1)));self.assertIsNone(c.lookup(ident(2)))
        self.assertGreater(c.victim_rejects,0)
    def test_no_victim_ablation_evicts_same_trace(self):
        c=self.cache('gain_no_victim',budget=19512)
        for n,i in enumerate([1,1,2,1,2]):self.accept(c,i,n)
        self.assertIsNone(c.lookup(ident(1)));self.assertIsNotNone(c.lookup(ident(2)))
    def test_history_bounded_after_churn(self):
        c=self.cache()
        for i in range(100):self.accept(c,i,i)
        self.assertEqual(sum(h.used for h in c.history),64);self.assertEqual(c.history_evictions,36)
        self.assertEqual(c.builds,0)
    def test_expiry_discards_history_and_acceleration(self):
        c=self.cache();self.accept(c,1,1);self.accept(c,1,2)
        c.expire(100001);self.assertIsNone(c.lookup(ident(1)));self.assertIsNone(c._history(ident(1)))
    def test_lfu2_rejects_equal_frequency_victim(self):
        c=self.cache('lfu2',budget=19512)
        for n,i in enumerate([1,1,2,2]):self.accept(c,i,n)
        self.assertIsNotNone(c.lookup(ident(1)));self.assertIsNone(c.lookup(ident(2)))

class AuthenticatedBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sk,cls.pk=keygen();cls.ask,cls.apk=keygen();cls.ak=extract(cls.ask,CONTROL_ID)
    def setUp(self):self.now=1000000
    def fixture(self,variant,hook=None):
        r=Receiver(self.pk,self.apk,policy_revision='v3',method='cold',clock=lambda:self.now,hook=hook)
        r.cache=ProspectiveCache(r.crypto,variant,build_ns=2,delta_ns=1)
        r.install(signed_snapshot({'version':1,'issued_us':self.now,'expires_us':3000000,
            'domain':1,'key_version':1,'public_key':self.pk.hex(),'epochs':{'1':[0,2000000]},'revoked':[]},self.ak))
        self.addCleanup(r.close);return r
    def packet(self,c,bad=False):
        m=Message(1,1,1,bytes(16),self.now,c,b'x');sig=sign(extract(self.sk,m.identity()),m.signed_bytes())
        return (replace(m,payload=b'y') if bad else m).encode(sig)
    def test_real_crypto_invalid_and_replay_cannot_mutate_predictors(self):
        for variant in ProspectiveCache.VARIANTS:
            r=self.fixture(variant);p=self.packet(0)
            self.assertEqual(r.process(p)['reason'],'delivered')
            before=(bytes(r.cache.history),bytes(r.cache.slots),r.cache.events)
            self.assertEqual(r.process(p)['reason'],'replay_reject')
            self.assertEqual(r.process(self.packet(1,True))['reason'],'signature_reject')
            self.assertEqual(before,(bytes(r.cache.history),bytes(r.cache.slots),r.cache.events))
            self.assertEqual(r.process(self.packet(1))['reason'],'delivered')
            self.assertEqual(r.cache.events,2)
    def test_consumed_rejected_has_no_predictor_credit(self):
        def hook(stage,r,m):
            if stage=='consumed':self.now+=200000
        r=self.fixture('gain',hook)
        e=r.process(self.packet(0));self.assertIsNone(e['accepted_ns'])
        self.assertEqual(r.cache.events,0);self.assertEqual(sum(h.used for h in r.cache.history),0)

if __name__=='__main__':unittest.main()
