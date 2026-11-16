import ctypes as C
import unittest
from siap.cache_v3 import CacheV3
from test_core import CoreTests
from siap.state import Record


def identity(i): return i.to_bytes(40, 'big')

class FakeCrypto:
    q_size = 32
    def build(self, identity, out):
        out[:] = bytes([identity[-1]]) * len(out)
        return out

class LeaseTests(unittest.TestCase):
    def cache(self, **kw): return CacheV3(FakeCrypto(), **kw)
    def test_no_retroactive_credit(self):
        c=self.cache(); i=identity(1)
        c.accepted(i,False,False,1,100)
        self.assertEqual(c.metrics()['a_active'],0)
        t=c.prepare(i,True,2,100,1)
        self.assertEqual(c.find(i).count,0)
        c.accepted(i,False,False,3,100,t)
        self.assertEqual(c.find(i).count,1)
        self.assertEqual(c.builds,0)

    def test_first_event_sunk_and_b_zero(self):
        c=self.cache(); i=identity(1)
        self.assertIsNone(c.prepare(i,False,0,100))
        c.accepted(i,True,False,1,100)
        self.assertEqual(c.builds,0)
        with self.assertRaises(ValueError): self.cache(threshold=0)
        class Retaining(FakeCrypto):
            def retained(self,identity): return C.create_string_buffer(32)
        z=CacheV3(Retaining(),threshold=0);z.accepted(i,True,False,1,100)
        self.assertEqual(z.builds,0);self.assertEqual(z.retentions,1)

    def test_replaced_token_cannot_credit(self):
        c=self.cache(budget=120);a,b=identity(1),identity(2)
        self.assertEqual(c.capacity,1)
        t=c.prepare(a,True,1,100);c.prepare(b,True,2,100)
        c.accepted(a,False,False,3,100,t)
        self.assertIsNone(c.find(a));self.assertEqual(c.charged_events,0)

    def test_invalid_does_not_refresh_authenticated_recency(self):
        c=self.cache();i=identity(1)
        c.prepare(i,True,8,100,3)
        self.assertEqual(c.find(i).last,3)
        c.prepare(i,True,9,100,3)
        self.assertEqual(c.find(i).count,0);self.assertEqual(c.find(i).last,3)

    def test_unreserved_cannot_credit(self):
        c=self.cache(budget=0);i=identity(1)
        self.assertIsNone(c.prepare(i,True,1,100))
        c.accepted(i,False,False,2,100)
        self.assertEqual(c.charged_events,0)

    def test_expiry_invalidates_token(self):
        c=self.cache();i=identity(1);t=c.prepare(i,True,0,1)
        c.expire(2);c.accepted(i,False,False,2,3,t)
        self.assertEqual(c.charged_events,0)

    def test_pending_work_no_rent_and_cancel_billed(self):
        c=self.cache(threshold=1,request_build=lambda *a:True);i=identity(1)
        t=c.prepare(i,True,0,10);c.accepted(i,False,False,1,10,t)
        p=c.prepare(i,True,2,10);c.accepted(i,False,False,3,10,p)
        self.assertEqual(c.charged_events,1);self.assertEqual(c.build_requests,1)
        c.expire(11);self.assertFalse(c.complete(i,t[1],bytes(32),123,False))
        self.assertEqual(c.build_cpu_ns,123);self.assertEqual(c.build_cancelled,1)
        self.assertEqual(c.workspace_bytes,32)

    def test_failed_build_not_retried(self):
        c=self.cache(threshold=1,request_build=lambda *a:True);i=identity(1)
        t=c.prepare(i,True,0,10);c.accepted(i,False,False,1,10,t)
        self.assertFalse(c.complete(i,t[1],None,77,True))
        p=c.prepare(i,True,2,10);c.accepted(i,False,False,3,10,p)
        self.assertEqual(c.build_requests,1);self.assertEqual(c.build_cpu_ns,77)

    def test_doorkeeper_and_aging(self):
        c=self.cache(method='tinylfu');i=identity(1)
        c._increment(i);self.assertEqual(c._frequency(i),1)
        self.assertEqual(sum(c.sketch),0)
        c._increment(i);self.assertEqual(c._frequency(i),2)
        for _ in range(c.sample_size-2): c._increment(i)
        self.assertEqual(c.aging_resets,1);self.assertFalse(c._present(i))
        self.assertLessEqual(c._frequency(i),7)

    def test_twohit_exact_ghost(self):
        c=self.cache(method='twohit');i=identity(1)
        c.accepted(i,True,False,1,100);self.assertEqual(c.builds,0)
        c.accepted(i,False,False,2,100);self.assertEqual(c.builds,1)

    def test_window_slru_capacity(self):
        class Large(FakeCrypto):q_size=14816
        c=CacheV3(Large(),'wtinylfu')
        for j in range(300):
            i=identity((j//3)%11);hit=c.lookup(i) is not None
            c.accepted(i,False,hit,j,1000)
            self.assertLessEqual(sum(s.state and s.count==1 for s in c.slots),1)
            self.assertLessEqual(sum(s.state and s.count==3 for s in c.slots),2)
            self.assertLessEqual(c.allocated_bytes,65536)
        self.assertEqual(c.capacity,4)


class V3CoreTests(CoreTests):
    def receiver(self, **kw):
        kw['policy_revision']='v3'
        if 'r_budget' in kw:
            kw['r_budget'] += (kw['r_budget']//C.sizeof(Record))*8
        return super().receiver(**kw)

    def test_admission_before_application_callback(self):
        def handoff(m):
            if m.counter == 1:self.assertEqual(r.cache.find(m.identity()).count,1)
        r=self.receiver(handoff=handoff)
        r.process(self.packet(self.msg(0)));r.process(self.packet(self.msg(1)))
        self.assertEqual(r.cache.charged_events,1)

    def test_consumed_rejected_has_no_first_accept_history(self):
        def hook(stage,r,m):
            if stage=='consumed':self.now+=200000
        r=self.receiver(hook=hook)
        event=r.process(self.packet(self.msg(0)))
        self.assertIsNone(event['accepted_ns'])
        self.assertEqual(sum(r.last_accept),0)
        self.assertEqual(r.cache.charged_events,0)

    def test_v3_async_real_crypto_and_workspace(self):
        r=self.receiver(build_mode='async',threshold=1,precompute='miller',a_budget=65536)
        r.process(self.packet(self.msg(0)));r.process(self.packet(self.msg(1)))
        r.drain_builds()
        self.assertEqual(r.cache.builds,1)
        self.assertTrue(r.process(self.packet(self.msg(2)))['cache_hit'])
        self.assertEqual(r.cache.workspace_bytes,r.crypto.q_size)
        self.assertLessEqual(r.cache.allocated_bytes,65536)

    def test_v3_async_revoked_result_is_billed(self):
        import threading
        from siap.control import signed_snapshot
        entered=threading.Event();release=threading.Event()
        def hook(stage,r,m):
            if stage=='build_started':entered.set();release.wait(3)
        r=self.receiver(build_mode='async',threshold=1,hook=hook)
        r.process(self.packet(self.msg(0)));r.process(self.packet(self.msg(1)))
        self.assertTrue(entered.wait(2))
        r.install(signed_snapshot({**self.data,'version':2,'revoked':[self.msg().identity().hex()]},self.ak))
        release.set();r.drain_builds()
        self.assertEqual(r.cache.build_cancelled,1)
        self.assertGreater(r.cache.build_cpu_ns,0)
        self.assertIsNone(r.cache.lookup(self.msg().identity()))

if __name__=='__main__':unittest.main()
