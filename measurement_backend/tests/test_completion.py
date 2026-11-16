import ctypes as C
import sys
import tempfile
import unittest
from pathlib import Path
from siap.crypto import Verifier,keygen,extract,sign
from siap.cache import Cache,NoReserveCache

class CompletionTests(unittest.TestCase):
    def test_miller_randomized_equivalence_and_corruption(self):
        sk,pk=keygen();v=Verifier(pk,'miller');qv=Verifier(pk)
        self.addCleanup(v.close);self.addCleanup(qv.close)
        self.assertEqual(v.q_size,32+77*3*64)
        for n in range(20):
            identity=b'identity'+n.to_bytes(2,'big');m=bytes(range(n+1))*3
            sig=sign(extract(sk,identity),m);table=v.build(identity);q=qv.build(identity)
            self.assertFalse(v.verify(b'wrong',m,sig,table));self.assertFalse(qv.verify(b'wrong',m,sig,q))
            for body,s,expected in ((m,sig,True),(m+b'x',sig,False),(m,b'\0'*32+sig[32:],False)):
                self.assertEqual(v.verify(identity,body,s,table),expected)
                self.assertEqual(v.verify(identity,body,s),expected)
                self.assertEqual(qv.verify(identity,body,s,q),expected)
                self.assertEqual(v.verify(identity,body,s,reference=True),expected)
            broken=C.create_string_buffer(bytes(table),len(bytes(table)))
            broken[0]=bytes([broken.raw[0]^1]);self.assertFalse(v.verify(identity,m,sig,broken))

    def test_independent_sm9_both_directions(self):
        sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'vendor/gmalg-python'))
        import gmalg
        for identity in (b'Alice',b'\0'+bytes(range(39))):
            sk,pk=keygen();key=extract(sk,identity);message=b'independent SM9 test'
            kgc=gmalg.SM9KGC(hid_s=b'\x01',msk_s=sk,mpk_s=pk)
            self.assertEqual(kgc.generate_sk_sign(identity),key[129:])
            ref=gmalg.SM9(hid_s=b'\x01',mpk_s=pk,sk_s=key[129:],uid=identity)
            raw=sign(key,message);self.assertTrue(ref.verify(message,raw[:32],raw[32:]))
            self.assertFalse(ref.verify(message+b'x',raw[:32],raw[32:]))
            h,s=ref.sign(message);v=Verifier(pk,'miller');self.addCleanup(v.close)
            self.assertTrue(v.verify(identity,message,h+s,v.build(identity)))
            self.assertFalse(v.verify(identity,message+b'x',h+s,v.build(identity)))

    def test_noreserve_counts_without_leasing_table(self):
        _,pk=keygen();v=Verifier(pk,'miller');self.addCleanup(v.close)
        a=NoReserveCache(v,budget=32768,threshold=2)
        identity=b'a'*40
        a.accepted(identity,True,False,1,100)
        a.accepted(identity,False,False,2,100)
        self.assertEqual(a.metrics()['a_active'],0)
        self.assertEqual(a.metrics()['metadata_active'],1)
        a.accepted(identity,False,False,3,100)
        self.assertIsNotNone(a.lookup(identity))
        self.assertLessEqual(a.allocated_bytes,32768)
        self.assertEqual(a.metrics()['metadata_active'],0)

    def test_noreserve_expired_async_generation_not_published(self):
        _,pk=keygen();v=Verifier(pk);self.addCleanup(v.close);jobs=[]
        a=NoReserveCache(v,budget=4096,threshold=1,request_build=lambda *x:jobs.append(x) or True)
        identity=b'a'*40;a.accepted(identity,False,False,1,2)
        self.assertEqual(a.metrics()['a_active'],0);a.expire(3)
        self.assertFalse(a.complete(identity,jobs[0][1],v.build(identity),1,True))
        self.assertIsNone(a.lookup(identity));self.assertEqual(a.build_cancelled,1)

if __name__=='__main__':unittest.main()
