"""Supplemental negative/control-path checks, outside all timing windows."""
import ctypes as C
from dataclasses import replace
import unittest
from siap.crypto import keygen,extract,sign
from siap.control import CONTROL_ID,signed_snapshot
from siap.receiver import Receiver
from siap.wire import Message

class V3SecurityControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sk,cls.pk=keygen();cls.ask,cls.apk=keygen();cls.ak=extract(cls.ask,CONTROL_ID)

    def setUp(self):self.now=1000000

    def setup_receiver(self,**kw):
        r=Receiver(self.pk,self.apk,clock=lambda:self.now,policy_revision='v3',**kw)
        control={'version':1,'issued_us':self.now,'expires_us':self.now+2000000,'domain':1,'key_version':1,
                 'public_key':self.pk.hex(),'epochs':{'1':[0,2000000]},'revoked':[]}
        r.install(signed_snapshot(control,self.ak));self.addCleanup(r.close);return r

    def packet(self,c=0,pid=1,bad=False):
        m=Message(1,1,1,pid.to_bytes(16,'big'),self.now,c,b'control-test')
        sig=sign(extract(self.sk,m.identity()),m.signed_bytes())
        return (replace(m,payload=b'tampered') if bad else m).encode(sig)

    def test_all_baseline_histories_ignore_replay_and_invalid(self):
        for method in ['lru','tinylfu','wtinylfu','twohit']:
            with self.subTest(method=method):
                r=self.setup_receiver(method=method)
                p=self.packet();self.assertEqual(r.process(p)['reason'],'delivered')
                def state():return (bytes(r.cache.slots),bytes(r.cache.sketch),bytes(r.cache.door),bytes(r.cache.ghosts),r.cache.auth_events)
                before=state()
                self.assertEqual(r.process(p)['reason'],'replay_reject')
                self.assertEqual(state(),before)
                self.assertEqual(r.process(self.packet(1,bad=True))['reason'],'signature_reject')
                self.assertEqual(state(),before)

    def test_invalid_known_identity_can_churn_a_but_cannot_erase_r(self):
        # One Q-sized acceleration slot. This is an availability limitation,
        # deliberately made visible rather than hidden by a post-verify reserve.
        r=self.setup_receiver(method='siap',threshold=1,a_budget=312)
        a=self.packet(0,1);b=self.packet(0,2)
        self.assertEqual(r.process(a)['reason'],'delivered')
        self.assertEqual(r.process(b)['reason'],'delivered')
        self.assertEqual(r.process(self.packet(1,1))['reason'],'delivered')
        self.assertEqual(r.cache.capacity,1)
        a_id=Message(1,1,1,(1).to_bytes(16,'big'),self.now,0,b'x').identity()
        self.assertIsNotNone(r.cache.lookup(a_id))
        credit=r.cache.charged_events;replay_before=bytes(r.ledger.records)
        self.assertEqual(r.process(self.packet(1,2,bad=True))['reason'],'signature_reject')
        self.assertIsNone(r.cache.lookup(a_id))
        self.assertEqual(r.cache.charged_events,credit)
        self.assertEqual(bytes(r.ledger.records),replay_before)
        self.assertEqual(r.process(a)['reason'],'replay_reject')

if __name__=='__main__':unittest.main()
