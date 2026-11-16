"""Real child termination at every exposed acceptance boundary."""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from siap.crypto import keygen,extract,sign
from siap.control import CONTROL_ID,signed_snapshot
from siap.receiver import Receiver
from siap.wire import Message

class FaultMatrixTests(unittest.TestCase):
    def fixture(self,folder=None,**kwargs):
        sk,pk=keygen();ask,apk=keygen();now=1000000
        r=Receiver(pk,apk,clock=lambda:now,precompute='miller',db=str(Path(folder)/'r.db') if folder else None,**kwargs)
        self.addCleanup(r.close)
        d={'version':1,'issued_us':now,'expires_us':now+2000000,'domain':1,'key_version':1,'public_key':pk.hex(),
           'epochs':{'1':[0,2000000]},'revoked':[]}
        r.install(signed_snapshot(d,extract(ask,CONTROL_ID)))
        def packet(counter=0,pid=1):
            m=Message(1,1,1,pid.to_bytes(16,'big'),now,counter,b'test')
            return m.encode(sign(extract(sk,m.identity()),m.signed_bytes()))
        return r,packet

    def test_duplicate_concurrency_every_build_policy(self):
        import concurrent.futures
        for method in ('siap','noreserve'):
            for mode in ('sync','async'):
                r,packet=self.fixture(method=method,build_mode=mode,threshold=1)
                for counter,parallel in enumerate((2,4,8,16)):
                    p=packet(counter)
                    with concurrent.futures.ThreadPoolExecutor(max_workers=parallel) as pool:
                        events=list(pool.map(r.process,[p]*parallel))
                    self.assertEqual(sum(e['accepted_ns'] is not None for e in events),1)
                    self.assertEqual(sum(e['reason']=='replay_reject' for e in events),parallel-1)
                    r.drain_builds()
                r.close()

    def test_storage_failure_fails_closed_without_acceptance(self):
        import sqlite3
        with tempfile.TemporaryDirectory() as tmp:
            r,packet=self.fixture(tmp)
            r.ledger.db.set_authorizer(lambda action,*rest:sqlite3.SQLITE_DENY if action in (sqlite3.SQLITE_INSERT,sqlite3.SQLITE_UPDATE,sqlite3.SQLITE_DELETE) else sqlite3.SQLITE_OK)
            with self.assertRaises(sqlite3.DatabaseError):r.process(packet())
            self.assertTrue(r.ledger.failed);self.assertEqual(r.metrics()['r_active'],0)
            self.assertEqual(r.process(packet(1))['reason'],'clock_or_storage_reject');r.close()

    def test_unsafe_coupled_cache_counterexample(self):
        # Deliberately broken model, never selectable in the performance CLI.
        from siap.state import advance
        cache={};accepted=[]
        for identity,counter in [('A',0),('B',0),('A',0)]:
            state=cache.get(identity);result=advance(*(state or (None,0)),counter,64)
            if result is not None:
                if identity not in cache:cache.clear()
                cache[identity]=result;accepted.append((identity,counter))
        self.assertEqual(accepted.count(('A',0)),2)
        r,packet=self.fixture(method='immediate',a_budget=15000)
        p=packet();self.assertEqual(r.process(p)['reason'],'delivered')
        self.assertEqual(r.process(packet(pid=2))['reason'],'delivered')
        self.assertEqual(r.process(p)['reason'],'replay_reject')

    def test_crash_boundary_matrix(self):
        sk,pk=keygen();ask,apk=keygen();now=1000000
        m=Message(1,1,1,b'\1'*16,now,0,b'crash matrix');packet=m.encode(sign(extract(sk,m.identity()),m.signed_bytes()))
        d={'version':1,'issued_us':now,'expires_us':now+2000000,'domain':1,'key_version':1,'public_key':pk.hex(),
           'epochs':{'1':[0,2000000]},'revoked':[]}
        control=signed_snapshot(d,extract(ask,CONTROL_ID))
        script='''import json,os,sys
from pathlib import Path
from siap.receiver import Receiver
p=Path(sys.argv[1]);d=json.loads((p/'input.json').read_text());stage=sys.argv[2]
def hook(s,r,m):
 if s==stage:
  with (p/'boundary.txt').open('w') as f:f.write(s);f.flush();os.fsync(f.fileno())
  os._exit(77)
r=Receiver(bytes.fromhex(d['pk']),bytes.fromhex(d['apk']),db=str(p/'ledger.db'),clock=lambda:1000000,precompute='miller',hook=hook)
r.install(bytes.fromhex(d['control']));r.process(bytes.fromhex(d['packet']))
'''
        for stage in ('verified','before_consume','consumed','accepted','handed_off'):
            with self.subTest(stage=stage),tempfile.TemporaryDirectory() as temp:
                p=Path(temp);(p/'input.json').write_text(json.dumps({'pk':pk.hex(),'apk':apk.hex(),'control':control.hex(),'packet':packet.hex()}))
                result=subprocess.run([sys.executable,'-c',script,str(p),stage],timeout=20)
                self.assertEqual(result.returncode,77);self.assertEqual((p/'boundary.txt').read_text(),stage)
                r=Receiver(pk,apk,db=str(p/'ledger.db'),clock=lambda:now,precompute='miller')
                try:
                    reason=r.process(packet)['reason']
                    self.assertEqual(reason,'delivered' if stage in ('verified','before_consume') else 'replay_reject')
                finally:r.close()

    def test_network_loss_is_preserved_in_schedule(self):
        from siap.workload import generate
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'trace.json'
            path.write_text(json.dumps({'schema':1,'messages':[{'offset_us':1,'pid':1,'network_drop':True,'network_delay_us':200}]}))
            rows=generate(1,1,trace=path);self.assertTrue(rows[0]['network_drop']);self.assertEqual(rows[0]['network_delay_us'],200)
            path.write_text(json.dumps({'schema':1,'messages':[{'offset_us':1,'pid':1,'network_delay_us':-1}]}))
            with self.assertRaises(ValueError):generate(1,1,trace=path)

    def test_fixed_wall_window_plan_has_no_padding_packet(self):
        sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
        from fixed_window_plan import fixed_schedule,make
        rows=fixed_schedule(4,3,seed=91)
        self.assertEqual(rows,fixed_schedule(4,3,seed=91))
        self.assertTrue(all(0<=r['offset_us']<3000000 for r in rows))
        with tempfile.TemporaryDirectory() as temp:
            out=make(Path(temp)/'fixed',4,warmup=1,observe=2,seed=91,lead=10)
            config=json.loads((out/'scenario/scenario.json').read_text());trust=json.loads((out/'scenario/trust.json').read_text())
            self.assertEqual(trust['measurement']['end_us']-trust['measurement']['start_us'],2000000)
            self.assertEqual(config['end_us']-config['start_us'],3000000)
            self.assertEqual(len((out/'scenario/plan.jsonl').read_text().splitlines()),len(rows))
