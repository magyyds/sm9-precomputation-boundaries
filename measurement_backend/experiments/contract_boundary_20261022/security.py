"""Bounded standard-contract model and actual v3 receiver differential cases."""
import argparse,collections,concurrent.futures,ctypes as C,hashlib,json,os,subprocess,sys,threading
from dataclasses import replace
from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1];sys.path.insert(0,str(ROOT))
from siap.crypto import keygen,extract,sign
from siap.control import CONTROL_ID,signed_snapshot
from siap.receiver import Receiver
from siap.state import Record
from siap.wire import Message
METHODS=['cold','twohit','tinylfu','siap']
def dump(p,x):p.write_text(json.dumps(x,indent=2,ensure_ascii=False),encoding='utf-8')

def explore(mode,depth=10):
    # p0,p1,used,revoked,expired,cached,crashed,accept_count,bad_control_accept
    initial=(0,0,0,0,0,0,0,0,0);q=collections.deque([(initial,())]);seen={initial};edges=0
    while q:
        s,path=q.popleft()
        if s[7]>1 or s[8]:return dict(mode=mode,states=len(seen),edges=edges,depth=depth,violation=True,witness=list(path),final=list(s))
        if len(path)==depth:continue
        moves=[]
        def add(label,**changes):
            n=list(s)
            for k,v in changes.items():n[int(k)]=v
            if tuple(n)!=s:moves.append((label,tuple(n)))
        for t in (0,1):
            p=s[t];blocked=s[3] or s[4]
            if p in (0,4) and not blocked:add(f'verify[{t}]',**{str(t):1})
            if p==1:
                if blocked or s[2]:add(f'reject[{t}]',**{str(t):4})
                elif mode=='non_atomic':add(f'check_empty[{t}]',**{str(t):2})
                else:add(f'consume[{t}]',**{str(t):3,'2':1})
            if p==2:add(f'write_without_recheck[{t}]',**{str(t):3,'2':1})
            if p==3:
                if blocked and mode!='no_final_check':add(f'final_reject[{t}]',**{str(t):4})
                else:add(f'accept[{t}]',**{str(t):4,'5':1,'7':s[7]+1,'8':int(bool(blocked))})
        add('revoke',**{'3':1});add('expire',**{'4':1})
        if s[5]:add('evict_A',**{'5':0,'2':0 if mode=='coupled_eviction' else s[2]})
        if s[4]:add('safe_gc_after_expiry',**{'2':0})
        if not s[6]:add('crash_restart',**{'0':0,'1':0,'5':0,'6':1,'2':0 if mode=='volatile_restart' else s[2]})
        for label,n in moves:
            edges+=1
            if n not in seen:seen.add(n);q.append((n,path+(label,)))
    return dict(mode=mode,states=len(seen),edges=edges,depth=depth,violation=False,witness=None)

class Fixture:
    def __init__(self):
        self.sk,self.pk=keygen();ask,self.apk=keygen();self.ak=extract(ask,CONTROL_ID);self.now=1000000
        self.control=dict(version=1,issued_us=self.now,expires_us=3000000,domain=1,key_version=1,public_key=self.pk.hex(),epochs={'1':[0,2000000]},revoked=[])
        self.raw=signed_snapshot(self.control,self.ak);self.keys={};self.packets={}
    def packet(self,pid,c,bad=False):
        key=(pid,c,bad)
        if key not in self.packets:
            m=Message(1,1,1,pid.to_bytes(16,'big'),1000000,c,b'contract-minimum')
            if pid not in self.keys:self.keys[pid]=extract(self.sk,m.identity())
            sig=sign(self.keys[pid],m.signed_bytes());self.packets[key]=(replace(m,payload=b'invalid') if bad else m).encode(sig)
        return self.packets[key]
    def receiver(self,method,db=None,hook=None,r_slots=2):
        r=Receiver(self.pk,self.apk,method=method,threshold=2,r_budget=r_slots*(C.sizeof(Record)+8),a_budget=32768,width=64,db=db,clock=lambda:self.now,hook=hook,policy_revision='v3',precompute='miller')
        if r.control is None:r.install(self.raw)
        return r

def child(folder,stage,method):
    d=json.loads((folder/'input.json').read_text())
    def hook(s,r,m):
        if s==stage:
            with (folder/'boundary.txt').open('w') as f:f.write(s);f.flush();os.fsync(f.fileno())
            os._exit(77)
    r=Receiver(bytes.fromhex(d['public']),bytes.fromhex(d['authority']),method=method,threshold=2,r_budget=d['r_budget'],a_budget=32768,width=64,db=str(folder/'ledger.db'),clock=lambda:1000000,hook=hook,policy_revision='v3',precompute='miller')
    r.install(bytes.fromhex(d['control']));r.process(bytes.fromhex(d['packet']));raise AssertionError('missed boundary')

def run(out):
    out.mkdir(parents=True,exist_ok=False);fx=Fixture();records=[];failures=[]
    model=[explore(m) for m in ['standard_contract','coupled_eviction','volatile_restart','no_final_check','non_atomic']]
    assert not model[0]['violation'] and all(x['violation'] for x in model[1:]);dump(out/'bounded_model.json',model)
    def record(case,method,events,expected=None,**extra):
        ok=expected is None or [e['reason'] for e in events]==expected
        row=dict(case=case,method=method,pass_check=ok,events=events,expected=expected,**extra);records.append(row)
        if not ok:failures.append(row)
    # Independent mathematical oracle: finite set plus high-watermark, no reuse
    # of Ledger.advance or cache logic. No garbage collection in this fixed-time case.
    stream=[(1,0,False),(1,2,False),(1,1,False),(1,2,False),(1,3,True),(1,3,False),(2,0,False),(3,0,False),(1,65,False),(1,1,False),(1,65,False),(2,1,False)]
    oracle={};expected=[]
    for pid,c,bad in stream:
        if bad:reason='signature_reject'
        elif pid not in oracle and len(oracle)==2:reason='ledger_capacity'
        elif pid in oracle and (c in oracle[pid] or c<=max(oracle[pid])-64):reason='replay_reject'
        else:oracle.setdefault(pid,set()).add(c);reason='delivered'
        expected.append(reason)
    for method in METHODS:
        r=fx.receiver(method);events=[r.process(fx.packet(*x)) for x in stream];record('independent_oracle_stream',method,events,expected,metrics=r.metrics());r.close()
        r=fx.receiver(method);events=[]
        for c,n in enumerate([2,4,8]):
            packet=fx.packet(1,c);barrier=threading.Barrier(n)
            def work(_):barrier.wait();return r.process(packet)
            with concurrent.futures.ThreadPoolExecutor(max_workers=n) as pool:group=list(pool.map(work,range(n)))
            ok=sum(e['accepted_ns'] is not None for e in group)==1 and sum(e['reason']=='replay_reject' for e in group)==n-1
            record(f'concurrent_duplicates_{n}',method,group,**{'invariant_pass':ok})
            if not ok:failures.append(records[-1])
        r.close()
        ident=Message(1,1,1,(1).to_bytes(16,'big'),1000000,0,b'x').identity().hex()
        revoke=signed_snapshot({**fx.control,'version':2,'revoked':[ident]},fx.ak)
        def hook(stage,r,m):
            if stage=='consumed':r.install(revoke)
        r=fx.receiver(method,hook=hook);e=r.process(fx.packet(1,0));record('revocation_after_consume',method,[e],['revoked_reject'],consumed=e.get('consumed_ns') is not None,accepted=e['accepted_ns'] is not None);assert e['accepted_ns'] is None;r.close()
        # A erasure leaves R invariant. It does not imply equal latency/acceptance
        # under deadlines; these logical-time security cases freeze the clock.
        r=fx.receiver(method);first=r.process(fx.packet(1,0));before=bytes(r.ledger.records)
        C.memset(C.addressof(r.cache.slots),0,C.sizeof(r.cache.slots))
        same=before==bytes(r.ledger.records);e=r.process(fx.packet(1,0));record('erase_only_A',method,[first,e],['delivered','replay_reject'],r_unchanged=same);assert same;r.close()
        for stage in ['verified','before_consume','consumed','accepted','handed_off']:
            folder=out/f'crash-{method}-{stage}';folder.mkdir()
            dump(folder/'input.json',dict(public=fx.pk.hex(),authority=fx.apk.hex(),control=fx.raw.hex(),packet=fx.packet(1,0).hex(),r_budget=2*(C.sizeof(Record)+8)))
            p=subprocess.run([sys.executable,str(HERE/'security.py'),'child',str(folder),'--stage',stage,'--method',method],timeout=30)
            assert p.returncode==77 and (folder/'boundary.txt').read_text()==stage
            r=fx.receiver(method,db=str(folder/'ledger.db'));e=r.process(fx.packet(1,0));record('crash_'+stage,method,[e],['delivered' if stage in ['verified','before_consume'] else 'replay_reject']);r.close()
            fx.now=999999;r=fx.receiver(method,db=str(folder/'ledger.db'));e=r.process(fx.packet(1,1));record('rollback_after_'+stage,method,[e],['clock_or_storage_reject']);r.close();fx.now=1000000
    dump(out/'public_inputs.json',dict(public=fx.pk.hex(),authority=fx.apk.hex(),control=fx.raw.hex(),packets={str(k):v.hex() for k,v in fx.packets.items()}))
    dump(out/'cases.json',records)
    result=dict(cases=len(records),events=sum(len(x['events']) for x in records),failures=len(failures),methods=METHODS,model=model,policy_specific_security_advantage_observed=False,process_kills=20,power_loss_tested=False,shared_receiver_wrapper=True)
    dump(out/'summary.json',result);print(json.dumps(result,indent=2));assert not failures

if __name__=='__main__':
    ap=argparse.ArgumentParser();ap.add_argument('action');ap.add_argument('out',type=Path);ap.add_argument('--stage');ap.add_argument('--method');a=ap.parse_args()
    if a.action=='child':child(a.out,a.stage,a.method)
    else:run(a.out.resolve())
