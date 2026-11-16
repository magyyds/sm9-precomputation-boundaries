"""Real-SM9 screening with frozen, independently calibrated policy parameters."""
import argparse, ctypes as C, csv, hashlib, importlib.util, json, math, os
import platform, random, resource, statistics as S, subprocess, sys, time
from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1];sys.path.insert(0,str(ROOT))
from siap.cache import Cache
from siap.cache_v3 import CacheV3
from siap.state import Ledger
from siap.crypto import keygen,extract,sign

def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
kernel=module('shared_kernel',ROOT/'experiments/kernel_screen_20261021/screen.py')
old=module('original_screen',ROOT/'experiments/minscreen_20261020/screen.py')
Fixed=kernel.Fixed
METHODS=['qonly','lru','tinylfu','wtinylfu','twohit','siap','legacy']
BASELINES=METHODS[:5]
PROFILES=['stable_fit','stable_pressure','mixed','short','burst']

def dump(p,x):p.write_text(json.dumps(x,indent=2,ensure_ascii=False),encoding='utf-8')
def read(p):return json.loads(p.read_text(encoding='utf-8'))
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def measure(f):
    c=time.thread_time_ns();w=time.monotonic_ns();v=f();return v,time.thread_time_ns()-c,time.monotonic_ns()-w
def boot(xs):
    r=random.Random(83000);v=sorted(S.mean(r.choices(xs,k=len(xs))) for _ in range(10000));return [v[249],v[9749]]

class QPool:
    def __init__(self,v,budget=65536):
        class Q(C.Structure):
            _fields_=[('used',C.c_uint8),('identity',C.c_ubyte*40),('last',C.c_uint64),('q',C.c_ubyte*v.q_size)]
        self.slots=(Q*((budget-v.q_size)//C.sizeof(Q)))()
        self.scratch=C.create_string_buffer(v.q_size)
        self.bytes=C.sizeof(self.slots)+C.sizeof(self.scratch)
    def find(self,i):return next((s for s in self.slots if s.used and bytes(s.identity)==i),None)
    def get(self,i):
        s=self.find(i);return None if s is None else s.q
    def put(self,i,q,now):
        s=self.find(i)
        if s is None:
            s=next((s for s in self.slots if not s.used),None)
            if s is None:raise AssertionError('profile exceeded predeclared Q capacity')
            s.identity[:]=i;s.q[:]=bytes(q);s.used=1
        s.last=now

class Incremental:
    def __init__(self,tv,qp):self.q_size=tv.q_size;self.qp=qp;self.bridge=old.bridge()
    def build(self,i,out):
        q=self.qp.get(i);assert q is not None
        self.bridge.screen_from_q(q,out);return out

def material(seed,profile):
    r=random.Random(seed);sk,pk=keygen()
    if profile=='stable_fit': seq=[i for i in range(4) for _ in range(32)]
    elif profile=='stable_pressure':seq=[i for i in range(8) for _ in range(16)]
    elif profile=='mixed':seq=[i for i in range(4) for _ in range(24)]+list(range(4,36))
    elif profile=='short':seq=[i for i in range(64) for _ in range(2)]
    elif profile=='burst':
        ids=list(range(32));r.shuffle(ids);seq=[i for i in ids for _ in range(4)]
    else:raise ValueError(profile)
    if profile!='burst':r.shuffle(seq)
    ids={i:hashlib.sha256(f'{seed}:{i}'.encode()).digest()+(1).to_bytes(8,'big') for i in set(seq)}
    keys={i:extract(sk,j) for i,j in ids.items()};counts={i:0 for i in ids};data=[]
    for i in seq:
        counter=counts[i];counts[i]+=1
        msg=b'V3-SCREEN'+ids[i]+counter.to_bytes(8,'big')+r.randbytes(200)
        data.append((ids[i],counter,msg,sign(keys[i],msg)))
    return pk,data

def calibration(out):
    out.mkdir(parents=True);blocks=[]
    for seed in range(82001,82006):
        pk,data=material(seed,'stable_fit');i,_,m,s=data[0]
        qv=Fixed(pk);tv=Fixed(pk,'miller');qp=QPool(qv);q=qv.build(i);qp.put(i,q,1)
        provider=Incremental(tv,qp);cache=CacheV3(provider);table=provider.build(i,C.create_string_buffer(tv.q_size))
        for _ in range(32):assert qv.verify(i,m,s,q)
        rng=random.Random(seed);samples=[]
        for n in range(48):
            ops=['q','table','build'];rng.shuffle(ops)
            for op in ops:
                if op=='q':fn=lambda:qv.verify(i,m,s,q)
                elif op=='table':fn=lambda:tv.verify(i,m,s,table)
                else:
                    def fn():
                        slot=cache._new(cache.slots[0],i,n,1000);cache._build(i,slot,1000);return True
                val,c,w=measure(fn);assert val
                samples.append({'index':n,'op':op,'cpu_ns':c,'wall_ns':w})
        means={op:S.mean(x['cpu_ns'] for x in samples if x['op']==op) for op in ('q','table','build')}
        blocks.append(means);dump(out/f'{seed}.json',{'means':means,'samples':samples,'public':pk.hex(),
            'probe':[i.hex(),m.hex(),s.hex()]});qv.close();tv.close()
    deltas=[b['q']-b['table'] for b in blocks];delta=S.mean(deltas);cost=S.mean(b['build'] for b in blocks)
    ci=boot(deltas);result={'blocks':blocks,'delta_ns':delta,'delta_ci95_ns':ci,'B_ns':cost,
        'threshold':math.ceil(cost/delta) if ci[0]>0 else None,'proceed':ci[0]>0}
    dump(out/'summary.json',result);return result

def run_method(pk,data,method,threshold):
    qv=Fixed(pk);tv=Fixed(pk,'miller');qp=QPool(qv);provider=Incremental(tv,qp)
    c=Cache(provider,'siap',65536,threshold) if method=='legacy' else CacheV3(provider,'cold' if method=='qonly' else method,65536,threshold)
    ledger=Ledger(65536,256);events=[];thits=qhits=0
    start=time.thread_time_ns();wall=time.monotonic_ns()
    for j,(i,counter,msg,sig) in enumerate(data):
        cs=time.thread_time_ns();c.expire(j)
        previous=qp.find(i);qhit=previous is not None;qhits+=int(qhit)
        token=c.prepare(i,qhit,j,100000,previous.last if qhit else 0) if method!='legacy' else None
        q=previous.q if qhit else qv.build(i,qp.scratch)
        t=c.lookup(i);hit=t is not None;thits+=int(hit)
        assert (tv.verify(i,msg,sig,t) if hit else qv.verify(i,msg,sig,q))
        status,fresh=ledger.consume(i,counter,100000,j);assert status=='consumed'
        qp.put(i,q,j+1)
        if method=='legacy':c.accepted(i,fresh,hit,j+1,100000)
        else:c.accepted(i,fresh,hit,j+1,100000,token)
        slot=c.find(i)
        events.append({'index':j,'id':i.hex(),'counter':counter,'accepted':True,'qhit':qhit,'hit':hit,
            'token':None if token is None else [token[1],token[2]],
            'slot_state':None if slot is None else int(slot.state),
            'slot_count':None if slot is None else int(slot.count),
            'builds':c.builds,'charged':getattr(c,'charged_events',None),
            'cpu_ns':time.thread_time_ns()-cs})
    cpu=time.thread_time_ns()-start;wall=time.monotonic_ns()-wall
    assert all(ledger.consume(i,n,100000,1000)[0]=='replay_reject' for i,n,_,_ in data)
    result={'method':method,'count':len(data),'cpu_ns':cpu,'wall_ns':wall,'cpu_per_message_ns':cpu/len(data),
        'q_hits':qhits,'table_hits':thits,'q_payload_bytes':qp.bytes,'r_payload_bytes':ledger.allocated_bytes,
        'a':c.metrics(),'replays_rejected':len(data),'peak_process_rss_kib':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss}
    assert result['q_payload_bytes']<=65536 and result['a']['a_allocated_bytes']<=65536
    qv.close();tv.close();ledger.close();return result,events

def worker(out,seed,threshold,orders):
    out.mkdir(parents=True);pk,data=material(seed,'stable_fit');i,_,m,s=data[0];v=Fixed(pk);q=v.build(i)
    for _ in range(64):assert v.verify(i,m,s,q)
    def sentinel():return S.mean(measure(lambda:v.verify(i,m,s,q))[1] for _ in range(16))
    before=sentinel();runs=[]
    for profile in orders['profiles']:
        pk,data=material(seed*17+PROFILES.index(profile),profile)
        ip=out/f'{profile}-input.json';dump(ip,{'public':pk.hex(),'messages':[[i.hex(),n,m.hex(),s.hex()] for i,n,m,s in data]})
        for method in orders['methods']:
            result,events=run_method(pk,data,method,threshold)
            result.update(profile=profile,input_sha256=sha(ip),seed=seed)
            dump(out/f'{profile}-{method}.json',events);runs.append(result)
    after=sentinel();v.close()
    dump(out/'summary.json',{'seed':seed,'runs':runs,'orders':orders,'sentinel_before_ns':before,
        'sentinel_after_ns':after,'drift_flag':abs(after/before-1)>.05,'relative_drift':after/before-1})

def analyze(out):
    blocks=[read(p) for p in sorted((out/'confirm').glob('*/summary.json'))];assert len(blocks)==21
    comparisons={};agg={};flat=[]
    for profile in PROFILES:
        rows=[{r['method']:r for r in b['runs'] if r['profile']==profile} for b in blocks]
        agg[profile]={m:{'cpu_ms':S.mean(r[m]['cpu_per_message_ns'] for r in rows)/1e6,
                        'hits':S.mean(r[m]['table_hits'] for r in rows),
                        'builds':S.mean(r[m]['a']['builds'] for r in rows),
                        'build_ms':S.mean(r[m]['a']['build_cpu_ns'] for r in rows)/1e6,
                        'capacity':rows[0][m]['a']['a_capacity'],
                        'a_bytes':rows[0][m]['a']['a_allocated_bytes']} for m in METHODS}
        for ref in BASELINES+['legacy','fastest']:
            x=[]
            for row in rows:
                z=min(row[m]['cpu_per_message_ns'] for m in BASELINES) if ref=='fastest' else row[ref]['cpu_per_message_ns']
                x.append((z-row['siap']['cpu_per_message_ns'])/z)
            comparisons[f'{profile}:siap_vs_{ref}']={'saving':S.mean(x),'ci95':boot(x),'block_savings':x}
        for b,row in zip(blocks,rows):
            for m,r in row.items():flat.append({'seed':b['seed'],'profile':profile,'method':m,'cpu_ms':r['cpu_per_message_ns']/1e6,
                'wall_ms':r['wall_ns']/r['count']/1e6,'hits':r['table_hits'],'builds':r['a']['builds'],
                'build_ms':r['a']['build_cpu_ns']/1e6,'a_bytes':r['a']['a_allocated_bytes'],'a_capacity':r['a']['a_capacity']})
    gate=(comparisons['mixed:siap_vs_fastest']['ci95'][0]>.05 and
          all(comparisons[p+':siap_vs_fastest']['ci95'][0]>=-.01 for p in ['stable_fit','stable_pressure']))
    result={'blocks':len(blocks),'timed_verifications':sum(r['count'] for b in blocks for r in b['runs']),
            'drift_blocks':[b['seed'] for b in blocks if b['drift_flag']],
            'aggregates':agg,'comparisons':comparisons,'investment_gate_passed':gate}
    dump(out/'analysis.json',result)
    with (out/'runs.csv').open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(flat[0]));w.writeheader();w.writerows(flat)
    return result

def campaign(out):
    out.mkdir(parents=True,exist_ok=False)
    paths=[HERE/'PLAN.md',HERE/'run.py',ROOT/'siap/cache_v3.py',ROOT/'siap/cache.py',ROOT/'siap/receiver.py',ROOT/'siap/state.py',
           ROOT/'siap/crypto.py',ROOT/'siap/control.py',ROOT/'siap/wire.py',ROOT/'tests/test_core.py',
           ROOT/'experiments/minscreen_20261020/screen.py',
           ROOT/'tests/test_cache_v3.py',ROOT/'experiments/kernel_screen_20261021/kernel.c',ROOT/'experiments/kernel_screen_20261021/kernel.so',
           ROOT/'experiments/kernel_screen_20261021/screen.py',ROOT/'experiments/minscreen_20261020/bridge.so',ROOT/'build/libsiap_crypto.so',
           ROOT/'build/vendor/gmssl-src/bin/libgmssl.so.3.3']
    hashes={str(p.relative_to(ROOT)):sha(p) for p in paths};dump(out/'frozen_sources.json',hashes)
    snapshot=out/'sources';snapshot.mkdir()
    for p in paths:
        dest=snapshot/p.relative_to(ROOT);dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(p.read_bytes())
    dump(out/'environment.json',{'platform':platform.platform(),'python':sys.version,'affinity':sorted(os.sched_getaffinity(0)),
                                'cpuinfo':Path('/proc/cpuinfo').read_text(),'started_utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())})
    cal=calibration(out/'calibration');print('calibration',json.dumps(cal),flush=True)
    if not cal['proceed']:return
    orders=[];rng=random.Random(83000)
    for cycle in range(3):
        base=METHODS[:];rng.shuffle(base)
        for shift in range(7):
            n=cycle*7+shift;p=n%len(PROFILES)
            orders.append({'methods':base[shift:]+base[:shift],'profiles':PROFILES[p:]+PROFILES[:p]})
    dump(out/'frozen_orders.json',orders)
    for n,order in enumerate(orders):
        target=out/'confirm'/str(83001+n)
        subprocess.run([sys.executable,str(HERE/'run.py'),'worker',str(target),'--seed',str(83001+n),
                        '--threshold',str(cal['threshold']),'--orders',json.dumps(order)],check=True,cwd=ROOT)
        print('completed',n+1,'/21',flush=True)
    assert all(sha(ROOT/p)==h for p,h in hashes.items()),'source changed during confirmation'
    result=analyze(out);print('gate',result['investment_gate_passed'],flush=True)

if __name__=='__main__':
    ap=argparse.ArgumentParser();ap.add_argument('action',choices=['campaign','worker','analyze']);ap.add_argument('out',type=Path)
    ap.add_argument('--seed',type=int);ap.add_argument('--threshold',type=int);ap.add_argument('--orders');a=ap.parse_args()
    if a.action=='campaign':campaign(a.out.resolve())
    elif a.action=='worker':worker(a.out.resolve(),a.seed,a.threshold,json.loads(a.orders))
    else:analyze(a.out.resolve())
