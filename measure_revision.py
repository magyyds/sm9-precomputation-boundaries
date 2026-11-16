"""Independent-process software calibration, no external device required.

Run under the same Linux environment as the supplied SM9 implementation:
python3 measure_revision.py --lab /path/to/sm9-v2x-lab --processes 12
The lab argument is needed only for remeasuring cryptographic paths.
"""
from pathlib import Path
import argparse,sys,subprocess,json,time,random,statistics,os,platform,hashlib,importlib.util,ctypes as C
from revision_policies import Policy,METHODS
ROOT=Path(__file__).resolve().parent

def digest(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def trace(seed,family,n=4096):
    rng=random.Random(seed)
    if family=='stable8':return [rng.randrange(8) for _ in range(n)]
    if family=='pressure64':return [rng.randrange(64) for _ in range(n)]
    if family=='short2':
        ids=list(range(n//2))*2;rng.shuffle(ids);return ids
    if family=='bursts4':return [i//4 for i in range(n)]
    if family=='shift8':return [rng.randrange(8)+(0 if j<n//2 else 8) for j in range(n)]
    return [rng.randrange(8) if rng.random()<.8 else 1000+j for j in range(n)]
def timed_loop(ids,method,repeats=12):
    start=time.thread_time_ns()
    for _ in range(repeats):
        p=Policy(method,8)
        for k in ids:p.step(k)
    return (time.thread_time_ns()-start)/(repeats*len(ids))
def worker(lab,index):
    affinity=sorted(os.sched_getaffinity(0)) if hasattr(os,'sched_getaffinity') else []
    if affinity:os.sched_setaffinity(0,{affinity[min(2,len(affinity)-1)]})
    rng=random.Random(811600+index)
    families=['stable8','pressure64','short2','bursts4','mixed_scan','shift8'];pr=[]
    for f in families:
        ids=trace(811600+index,f);order=METHODS.copy();rng.shuffle(order)
        for m in order:timed_loop(ids,m,2)
        raw={m:timed_loop(ids,m) for m in order};base=raw['Q-only']
        for m in METHODS:pr.append(dict(family=f,method=m,gross_ns_per_message=raw[m],loop_baseline_ns=base,net_ns_per_message=raw[m]-base))
    # Isolated operation timings are diagnostic, never summed into the full-path estimate.
    from collections import OrderedDict
    ids=trace(811600+index,'mixed_scan');ops={}
    for mode in ['loop','candidate_count','cache_lookup_lru']:
        history={};cache=OrderedDict((i,0) for i in range(8));start=time.thread_time_ns()
        for _ in range(32):
            for k in ids:
                if mode=='candidate_count':history[k]=min(3,history.get(k,0)+1)
                elif mode=='cache_lookup_lru':
                    if k in cache:cache.move_to_end(k)
        ops[mode]=(time.thread_time_ns()-start)/(32*len(ids))
    sys.path.insert(0,str(lab))
    # Load the retained versioned shared object explicitly; archive symlinks
    # can be unavailable when the project is stored on a Windows volume.
    C.CDLL(str(lab/'build/vendor/gmssl-src/bin/libgmssl.so.3.3'),mode=C.RTLD_GLOBAL)
    sp=importlib.util.spec_from_file_location('contract_calibration',lab/'experiments/contract_boundary_20261022/boundary.py')
    mod=importlib.util.module_from_spec(sp);sp.loader.exec_module(mod)
    pk,data=mod.material(811600+index,'stable_fit');identity,_,msg,sig=data[0]
    qv=mod.Fixed(pk);tv=mod.Fixed(pk,'miller');qp=mod.QPool(qv);q=qv.build(identity);qp.put(identity,q,1)
    provider=mod.Incremental(tv,qp);cache=mod.CacheV3(provider);table=provider.build(identity,C.create_string_buffer(tv.q_size))
    for _ in range(32):assert qv.verify(identity,msg,sig,q) and tv.verify(identity,msg,sig,table)
    samples=[]
    for j in range(64):
        order=['q','table','build'];rng.shuffle(order)
        for op in order:
            start=time.thread_time_ns();wall=time.perf_counter_ns()
            if op=='q':ok=qv.verify(identity,msg,sig,q)
            elif op=='table':ok=tv.verify(identity,msg,sig,table)
            else:
                cache._new(cache.slots[0],identity,j,100000);cache._build(identity,cache.slots[0],100000);ok=True
            elapsed=time.thread_time_ns()-start;elapsedwall=time.perf_counter_ns()-wall
            assert ok
            samples.append(dict(index=j,op=op,cpu_ns=elapsed,wall_ns=elapsedwall))
    # Verify modified messages are rejected through both software paths.
    assert not qv.verify(identity,msg+b'!',sig,q) and not tv.verify(identity,msg+b'!',sig,table)
    qv.close();tv.close()
    return dict(process_index=index,pid=os.getpid(),cpu_affinity=list(os.sched_getaffinity(0)),python=sys.version,platform=platform.platform(),policy=pr,isolated_operations_ns=ops,crypto_samples=samples,crypto_means={op:statistics.mean(s['cpu_ns'] for s in samples if s['op']==op) for op in ['q','table','build']},valid_verifications=128,altered_message_rejections=2)

if __name__=='__main__':
    a=argparse.ArgumentParser();a.add_argument('--lab',type=Path,required=True);a.add_argument('--processes',type=int,default=12);a.add_argument('--worker',type=int);o=a.parse_args()
    dest=ROOT/'revision_measurements';dest.mkdir(exist_ok=True)
    if o.worker is not None:
        r=worker(o.lab,o.worker);(dest/f'process_{o.worker:02d}.json').write_text(json.dumps(r,indent=2),encoding='utf-8')
    else:
        records=[]
        for i in range(o.processes):
            subprocess.run([sys.executable,__file__,'--lab',str(o.lab),'--worker',str(i)],check=True)
            records.append(json.loads((dest/f'process_{i:02d}.json').read_text()));print('Measured process',i+1,flush=True)
        provenance={'processes':o.processes,'crypto_timings':o.processes*192,'source_sha256':{p.name:digest(p) for p in [Path(__file__),ROOT/'revision_policies.py']},'native_sha256':digest(o.lab/'build/libsiap_crypto.so'),'environment':records[0]['platform'],'python':records[0]['python'],'affinity':records[0]['cpu_affinity'],'scope':'Independent software processes on one host, not independent machines; policy and crypto timings obtained in same WSL environment; no physical vehicle tests.'}
        (dest/'provenance.json').write_text(json.dumps(provenance,indent=2),encoding='utf-8')
