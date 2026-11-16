import argparse,ctypes as C,hashlib,importlib.util,itertools,json,math,os,platform,random,statistics as S,subprocess,sys,time,unittest
from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1];sys.path.insert(0,str(ROOT))
from siap.crypto import Verifier as Base,keygen,extract,sign,lib
METHODS=['q_binary','miller_binary','q_comb4','q_comb6','q_comb8','q_position4','miller_comb6']
def dump(p,x):p.write_text(json.dumps(x,indent=2),encoding='utf-8')
def read(p):return json.loads(p.read_text())
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def timing(fn):
    c=time.thread_time_ns();w=time.monotonic_ns();v=fn();return v,time.thread_time_ns()-c,time.monotonic_ns()-w
def boot(xs):
    r=random.Random(71021);a=sorted(S.mean(r.choices(xs,k=len(xs))) for _ in range(10000));return [a[249],a[9749]]
def dll():
    b=C.CDLL(str(HERE/'kernel.so'))
    specs={'lab_fixed_new':([C.c_void_p,C.c_uint,C.c_uint],C.c_void_p),
           'lab_fixed_free':([C.c_void_p],None),'lab_fixed_bytes':([C.c_void_p],C.c_size_t),
           'lab_fixed_check':([C.c_void_p,C.c_void_p,C.c_char_p],C.c_int),
           'lab_fixed_verify':([C.c_void_p,C.c_void_p,C.c_char_p,C.c_size_t,C.c_char_p,C.c_size_t,C.c_char_p,C.c_void_p,C.c_int],C.c_int)}
    for n,(a,r) in specs.items():f=getattr(b,n);f.argtypes=a;f.restype=r
    return b
B=dll();POOL={}
class Fixed:
    """One public-base table per live master-key context, shared across Q/Miller views."""
    def __init__(self,public,precompute='q'):
        if precompute not in ('q','miller'):raise ValueError('mode')
        self.public=public;self.precompute=precompute;self.closed=False
        if public not in POOL:
            v=Base(public);table=B.lab_fixed_new(v.handle,6,0)
            if not table:raise MemoryError()
            POOL[public]={'v':v,'table':table,'refs':0}
        self.shared=POOL[public];self.shared['refs']+=1
        self.q_size=lib().lab_miller_size() if precompute=='miller' else lib().lab_q_size()
    def build(self,identity,out=None):
        out=out if out is not None else C.create_string_buffer(self.q_size)
        if C.sizeof(out)<self.q_size:raise ValueError('small output')
        fn=lib().lab_build_miller if self.precompute=='miller' else lib().lab_build
        if fn(self.shared['v'].handle,identity,len(identity),out)!=1:raise ValueError('build')
        return out
    def verify(self,identity,message,signature,q=None,reference=False):
        if len(signature)!=97 or not identity:return False
        if q is not None and C.sizeof(q)<self.q_size:raise ValueError('small cache')
        v=self.shared['v']
        if reference:return v.verify(identity,message,signature,reference=True)
        return B.lab_fixed_verify(v.handle,self.shared['table'],identity,len(identity),message,len(message),signature,q,int(self.precompute=='miller'))==1
    def close(self):
        if self.closed:return
        self.closed=True;self.shared['refs']-=1
        if self.shared['refs']==0:
            B.lab_fixed_free(self.shared['table']);self.shared['v'].close();del POOL[self.public]
    def __del__(self):
        if hasattr(self,'shared'):self.close()

def make(seed):
    r=random.Random(seed);sk,pk=keygen();ids=[hashlib.sha256(f'{seed}:{i}'.encode()).digest() for i in range(8)]
    keys=[extract(sk,i) for i in ids];data=[]
    for j in range(32):
        msg=b'KERNEL-V1'+ids[j%8]+j.to_bytes(8,'big')+r.randbytes(200);sig=sign(keys[j%8],msg)
        data.append((ids[j%8],msg,sig))
    return pk,ids,data
def verify_mode(mode,v,tv,tables,qs,ts,i,msg,sig):
    miller=mode.startswith('miller');q=ts[i] if miller else qs[i]
    if mode.endswith('binary'):return (tv if miller else v).verify(i,msg,sig,q)
    name='comb6' if miller else mode[2:]
    return B.lab_fixed_verify(v.handle,tables[name],i,len(i),msg,len(msg),sig,q,int(miller))==1
def stage_worker(out,seed,order):
    out.mkdir(parents=True);pk,ids,data=make(seed);v=Base(pk);tv=Base(pk,'miller')
    qs={i:v.build(i) for i in ids};ts={i:tv.build(i) for i in ids};tables={};setup={}
    for name,w,s in [('comb4',4,0),('comb6',6,0),('comb8',8,0),('position4',4,1)]:
        t,c,wall=timing(lambda:B.lab_fixed_new(v.handle,w,s));assert t
        tables[name]=t;setup[name]={'cpu_ns':c,'wall_ns':wall,'bytes':B.lab_fixed_bytes(t)}
    dump(out/'input.json',{'public':pk.hex(),'messages':[[i.hex(),m.hex(),s.hex()] for i,m,s in data],
                         'alteration':'Odd indices append byte 0x78; even indices unchanged.'})
    runs=[]
    for method in order:
        for i,m,s in data[:8]:assert verify_mode(method,v,tv,tables,qs,ts,i,m,s)
        samples=[]
        for j,(i,msg,sig) in enumerate(data):
            actual=msg if j%2==0 else msg+b'x'
            ok,c,wall=timing(lambda:verify_mode(method,v,tv,tables,qs,ts,i,actual,sig));assert ok==(j%2==0)
            samples.append({'index':j,'accepted':ok,'cpu_ns':c,'wall_ns':wall})
        dump(out/f'{method}-samples.json',samples)
        runs.append({'method':method,'cpu_ns':S.mean(x['cpu_ns'] for x in samples),'wall_ns':S.mean(x['wall_ns'] for x in samples),'count':32})
    dump(out/'summary.json',{'seed':seed,'order':order,'runs':runs,'setup':setup,'q_bytes_per_id':v.q_size,'miller_bytes_per_id':tv.q_size})
    for t in tables.values():B.lab_fixed_free(t)
    v.close();tv.close()
def correctness(out):
    pk,ids,data=make(70000);v=Base(pk);tv=Base(pk,'miller');other=Base(pk)
    qs={i:v.build(i) for i in ids};ts={i:tv.build(i) for i in ids};tables={};checks=0
    rng=random.Random(70000);order=int('B640000002A3A6F1D603AB4FF58EC74449F2934B18EA8BEEE56EE19CD69ECF25',16)
    exps=[0,1,(1<<256)-1,order-1]+[rng.getrandbits(256) for _ in range(32)]
    for name,w,s in [('comb4',4,0),('comb6',6,0),('comb8',8,0),('position4',4,1)]:
        t=B.lab_fixed_new(v.handle,w,s);assert t;tables[name]=t
        for h in exps:assert B.lab_fixed_check(v.handle,t,h.to_bytes(32,'big'))==1;checks+=1
        assert B.lab_fixed_check(other.handle,t,bytes(32))==0;checks+=1
    for i,msg,sig in data[:8]:
        for method in METHODS:
            assert verify_mode(method,v,tv,tables,qs,ts,i,msg,sig)
            assert not verify_mode(method,v,tv,tables,qs,ts,i,msg+b'x',sig)
            assert not verify_mode(method,v,tv,tables,qs,ts,i,msg,bytes(32)+sig[32:])
            # Explicitly use the original ID-bound Q under a different supplied ID.
            if 'binary' not in method:
                t=tables['comb6' if method.startswith('miller') else method[2:]]
                assert B.lab_fixed_verify(v.handle,t,i+b'x',len(i)+1,msg,len(msg),sig,qs[i],0)==0
            checks+=3+('binary' not in method)
        assert v.verify(i,msg,sig,reference=True);assert not v.verify(i,msg+b'x',sig,reference=True);checks+=2
    for t in tables.values():B.lab_fixed_free(t)
    v.close();tv.close();other.close()
    # Exercise original receiver unit tests using optimized data/control verifiers.
    import siap.receiver as receiver
    receiver.Verifier=Fixed
    sys.path.insert(0,str(ROOT/'tests'));import test_core
    with (out/'receiver-tests.log').open('w') as f:
        result=unittest.TextTestRunner(stream=f,verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(test_core.CoreTests))
    assert result.wasSuccessful()
    dump(out/'correctness.json',{'algebra_and_signature_assertions':checks,'receiver_core_tests':result.testsRun,'passed':True,
         'scope':'Sampled equivalence and optimized-backend receiver unit tests; not a cryptographic security proof or end-to-end performance test.'})
def old_module():
    spec=importlib.util.spec_from_file_location('original_screen',ROOT/'experiments/minscreen_20261020/screen.py')
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);m.Verifier=Fixed;return m
def sources():
    files=[HERE/'screen.py',HERE/'kernel.c',HERE/'kernel.so',HERE/'PLAN.md',ROOT/'native/crypto.c',ROOT/'native/miller.c',ROOT/'siap/crypto.py',ROOT/'siap/cache.py',ROOT/'siap/state.py',ROOT/'siap/receiver.py',ROOT/'experiments/minscreen_20261020/screen.py',ROOT/'experiments/minscreen_20261020/bridge.c',ROOT/'experiments/minscreen_20261020/bridge.so',ROOT/'build/libsiap_crypto.so',ROOT/'build/vendor/gmssl-src/bin/libgmssl.so.3']
    return {str(p.relative_to(ROOT)):sha(p) for p in files}
def orchestrate(out):
    out.mkdir(parents=True,exist_ok=False);dump(out/'sources.json',sources())
    dump(out/'environment.json',{'platform':platform.platform(),'python':sys.version,'affinity':sorted(os.sched_getaffinity(0)),'cpuinfo':Path('/proc/cpuinfo').read_text()})
    correctness(out);print('CORRECTNESS_PASS',flush=True)
    rng=random.Random(71000);orders=[]
    for seed in range(71001,71025):
        order=METHODS[:];rng.shuffle(order);orders.append({'seed':seed,'order':order})
    dump(out/'stage_a_orders.json',orders)
    for o in orders:
        subprocess.run([sys.executable,__file__,'kernel_worker',str(out/'kernel'/str(o['seed'])),'--seed',str(o['seed']),'--order',','.join(o['order'])],check=True)
        print('KERNEL',o['seed'],flush=True)
    blocks=[read(p) for p in sorted((out/'kernel').glob('*/summary.json'))];analysis={'n':24,'means_ms':{},'comb6_vs':{}}
    for method in METHODS:
        analysis['means_ms'][method]=S.mean(next(r['cpu_ns'] for r in b['runs'] if r['method']==method) for b in blocks)/1e6
        values=[]
        for b in blocks:
            d={r['method']:r['cpu_ns'] for r in b['runs']};values.append(1-d['q_comb6']/d[method])
        analysis['comb6_vs'][method]={'mean_cpu_saving':S.mean(values),'ci95':boot(values)}
    analysis['setup']={m:{'mean_cpu_ms':S.mean(b['setup'][m]['cpu_ns'] for b in blocks)/1e6,'bytes':blocks[0]['setup'][m]['bytes']} for m in ['comb4','comb6','comb8','position4']}
    dump(out/'kernel_analysis.json',analysis);print('KERNEL_DONE',json.dumps(analysis),flush=True)
    cal=[]
    for seed in range(71501,71506):
        folder=out/'calibration'/str(seed);folder.mkdir(parents=True)
        subprocess.run([sys.executable,__file__,'calibration',str(folder),'--seed',str(seed)],check=True)
        cal.append(read(folder/'summary.json'))
    delta=[x['q']-x['table'] for x in cal];config={'delta_ns':S.mean(delta),'delta_ci95':boot(delta),'build_ns':S.mean(x['build'] for x in cal),'global_table_width':6}
    config['threshold']=max(1,math.ceil(config['build_ns']/config['delta_ns'])) if config['delta_ci95'][0]>0 else None
    dump(out/'frozen_calibration.json',config);print('CALIBRATION',json.dumps(config),flush=True)
    if config['threshold'] is not None:
        methods=list(itertools.permutations(['qonly','tinylfu','siap']))*3;profiles=list(itertools.permutations(['stable','mixed','short']))*3
        random.Random(72000).shuffle(methods);random.Random(72001).shuffle(profiles)
        orders=[{'seed':72001+j,'methods':methods[j],'profiles':profiles[j]} for j in range(18)]
        dump(out/'stage_b_orders.json',orders)
        for o in orders:
            folder=out/'policy'/str(o['seed']);folder.mkdir(parents=True);dump(folder/'order.json',o)
            subprocess.run([sys.executable,__file__,'policy_worker',str(folder),'--seed',str(o['seed']),'--threshold',str(config['threshold'])],check=True)
            print('POLICY',o['seed'],flush=True)
        blocks=[read(p) for p in sorted((out/'policy').glob('*/summary.json'))];answer={}
        for profile in ['stable','mixed','short']:
            result={}
            for ref in ['qonly','tinylfu','best']:
                values=[]
                for b in blocks:
                    d={r['method']:r['cpu_per_message_ns'] for r in b['runs'] if r['profile']==profile}
                    reference=min(d['qonly'],d['tinylfu']) if ref=='best' else d[ref]
                    values.append(1-d['siap']/reference)
                result[ref]={'mean_cpu_saving':S.mean(values),'ci95':boot(values)}
            result['means_ms']={m:S.mean(r['cpu_per_message_ns'] for b in blocks for r in b['runs'] if r['method']==m and r['profile']==profile)/1e6 for m in ['qonly','tinylfu','siap']}
            answer[profile]=result
        answer['n_blocks']=18;answer['timed_verifications']=sum(r['count'] for b in blocks for r in b['runs'])
        answer['gate_pass']=answer['mixed']['tinylfu']['ci95'][0]>.05 and answer['mixed']['best']['ci95'][0]>.05 and answer['stable']['best']['ci95'][0]>=-.01
        answer['drift_flags']=sum(b['drift_flag'] for b in blocks)
        dump(out/'policy_analysis.json',answer);print('POLICY_DONE',json.dumps(answer),flush=True)
    dump(out/'manifest.json',{str(p.relative_to(out)):sha(p) for p in sorted(out.rglob('*')) if p.is_file()})

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('mode',choices=['run','kernel_worker','calibration','policy_worker']);p.add_argument('out',type=Path);p.add_argument('--seed',type=int);p.add_argument('--order');p.add_argument('--threshold',type=int);a=p.parse_args()
    if a.mode=='run':orchestrate(a.out.resolve())
    elif a.mode=='kernel_worker':stage_worker(a.out,a.seed,a.order.split(','))
    elif a.mode=='calibration':old_module().calibration(a.out,a.seed)
    else:old_module().worker(a.out,a.seed,a.threshold,read(a.out/'order.json'))
