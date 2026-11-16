"""Predeclared prospective-gain screening, with shared component profiling."""
import argparse,ctypes as C,csv,hashlib,importlib.util,json,math,os,platform,random,resource
import statistics as S,subprocess,sys,time
from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1];sys.path.insert(0,str(ROOT))
spec=importlib.util.spec_from_file_location('v3screen',ROOT/'experiments/siap_v3_20261021/run.py')
prev=importlib.util.module_from_spec(spec);spec.loader.exec_module(prev)
from siap.prospective_cache import ProspectiveCache,History
from siap.cache_v3 import CacheV3
from siap.state import Ledger
Fixed,QPool,Incremental,material=prev.Fixed,prev.QPool,prev.Incremental,prev.material
dump,read,sha,measure=prev.dump,prev.read,prev.sha,prev.measure
METHODS=['qonly','lru','tinylfu','wtinylfu','twohit','siap','lfu2','gain','gain_no_victim','gain_no_cost']
BASELINES=['qonly','lru','tinylfu','wtinylfu','twohit','lfu2']
PROFILES=prev.PROFILES
def boot(xs):
    r=random.Random(85000);v=sorted(S.mean(r.choices(xs,k=len(xs))) for _ in range(10000));return [v[249],v[9749]]

def calibrate(out):
    out.mkdir();blocks=[]
    for seed in range(84001,84006):
        pk,data=material(seed,'stable_fit');i,_,m,s=data[0];qv=Fixed(pk);tv=Fixed(pk,'miller')
        qp=QPool(qv);q=qv.build(i);qp.put(i,q,1);provider=Incremental(tv,qp);cache=CacheV3(provider)
        table=provider.build(i,C.create_string_buffer(tv.q_size))
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
                value,c,w=measure(fn);assert value
                samples.append({'index':n,'op':op,'cpu_ns':c,'wall_ns':w})
        means={op:S.mean(x['cpu_ns'] for x in samples if x['op']==op) for op in ('q','table','build')}
        blocks.append(means);dump(out/f'{seed}.json',{'means':means,'samples':samples,'public':pk.hex(),'probe':[i.hex(),m.hex(),s.hex()]})
        qv.close();tv.close()
    delta=[b['q']-b['table'] for b in blocks];ci=boot(delta);cost=S.mean(b['build'] for b in blocks);avg=S.mean(delta)
    result={'blocks':blocks,'delta_ns':avg,'delta_ci95_ns':ci,'B_ns':cost,'threshold':math.ceil(cost/avg) if ci[0]>0 else None,'proceed':ci[0]>0}
    dump(out/'summary.json',result);return result

def run_method(pk,data,method,cal):
    qv=Fixed(pk);tv=Fixed(pk,'miller');qp=QPool(qv);provider=Incremental(tv,qp)
    if method in ProspectiveCache.VARIANTS:c=ProspectiveCache(provider,method,65536,cal['B_ns'],cal['delta_ns'])
    else:c=CacheV3(provider,'cold' if method=='qonly' else method,65536,cal['threshold'])
    assert c.capacity==(0 if method=='qonly' else 4)
    ledger=Ledger(65536,256);events=[];qhits=hits=0
    totals={k:0 for k in ['verify_cpu_ns','q_cpu_ns','ledger_cpu_ns','policy_with_build_cpu_ns']}
    start=time.thread_time_ns();wall=time.monotonic_ns()
    for j,(i,counter,msg,sig) in enumerate(data):
        cs=time.thread_time_ns();parts={}
        t0=time.thread_time_ns();previous=qp.find(i);qhit=previous is not None;qhits+=int(qhit)
        q=previous.q if qhit else qv.build(i,qp.scratch)
        parts['q_cpu_ns']=time.thread_time_ns()-t0
        t0=time.thread_time_ns();c.expire(j)
        token=c.prepare(i,qhit,j,100000,previous.last if qhit else 0)
        table=c.lookup(i);hit=table is not None;hits+=int(hit)
        parts['policy_with_build_cpu_ns']=time.thread_time_ns()-t0
        t0=time.thread_time_ns();ok=tv.verify(i,msg,sig,table) if hit else qv.verify(i,msg,sig,q)
        parts['verify_cpu_ns']=time.thread_time_ns()-t0;assert ok
        t0=time.thread_time_ns();status,fresh=ledger.consume(i,counter,100000,j)
        parts['ledger_cpu_ns']=time.thread_time_ns()-t0;assert status=='consumed'
        t0=time.thread_time_ns();qp.put(i,q,j+1);parts['q_cpu_ns']+=time.thread_time_ns()-t0
        t0=time.thread_time_ns();c.accepted(i,fresh,hit,j+1,100000,token)
        parts['policy_with_build_cpu_ns']+=time.thread_time_ns()-t0
        for name,value in parts.items():totals[name]+=value
        events.append({'index':j,'id':i.hex(),'counter':counter,'accepted':True,'qhit':qhit,'hit':hit,
            'builds':c.builds,'cpu_ns':time.thread_time_ns()-cs,**parts})
    cpu=time.thread_time_ns()-start;wall=time.monotonic_ns()-wall
    assert all(ledger.consume(i,n,100000,1000)[0]=='replay_reject' for i,n,_,_ in data)
    totals['policy_nonbuild_cpu_ns']=totals['policy_with_build_cpu_ns']-c.build_cpu_ns
    totals['residual_cpu_ns']=cpu-sum(totals[k] for k in ['verify_cpu_ns','q_cpu_ns','ledger_cpu_ns','policy_with_build_cpu_ns'])
    assert min(totals.values())>=0
    result={'method':method,'count':128,'cpu_ns':cpu,'wall_ns':wall,'cpu_per_message_ns':cpu/128,
        'components':totals,'q_hits':qhits,'table_hits':hits,'q_payload_bytes':qp.bytes,'r_payload_bytes':ledger.allocated_bytes,
        'a':c.metrics(),'replays_rejected':128,'peak_rss_kib':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss}
    assert max(qp.bytes,ledger.allocated_bytes,c.allocated_bytes)<=65536
    qv.close();tv.close();ledger.close();return result,events

def worker(out,seed,cal,orders):
    out.mkdir(parents=True);pk,probe=material(seed,'stable_fit');i,_,m,s=probe[0];v=Fixed(pk);q=v.build(i)
    for _ in range(64):assert v.verify(i,m,s,q)
    def sentinel():return S.mean(measure(lambda:v.verify(i,m,s,q))[1] for _ in range(16))
    before=sentinel();runs=[]
    for profile in orders['profiles']:
        pk,data=material(seed*17+PROFILES.index(profile),profile)
        ip=out/f'{profile}-input.json';dump(ip,{'public':pk.hex(),'messages':[[i.hex(),n,m.hex(),s.hex()] for i,n,m,s in data]})
        for method in orders['methods']:
            result,events=run_method(pk,data,method,cal);result.update(profile=profile,seed=seed,input_sha256=sha(ip))
            dump(out/f'{profile}-{method}.json',events);runs.append(result)
    after=sentinel();v.close();dump(out/'summary.json',{'seed':seed,'runs':runs,'orders':orders,
        'sentinel_before_ns':before,'sentinel_after_ns':after,'relative_drift':after/before-1,'drift_flag':abs(after/before-1)>.05})

def analyze(out):
    blocks=[read(p) for p in sorted((out/'confirm').glob('*/summary.json'))];assert len(blocks)==10
    comps={};aggregates={};flat=[]
    references=BASELINES+['siap','gain_no_victim','gain_no_cost','fastest']
    for profile in PROFILES+['all_five_equal_weight']:
        rows=[]
        for b in blocks:
            rows.append({m:S.mean(r['cpu_per_message_ns'] for r in b['runs'] if r['method']==m and (r['profile']==profile or profile=='all_five_equal_weight')) for m in METHODS})
        for ref in references:
            values=[]
            for row in rows:
                z=min(row[m] for m in BASELINES) if ref=='fastest' else row[ref]
                values.append((z-row['gain'])/z)
            comps[f'{profile}:gain_vs_{ref}']={'saving':S.mean(values),'ci95':boot(values),'block_savings':values}
        if profile=='all_five_equal_weight':continue
        aggregates[profile]={}
        for m in METHODS:
            rs=[r for b in blocks for r in b['runs'] if r['profile']==profile and r['method']==m]
            aggregates[profile][m]={'cpu_ms':S.mean(r['cpu_per_message_ns'] for r in rs)/1e6,
                'hits':S.mean(r['table_hits'] for r in rs),'builds':S.mean(r['a']['builds'] for r in rs),
                'build_ms':S.mean(r['a']['build_cpu_ns'] for r in rs)/1e6,
                'components_ms_per_message':{k:S.mean(r['components'][k]/128/1e6 for r in rs) for k in rs[0]['components']},
                'a_bytes':rs[0]['a']['a_allocated_bytes'],'capacity':rs[0]['a']['a_capacity'],
                'cost_rejects':S.mean(r['a'].get('cost_rejects',0) for r in rs),
                'victim_rejects':S.mean(r['a'].get('victim_rejects',0) for r in rs)}
            for r in rs:flat.append({'seed':r['seed'],'profile':profile,'method':m,'cpu_ms':r['cpu_per_message_ns']/1e6,
                'wall_ms':r['wall_ns']/128/1e6,'hits':r['table_hits'],'builds':r['a']['builds'],
                **{k:r['components'][k]/128/1e6 for k in r['components']}})
    gate=comps['mixed:gain_vs_fastest']['ci95'][0]>.05 and all(comps[p+':gain_vs_fastest']['ci95'][0]>=-.01 for p in ['stable_fit','stable_pressure'])
    ablation=all(comps['mixed:gain_vs_'+m]['ci95'][0]>0 for m in ['lfu2','gain_no_victim','gain_no_cost'])
    result={'blocks':10,'timed_verifications':sum(r['count'] for b in blocks for r in b['runs']),
        'comparisons':comps,'aggregates':aggregates,'investment_gate_passed':gate,
        'full_mechanism_attribution_passed':ablation,'paper_rewrite_allowed_by_this_experiment':gate and ablation,
        'drift_blocks':[b['seed'] for b in blocks if b['drift_flag']]}
    dump(out/'analysis.json',result)
    with (out/'runs.csv').open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(flat[0]));w.writeheader();w.writerows(flat)
    return result

def campaign(out):
    out.mkdir(parents=True,exist_ok=False)
    dependency_manifest=read(ROOT/'results/siap-v3-20261021-02/frozen_sources.json')
    paths=[ROOT/p for p in dependency_manifest]
    paths += [ROOT/'experiments/siap_v3_20261021/run.py',ROOT/'siap/prospective_cache.py',ROOT/'tests/test_prospective.py',
              HERE/'PLAN.md',HERE/'run.py',HERE/'diagnose.py',HERE/'prior_diagnosis.json']
    sources={str(p.relative_to(ROOT)):sha(p) for p in paths};dump(out/'frozen_sources.json',sources)
    for p in paths:
        dest=out/'sources'/p.relative_to(ROOT);dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(p.read_bytes())
    dump(out/'environment.json',{'platform':platform.platform(),'python':sys.version,'affinity':sorted(os.sched_getaffinity(0)),
        'cpuinfo':Path('/proc/cpuinfo').read_text(),'started_utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())})
    cal=calibrate(out/'calibration');print('calibration',json.dumps(cal),flush=True)
    if not cal['proceed']:return
    base=METHODS[:];random.Random(85000).shuffle(base)
    orders=[{'methods':base[n:]+base[:n],'profiles':PROFILES[n%5:]+PROFILES[:n%5]} for n in range(10)]
    dump(out/'frozen_orders.json',orders)
    for n,order in enumerate(orders):
        subprocess.run([sys.executable,str(HERE/'run.py'),'worker',str(out/'confirm'/str(85001+n)),
            '--seed',str(85001+n),'--calibration',str(out/'calibration/summary.json'),'--orders',json.dumps(order)],cwd=ROOT,check=True)
        print('completed',n+1,'/10',flush=True)
    assert all(sha(ROOT/p)==h for p,h in sources.items()),'source mutation'
    r=analyze(out);print('gate',r['investment_gate_passed'],'attribution',r['full_mechanism_attribution_passed'],flush=True)

if __name__=='__main__':
    ap=argparse.ArgumentParser();ap.add_argument('action',choices=['campaign','worker','analyze']);ap.add_argument('out',type=Path)
    ap.add_argument('--seed',type=int);ap.add_argument('--calibration',type=Path);ap.add_argument('--orders');a=ap.parse_args()
    if a.action=='campaign':campaign(a.out.resolve())
    elif a.action=='worker':worker(a.out.resolve(),a.seed,read(a.calibration),json.loads(a.orders))
    else:analyze(a.out.resolve())
