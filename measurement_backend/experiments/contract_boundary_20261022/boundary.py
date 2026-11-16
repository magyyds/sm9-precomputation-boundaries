"""Frozen byte-budget applicability experiment; no new cache algorithm."""
import argparse,ctypes as C,csv,hashlib,importlib.util,json,os,platform,random,shutil,statistics as S,subprocess,sys,time
from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1];sys.path.insert(0,str(ROOT))
spec=importlib.util.spec_from_file_location('prospective_screen',ROOT/'experiments/prospective_20261021/run.py')
old=importlib.util.module_from_spec(spec);spec.loader.exec_module(old)
Fixed,QPool,Incremental,material,measure=old.Fixed,old.QPool,old.Incremental,old.material,old.measure
CacheV3,Ledger=old.CacheV3,old.Ledger
dump,read,sha=old.dump,old.read,old.sha
METHODS=['qonly','twohit','tinylfu','siap'];BUDGETS=[32768,65536,131072];PROFILES=old.PROFILES

def boot(xs):
    rng=random.Random(91000);v=sorted(S.mean(rng.choices(xs,k=len(xs))) for _ in range(10000));return [v[249],v[9749]]

def calibrate(out):
    out.mkdir();blocks=[]
    for seed in range(90001,90006):
        pk,data=material(seed,'stable_fit');i,_,m,s=data[0];qv=Fixed(pk);tv=Fixed(pk,'miller')
        qp=QPool(qv);q=qv.build(i);qp.put(i,q,1);provider=Incremental(tv,qp);c=CacheV3(provider)
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
                        c._new(c.slots[0],i,n,100000);c._build(i,c.slots[0],100000);return True
                val,cpu,wall=measure(fn);assert val;samples.append(dict(index=n,op=op,cpu_ns=cpu,wall_ns=wall))
        means={op:S.mean(x['cpu_ns'] for x in samples if x['op']==op) for op in ops};blocks.append(means)
        dump(out/f'{seed}.json',dict(means=means,samples=samples,public=pk.hex(),probe=[i.hex(),m.hex(),s.hex()]))
        qv.close();tv.close()
    delta=[x['q']-x['table'] for x in blocks];ci=boot(delta);d=S.mean(delta);b=S.mean(x['build'] for x in blocks)
    import math
    cal=dict(delta_ns=d,delta_ci95_ns=ci,B_ns=b,threshold=math.ceil(b/d) if ci[0]>0 else None,proceed=ci[0]>0)
    dump(out/'summary.json',cal);return cal

def run_method(pk,data,method,budget,cal):
    qv=Fixed(pk);tv=Fixed(pk,'miller');qp=QPool(qv);provider=Incremental(tv,qp)
    c=CacheV3(provider,'cold' if method=='qonly' else method,budget,cal['threshold']);ledger=Ledger(65536,256)
    events=[];totals={k:0 for k in ['verify','q','ledger','policy']}
    start=time.thread_time_ns();wall=time.monotonic_ns()
    for j,(i,n,msg,sig) in enumerate(data):
        t=time.thread_time_ns();prev=qp.find(i);q=prev.q if prev is not None else qv.build(i,qp.scratch);parts={'q':time.thread_time_ns()-t}
        t=time.thread_time_ns();c.expire(j);token=c.prepare(i,prev is not None,j,100000,prev.last if prev is not None else 0);table=c.lookup(i);hit=table is not None;parts['policy']=time.thread_time_ns()-t
        t=time.thread_time_ns();valid=tv.verify(i,msg,sig,table) if hit else qv.verify(i,msg,sig,q);parts['verify']=time.thread_time_ns()-t;assert valid
        t=time.thread_time_ns();status,fresh=ledger.consume(i,n,100000,j);parts['ledger']=time.thread_time_ns()-t;assert status=='consumed'
        t=time.thread_time_ns();qp.put(i,q,j+1);parts['q']+=time.thread_time_ns()-t
        t=time.thread_time_ns();c.accepted(i,fresh,hit,j+1,100000,token);parts['policy']+=time.thread_time_ns()-t
        for k,v in parts.items():totals[k]+=v
        events.append(dict(index=j,id=i.hex(),counter=n,accepted=True,hit=hit,builds=c.builds,**parts))
    cpu=time.thread_time_ns()-start;wall=time.monotonic_ns()-wall
    assert all(ledger.consume(i,n,100000,1000)[0]=='replay_reject' for i,n,_,_ in data)
    totals['policy_nonbuild']=totals['policy']-c.build_cpu_ns;totals['residual']=cpu-sum(totals[k] for k in ['verify','q','ledger','policy'])
    assert min(totals.values())>=0
    r=dict(method=method,budget=budget,count=len(data),cpu_ns=cpu,wall_ns=wall,components=totals,a=c.metrics(),q_bytes=qp.bytes,r_bytes=ledger.allocated_bytes,hits=sum(e['hit'] for e in events),replays_rejected=len(data))
    assert c.allocated_bytes<=budget and qp.bytes<=65536 and ledger.allocated_bytes<=65536
    qv.close();tv.close();ledger.close();return r,events

def worker(out,seed,order,cal):
    out.mkdir(parents=True);vpk,probe=material(seed,'stable_fit');i,_,m,s=probe[0];v=Fixed(vpk);q=v.build(i)
    for _ in range(64):assert v.verify(i,m,s,q)
    def sentinel():return S.mean(measure(lambda:v.verify(i,m,s,q))[1] for _ in range(12))
    data={p:material(seed*19+PROFILES.index(p),p) for p in PROFILES}
    for p,(pk,rows) in data.items():dump(out/f'{p}-input.json',dict(public=pk.hex(),messages=[[i.hex(),n,m.hex(),s.hex()] for i,n,m,s in rows]))
    runs=[];sentinels=[]
    for p,b in order['cells']:
        before=sentinel();pk,rows=data[p];input_sha=sha(out/f'{p}-input.json')
        for method in order['methods']:
            r,ev=run_method(pk,rows,method,b,cal);r.update(profile=p,seed=seed,input_sha256=input_sha)
            dump(out/f'{p}-{b}-{method}.json',ev);runs.append(r)
        after=sentinel();sentinels.append(dict(profile=p,budget=b,before=before,after=after,drift=after/before-1,flag=abs(after/before-1)>.05))
    v.close();dump(out/'summary.json',dict(seed=seed,order=order,runs=runs,sentinels=sentinels))

def analyze(out):
    bs=[read(p) for p in sorted((out/'confirm').glob('*/summary.json'))];assert len(bs)==8
    comparisons={};accounting=[];agg={};cal=read(out/'calibration/summary.json')
    for budget in BUDGETS:
        for profile in PROFILES+['all_five_equal']:
            rows=[{m:S.mean(r['cpu_ns']/r['count'] for r in b['runs'] if r['method']==m and r['budget']==budget and (profile=='all_five_equal' or r['profile']==profile)) for m in METHODS} for b in bs]
            for target in METHODS[1:]:
                for ref in METHODS:
                    if target==ref:continue
                    xs=[(r[ref]-r[target])/r[ref] for r in rows];comparisons[f'{budget}:{profile}:{target}_vs_{ref}']=dict(saving=S.mean(xs),ci95=boot(xs))
            if profile=='all_five_equal':continue
            for method in METHODS:
                rs=[r for b in bs for r in b['runs'] if r['budget']==budget and r['profile']==profile and r['method']==method]
                agg[f'{budget}:{profile}:{method}']=dict(cpu_ms=S.mean(r['cpu_ns']/128/1e6 for r in rs),hits=S.mean(r['hits'] for r in rs),builds=S.mean(r['a']['builds'] for r in rs),capacity=rs[0]['a']['a_capacity'],a_bytes=rs[0]['a']['a_allocated_bytes'])
            for b in bs:
                rs={r['method']:r for r in b['runs'] if r['budget']==budget and r['profile']==profile};q=rs['qonly']
                for m in METHODS[1:]:
                    r=rs[m];pred=r['a']['build_cpu_ns']-r['hits']*cal['delta_ns']+r['components']['policy_nonbuild']-q['components']['policy_nonbuild'];actual=r['cpu_ns']-q['cpu_ns']
                    accounting.append(dict(seed=b['seed'],budget=budget,profile=profile,method=m,predicted_extra_ms=pred/128/1e6,measured_extra_ms=actual/128/1e6,residual_ms=(actual-pred)/128/1e6,sign_match=(pred<0)==(actual<0)))
    result=dict(blocks=8,runs=sum(len(b['runs']) for b in bs),timed_verifications=sum(r['count'] for b in bs for r in b['runs']),comparisons=comparisons,aggregates=agg,drift_cells=[dict(seed=b['seed'],**s) for b in bs for s in b['sentinels'] if s['flag']],accounting=dict(rows=len(accounting),sign_agreement=S.mean(x['sign_match'] for x in accounting),mae_ms=S.mean(abs(x['residual_ms']) for x in accounting)),scope='module CPU under fixed byte budgets, no end-to-end or ARM claim')
    dump(out/'analysis.json',result)
    with (out/'accounting.csv').open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(accounting[0]));w.writeheader();w.writerows(accounting)
    dump(out/'runs.json',[r for b in bs for r in b['runs']]);return result

def campaign(out):
    out.mkdir(parents=True,exist_ok=False)
    paths=[ROOT/p for p in read(ROOT/'results/prospective-20261021-01/frozen_sources.json')]
    paths+=list(HERE.glob('*.py'))+[HERE/'PLAN.md']
    sources={str(p.relative_to(ROOT)):sha(p) for p in paths};dump(out/'frozen_sources.json',sources)
    for p in paths:
        dest=out/'sources'/p.relative_to(ROOT);dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(p,dest)
    dump(out/'environment.json',dict(platform=platform.platform(),python=sys.version,affinity=sorted(os.sched_getaffinity(0)),cpuinfo=Path('/proc/cpuinfo').read_text()))
    cal=calibrate(out/'calibration');print('calibration',cal,flush=True)
    if not cal['proceed']:return
    cells=[(p,b) for p in PROFILES for b in BUDGETS];random.Random(91000).shuffle(cells)
    methods=METHODS[:];random.Random(91000).shuffle(methods)
    orders=[dict(cells=cells[n:]+cells[:n],methods=methods[n%4:]+methods[:n%4]) for n in range(8)];dump(out/'orders.json',orders)
    for n,o in enumerate(orders):
        subprocess.run([sys.executable,str(HERE/'boundary.py'),'worker',str(out/'confirm'/str(91001+n)),'--seed',str(91001+n),'--order',json.dumps(o),'--cal',str(out/'calibration/summary.json')],check=True,cwd=ROOT)
        print('completed',n+1,'/8',flush=True)
    assert all(sha(ROOT/p)==h for p,h in sources.items());analyze(out);print('analysis complete',flush=True)

if __name__=='__main__':
    ap=argparse.ArgumentParser();ap.add_argument('action');ap.add_argument('out',type=Path);ap.add_argument('--seed',type=int);ap.add_argument('--order');ap.add_argument('--cal',type=Path);a=ap.parse_args()
    if a.action=='campaign':campaign(a.out.resolve())
    elif a.action=='worker':worker(a.out.resolve(),a.seed,json.loads(a.order),read(a.cal))
    else:analyze(a.out.resolve())
