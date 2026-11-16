from pathlib import Path
import json,hashlib,csv,sys,time
from collections import OrderedDict
import numpy as np
ROOT=Path(__file__).resolve().parents[2]
OUT=Path(__file__).resolve().parent
CAL=OUT/'calibration'
SEEDS=list(range(271101,271131))
FAMILIES=['stable8','pressure64','short2','bursts4','mixed_scan','shift8']
METHODS=['Q-only','Immediate','Second-hit','Third-hit']
CONFIG={'N':4096,'seeds':SEEDS,'families':FAMILIES,'slots':[2,4,8],'rho':[0.5,0.8,0.95,1.0,1.05],'methods':METHODS,'deadline_ms':100.0,'policy_ms':0.01,'model':'FCFS infinite-buffer finite-horizon verification queue; no radio; all inputs valid; no expiration; no deadline dropping','time_unit':'simulated milliseconds'}
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def writecsv(path,rows):
    with path.open('w',newline='',encoding='utf-8-sig') as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
def workload(family,n,rng):
    if family=='stable8':return rng.integers(0,8,n)
    if family=='pressure64':return rng.integers(0,64,n)
    if family=='short2':return rng.permutation(np.repeat(np.arange(n//2),2))
    if family=='bursts4':return np.repeat(rng.permutation(np.arange(n//4)),4)
    if family=='mixed_scan':
        ids=rng.integers(0,8,n); scan=rng.random(n)<0.2
        ids[scan]=1000+np.arange(n)[scan]
        return ids
    if family=='shift8':return np.r_[rng.integers(0,8,n//2),rng.integers(8,16,n-n//2)]
    raise ValueError(family)
def costs(ids,slots,threshold,q,delta,build,overhead):
    n=len(ids); service=np.full(n,q,dtype=float)
    if threshold==0:return service,0,0,0
    service+=overhead;cache=OrderedDict();history={}; hits=builds=unused=0
    # Ideal exact candidate history is deliberately excluded from the slot budget.
    # It is shared by all thresholds, unbounded within this finite trace, not TinyLFU or SIAP.
    for i,key in enumerate(ids):
        key=int(key)
        if key in cache:
            hits+=1;service[i]-=delta;cache[key]+=1;cache.move_to_end(key)
        else:
            history[key]=min(threshold,history.get(key,0)+1)
            if history[key]>=threshold:
                if len(cache)==slots:
                    _,uses=cache.popitem(last=False);unused+=int(uses==0)
                cache[key]=0;service[i]+=build;builds+=1
    unused+=sum(v==0 for v in cache.values())
    return service,hits,builds,unused
def queue(arr,service,deadline):
    # Departure recursion equivalent to a one-server discrete-event simulation.
    done=np.empty(len(arr)); end=0.
    for i,(a,s) in enumerate(zip(arr,service)):
        end=max(end,a)+s;done[i]=end
    sojourn=done-arr
    return {'mean_sojourn_ms':float(sojourn.mean()),'p95_sojourn_ms':float(np.quantile(sojourn,.95)),
            'ontime_pct':float((sojourn<=deadline).mean()*100),'end_backlog_ms':float(done[-1]-arr[-1])}
def audit(q,d,b):
    checks={}
    for th in [1,2,3]:
        s,h,c,u=costs([1,1,1,1],1,th,q,d,b,0)
        checks[f'contiguous4_threshold{th}']=h==4-th and c==1 and u==0 and np.isclose(s.sum(),4*q+b-(4-th)*d)
    s,h,c,u=costs([1,1],1,2,q,d,b,0);checks['second_hit_short_build_without_reuse']=(h,c,u)==(0,1,1)
    s,h,c,u=costs([1,1],1,3,q,d,b,0);checks['third_hit_short_no_build']=(h,c,u)==(0,0,0)
    checks['queue_reference']=np.isclose(queue(np.array([0.,1.,2.]),np.array([2.,2.,2.]),3)['mean_sojourn_ms'],3)
    checks['zero_gain_zero_build']=np.allclose(costs([1,2,1,2],1,1,q,0,0,0)[0],q)
    checks['qonly_constant']=np.allclose(costs([1,2,1],1,0,q,d,b,0)[0],q)
    checks['eviction_unused_accounting']=costs([1,2,3],1,1,q,d,b,0)[1:]==(0,3,3)
    # Independent scalar recurrence compared against event-list FCFS implementation.
    arrival=np.array([0.,0.,7.,7.1]);service=np.array([2.,3.,1.,4.])
    dep=[];clock=0.
    for a,s in zip(arrival,service):
        if clock<a:clock=a
        clock+=s;dep.append(clock-a)
    checks['queue_independent_example']=np.isclose(queue(arrival,service,4)['p95_sojourn_ms'],np.quantile(dep,.95))
    assert all(checks.values()),checks
    return {k:bool(v) for k,v in checks.items()}
def main():
    start=time.perf_counter()
    records=[json.loads((CAL/f'{s}.json').read_text())['means'] for s in range(90001,90006)]
    q=float(np.mean([r['q'] for r in records])/1e6)
    summary=json.loads((CAL/'summary.json').read_text());delta=summary['delta_ns']/1e6;build=summary['B_ns']/1e6
    config={**CONFIG,'q_ms':q,'delta_ms':delta,'build_ms':build,
            'calibration_provenance':{'calibration/'+p.name:sha(p) for p in CAL.glob('*.json')},
            'calibration_note':'Archived 2026-10-22 five-group single-process CPU calibration; fixed parameters here; no new hardware measurement; CI conditional on calibration.',
            'candidate_history':'Exact saturated per-identity counts persist after table eviction; finite trace dictionary not included in table slots. Not a byte-matched SIAP or TinyLFU experiment.',
            'trace_order':'Same identity trace and unit-exponential interarrivals across methods, slots, and rho in each seed/family. Cache starts empty each run. First arrival at zero.'}
    (OUT/'frozen_config.json').write_text(json.dumps(config,indent=2),encoding='utf-8')
    checks=audit(q,delta,build)
    rows=[];trace_hashes=[];sensitivity=[]
    traces=OUT/'traces';traces.mkdir(exist_ok=True)
    for seed in SEEDS:
        for fidx,family in enumerate(FAMILIES):
            rng=np.random.default_rng(np.random.SeedSequence([seed,fidx]))
            ids=workload(family,CONFIG['N'],rng);gaps=rng.exponential(1,CONFIG['N']);gaps[0]=0.
            tp=traces/f'{seed}_{family}.npz';np.savez_compressed(tp,ids=ids,unit_gaps=gaps)
            trace_hashes.append({'seed':seed,'family':family,'sha256':sha(tp)})
            for slots in CONFIG['slots']:
                for th,method in enumerate(METHODS):
                    svc,h,b,u=costs(ids,slots,th,q,delta,build,CONFIG['policy_ms'])
                    assert np.isclose(svc.sum(),len(ids)*(q+(CONFIG['policy_ms'] if th else 0))+b*build-h*delta)
                    for rho in CONFIG['rho']:
                        arr=np.cumsum(gaps*q/rho)
                        rows.append({'seed':seed,'family':family,'slots':slots,'rho':rho,'method':method,'n':len(ids),
                                     'service_ms':float(svc.mean()),'cpu_saving_pct':float(100*(q-svc.mean())/q),
                                     'hits':h,'builds':b,'unused_builds':u,**queue(arr,svc,CONFIG['deadline_ms'])})
                    if slots==8:
                        for ds,bs,ov in [(0.5,1,.01),(1.5,1,.01),(1,.5,.01),(1,1.5,.01),(1,1,0),(1,1,.05),(1,1,.1)]:
                            s2,h2,b2,u2=costs(ids,slots,th,q,delta*ds,build*bs,ov)
                            sensitivity.append({'seed':seed,'family':family,'method':method,'delta_scale':ds,'build_scale':bs,'policy_ms':ov,'saving_pct':float(100*(q-s2.mean())/q)})
        print(f'Completed seed {seed}',flush=True)
    writecsv(OUT/'run_metrics.csv',rows);writecsv(OUT/'sensitivity.csv',sensitivity)
    (OUT/'trace_manifest.json').write_text(json.dumps(trace_hashes,indent=2))
    # Seed is the replication unit. Percentile CIs are marginal descriptive Monte Carlo intervals.
    boot=np.random.default_rng(271100).integers(0,len(SEEDS),(10000,len(SEEDS)))
    summary_rows=[]
    for fam in FAMILIES+['all_equal']:
        for slots in CONFIG['slots']:
            for rho in CONFIG['rho']:
                for method in METHODS:
                    rr=[r for r in rows if (fam=='all_equal' or r['family']==fam) and r['slots']==slots and r['rho']==rho and r['method']==method]
                    o={'family':fam,'slots':slots,'rho':rho,'method':method,'n_seeds':len(SEEDS)}
                    for field in ['service_ms','cpu_saving_pct','p95_sojourn_ms','ontime_pct','hits','builds','unused_builds']:
                        a=np.array([np.mean([r[field] for r in rr if r['seed']==s]) for s in SEEDS])
                        lo,hi=np.quantile(a[boot].mean(axis=1),[.025,.975])
                        o[field]=float(a.mean());o[field+'_lo']=float(lo);o[field+'_hi']=float(hi)
                    summary_rows.append(o)
    writecsv(OUT/'summary.csv',summary_rows)
    report={'checks':checks,'cost_identity_all_runs':True,'runs':len(rows),'timed_or_simulated':'simulation only','simulated_service_events':len(rows)*CONFIG['N'],
            'unique_traces':len(trace_hashes),'sensitivity_rows':len(sensitivity),'wall_seconds':time.perf_counter()-start,
            'python':sys.version,'numpy':np.__version__,'source_sha256':sha(Path(__file__)),'no_result_deletion':True}
    (OUT/'simulation_audit.json').write_text(json.dumps(report,indent=2))
    print(json.dumps(report,indent=2))
if __name__=='__main__':main()
