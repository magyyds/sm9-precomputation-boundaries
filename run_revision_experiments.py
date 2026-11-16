"""Frozen reviewer-driven experiments. Reuses paired arrivals and all seeds.

Primary comparison uses newly measured mean costs. Sensitivity and empirical
resampling are explicitly distinct models. No result-dependent trace selection.
"""
from pathlib import Path
import json,csv,sys,hashlib,time,platform
from collections import defaultdict
import numpy as np
import simulate
from revision_policies import METHODS,events
ROOT=Path(__file__).resolve().parent
OUT=ROOT/'revision_results';OUT.mkdir(exist_ok=True)
CFG=json.loads((ROOT/'frozen_config.json').read_text(encoding='utf-8'))
SEEDS=CFG['seeds'];FAMS=CFG['families'];N=CFG['N']
BOOT=np.random.default_rng(811610).integers(0,30,(10000,30))
def write(name,rows):
    with (OUT/name).open('w',newline='',encoding='utf-8-sig') as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
def js(name,value): (OUT/name).write_text(json.dumps(value,ensure_ascii=False,indent=2),encoding='utf-8')
def stat(values,boot=BOOT):
    a=np.array(values,float);lo,hi=np.quantile(a[boot].mean(axis=1),[.025,.975]);return float(a.mean()),float(lo),float(hi)
def queue(arr,svc):
    c=np.cumsum(svc);before=np.r_[0,c[:-1]];soj=c+np.maximum.accumulate(np.maximum(arr-before,0))-arr
    return float(np.mean(soj<=100)*100),float(np.quantile(soj,.95))
def summarize(rows,keys,fields):
    groups=defaultdict(list)
    for r in rows:groups[tuple(r[k] for k in keys)].append(r)
    out=[]
    for k,rr in groups.items():
        rr.sort(key=lambda r:r['seed']);assert len(rr)==30 and [r['seed'] for r in rr]==SEEDS
        s=dict(zip(keys,k));s['n_seeds']=30
        for field in fields:
            v,lo,hi=stat([r[field] for r in rr]);s.update({field:v,field+'_lo':lo,field+'_hi':hi})
        out.append(s)
    return out
def dynamic(f,seed):
    rng=np.random.default_rng(np.random.SeedSequence([seed,811616,0 if f=='rotating_hotspots' else 1]))
    period=256 if f=='rotating_hotspots' else 512
    ids=rng.integers(0,8,N)+8*((np.arange(N)//period)%4)
    scan=rng.random(N)<.2;ids[scan]=10000+np.arange(N)[scan]
    gaps=rng.exponential(1,N)
    if f=='bursty_migration':gaps*=np.where(np.arange(N)%128<32,.1,1.3)
    gaps[0]=0
    return ids,gaps
def calibration():
    processes=[json.loads(p.read_text(encoding='utf-8')) for p in sorted((ROOT/'revision_measurements').glob('process_*.json'))]
    assert len(processes)==12 and len({r['pid'] for r in processes})==12
    boot=np.random.default_rng(811611).integers(0,12,(10000,12));pvals={}
    for m in METHODS:
        a=[np.mean([x['net_ns_per_message'] for x in r['policy'] if x['method']==m])/1e6 for r in processes]
        v,lo,hi=stat(a,boot);pvals[m]={'mean_ms':v,'lo_ms':lo,'hi_ms':hi,'process_values_ms':a}
    vals={k:[r['crypto_means'][k]/1e6 for r in processes] for k in ['q','table','build']}
    vals['delta']=[q-t for q,t in zip(vals['q'],vals['table'])]
    c={k:dict(zip(['mean_ms','lo_ms','hi_ms'],stat(v,boot))) for k,v in vals.items()}
    assert c['delta']['lo_ms']>0 and all(pvals[m]['mean_ms']>=0 for m in METHODS)
    pool={k:np.array([s['cpu_ns']/1e6 for r in processes for s in r['crypto_samples'] if s['op']==k]) for k in ['q','table','build']}
    report={'processes':12,'timings_per_operation':len(pool['q']),'crypto':c,'policy':pvals,'isolated_operations':[r['isolated_operations_ns'] for r in processes],'bootstrap_resamples':10000,'bootstrap_seed':811611,'replication_unit':'independent software process on one host','policy_measurement':'Complete reference policy loop minus Q-only no-op traversal; equal mean across six workload families; isolated operation timings are not summed.'}
    js('measurement_summary.json',report)
    return c['q']['mean_ms'],c['delta']['mean_ms'],c['build']['mean_ms'],{m:pvals[m]['mean_ms'] for m in METHODS},pool
def main():
    start=time.perf_counter();q,d,b,p,pool=calibration()
    frozen={'seeds':SEEDS,'n_messages':N,'methods':METHODS,'primary_slots':[2,4,8],'primary_loads':[.5,.8,.95,1,1.05],
        'primary_costs_ms':dict(q=q,delta=d,build=b,policy=p),'frequency_window':1024,
        'dynamic_families':{'rotating_hotspots':'8 hot IDs switch cyclically among four disjoint sets every 256 messages; 20% unique scans','bursty_migration':'same mixed construction, switch every512; within each128 messages,32 gaps scaled0.1 and96 scaled1.3; expected gap scale=1'},
        'empirical_service':'Independently sample pooled q/table/build operation timings with replacement; share the three per-event arrays across methods; no assertion that q and table were measured as paired calls. Arrivals remain tied to mean q.',
        'sensitivity_delta_scales':[.5,1,1.5],'sensitivity_build_scales':[.5,1,1.5],'sensitivity_common_p_ms':[0,.01,.05,.10],
        'bootstrap_seed':811610,'bootstrap_resamples':10000,'replication_unit':'seed','ci_scope':'Conditional on measured mean costs or the empirical timing pool. Process-level calibration CIs reported separately.',
        'metadata':'Optional table capacities equal; metadata excluded and separately counted; not byte-matched cache comparison.',
        'boundary':'Exact H*delta - NB*B - N*p for cost-independent admission decisions; empirical policy envelope, not an optimal online policy.'}
    js('revision_config.json',frozen)
    (ROOT/'revision_traces').mkdir(exist_ok=True)
    inputs={};masks={};oldchecks=0
    for seed in SEEDS:
        for fam in FAMS+['rotating_hotspots','bursty_migration']:
            if fam in FAMS:
                with np.load(ROOT/'traces'/f'{seed}_{fam}.npz') as z:ids=z['ids'].copy();gaps=z['unit_gaps'].copy()
            else:
                ids,gaps=dynamic(fam,seed);np.savez_compressed(ROOT/'revision_traces'/f'{seed}_{fam}.npz',ids=ids,unit_gaps=gaps)
            inputs[seed,fam]=(ids,gaps)
            for k in ([2,4,8] if fam in FAMS else [8]):
                for m in METHODS:
                    h,bu,u,meta=events(ids,m,k);h=np.array(h,float);bu=np.array(bu,float);masks[seed,fam,k,m]=(h,bu,u,meta)
                    assert max(np.cumsum(bu-h*0))>=0 and h.sum()+np.count_nonzero(1-h)==N
                    if fam in FAMS and m in CFG['methods']:
                        th=CFG['methods'].index(m);s,hh,bb,uu=simulate.costs(ids,k,th,CFG['q_ms'],CFG['delta_ms'],CFG['build_ms'],CFG['policy_ms'])
                        reconstruct=CFG['q_ms']+(.01 if m!='Q-only' else 0)-h*CFG['delta_ms']+bu*CFG['build_ms']
                        assert np.allclose(s,reconstruct,rtol=0,atol=1e-12) and (hh,bb,uu)==(int(h.sum()),int(bu.sum()),u);oldchecks+=1
    print('Policy equivalence checks',oldchecks,flush=True)
    primary=[]
    for seed in SEEDS:
        for fam in FAMS:
            _,gaps=inputs[seed,fam]
            for k in [2,4,8]:
                for rho in [.5,.8,.95,1,1.05]:
                    arr=np.cumsum(gaps*q/rho);base,base95=queue(arr,np.full(N,q))
                    for m in METHODS:
                        h,bu,u,meta=masks[seed,fam,k,m];svc=q+p[m]-h*d+bu*b;deadline,tail=queue(arr,svc)
                        assert np.isclose(svc.sum(),N*(q+p[m])-h.sum()*d+bu.sum()*b)
                        primary.append(dict(seed=seed,family=fam,slots=k,rho=rho,method=m,cpu_saving_pct=100*(q-svc.mean())/q,ontime_pct=deadline,difference_pp=deadline-base,p95_sojourn_ms=tail,hits=int(h.sum()),builds=int(bu.sum()),unused_builds=u,metadata_entries_peak=meta,policy_ms=p[m],service_ms=float(svc.mean()),p_critical_ms=float((h.sum()*d-bu.sum()*b)/N)))
    write('primary_runs.csv',primary)
    summ=summarize(primary,['family','slots','rho','method'],['cpu_saving_pct','ontime_pct','difference_pp','p95_sojourn_ms','hits','builds','unused_builds','p_critical_ms'])
    write('primary_summary.csv',summ)
    print('Primary matrix',len(primary),flush=True)
    # Direct paired comparisons against both established-history and frequency controls.
    lookup={(r['seed'],r['family'],r['slots'],r['rho'],r['method']):r for r in primary}
    comparisons=[]
    for f in FAMS:
        for rho in [.8,.95,1.05]:
            for m in ['Second-hit','Third-hit']:
                for ref in ['Immediate','LRU-2','Window-Frequency']:
                    for field in ['cpu_saving_pct','ontime_pct']:
                        x=[lookup[s,f,8,rho,m][field]-lookup[s,f,8,rho,ref][field] for s in SEEDS]
                        v,lo,hi=stat(x);comparisons.append(dict(family=f,rho=rho,method=m,reference=ref,metric=field,paired_difference=v,lo=lo,hi=hi))
    write('paired_baseline_comparisons.csv',comparisons)
    robust=[]
    for seed in SEEDS:
        for fi,fam in enumerate(['mixed_scan','shift8','rotating_hotspots','bursty_migration']):
            _,gaps=inputs[seed,fam];rng=np.random.default_rng(np.random.SeedSequence([seed,811617,fi]))
            draws={op:rng.choice(pool[op],N,replace=True) for op in pool}
            np.savez_compressed(ROOT/'revision_traces'/f'{seed}_{fam}_service.npz',**draws)
            for model in ['fixed','empirical']:
                qc=np.full(N,q) if model=='fixed' else draws['q'];tc=np.full(N,q-d) if model=='fixed' else draws['table'];bc=np.full(N,b) if model=='fixed' else draws['build']
                for rho in [.8,.95,1.05]:
                    arr=np.cumsum(gaps*q/rho);base,_=queue(arr,qc)
                    for m in METHODS:
                        h,bu,u,meta=masks[seed,fam,8,m];svc=np.where(h>0,tc,qc)+bu*bc+p[m];v,tail=queue(arr,svc)
                        robust.append(dict(seed=seed,family=fam,service_model=model,rho=rho,method=m,ontime_pct=v,difference_pp=v-base,cpu_saving_pct=100*(qc.mean()-svc.mean())/qc.mean(),p95_sojourn_ms=tail))
    write('robustness_runs.csv',robust);write('robustness_summary.csv',summarize(robust,['family','service_model','rho','method'],['ontime_pct','difference_pp','cpu_saving_pct','p95_sojourn_ms']))
    print('Dynamic / empirical matrix',len(robust),flush=True)
    joint=[]
    for seed in SEEDS:
        for fam in FAMS:
            _,gaps=inputs[seed,fam]
            for rho in [.95,1.05]:
                arr=np.cumsum(gaps*q/rho);base,_=queue(arr,np.full(N,q))
                for m in METHODS[1:]:
                    h,bu,_,_=masks[seed,fam,8,m]
                    for ds in [.5,1,1.5]:
                        for bs in [.5,1,1.5]:
                            for common_p in [0,.01,.05,.10]:
                                svc=q+common_p-h*d*ds+bu*b*bs;v,tail=queue(arr,svc)
                                joint.append(dict(seed=seed,family=fam,rho=rho,method=m,delta_scale=ds,build_scale=bs,policy_ms=common_p,cpu_saving_pct=100*(q-svc.mean())/q,difference_pp=v-base,ontime_pct=v))
    write('joint_sensitivity_runs.csv',joint);write('joint_sensitivity_summary.csv',summarize(joint,['family','rho','method','delta_scale','build_scale','policy_ms'],['cpu_saving_pct','difference_pp','ontime_pct']))
    print('Joint sensitivity',len(joint),flush=True)
    window=[]
    for seed in SEEDS:
        for fam in ['mixed_scan','shift8','rotating_hotspots','bursty_migration']:
            ids,gaps=inputs[seed,fam]
            for w in [128,512,1024,4096]:
                hh,bb,_,_=events(ids,'Window-Frequency',8,w);h=np.array(hh);bu=np.array(bb)
                svc=q+p['Window-Frequency']-h*d+bu*b
                for rho in [.95,1.05]:
                    arr=np.cumsum(gaps*q/rho);v,tail=queue(arr,svc);base,_=queue(arr,np.full(N,q))
                    window.append(dict(seed=seed,family=fam,window=w,rho=rho,cpu_saving_pct=100*(q-svc.mean())/q,difference_pp=v-base))
    write('frequency_window_runs.csv',window);write('frequency_window_summary.csv',summarize(window,['family','window','rho'],['cpu_saving_pct','difference_pp']))
    # Exact break-even boundary for every main workload, capacity and policy.
    boundaries=[]
    for r in summ:
        if r['rho']!=.95:continue
        h,nb=r['hits'],r['builds'];pp=p[r['method']]
        boundaries.append(dict(family=r['family'],slots=r['slots'],method=r['method'],hits=h,builds=nb,policy_ms=pp,p_critical_ms=(h*d-nb*b)/N,build_critical_ms=(h*d-N*pp)/nb if nb else None,delta_critical_ms=(nb*b+N*pp)/h if h else None))
    js('break_even_boundaries.json',boundaries)
    # Cost-only optimistic bound: unlimited table residency and zero policy cost.
    optimistic=[]
    for seed in SEEDS:
        for fam in FAMS:
            ids,_=inputs[seed,fam];counts=np.unique(ids,return_counts=True)[1]
            gain=np.maximum((counts-1)*d-b,0).sum()
            optimistic.append(dict(seed=seed,family=fam,optimistic_saving_pct=100*gain/(N*q)))
    write('optimistic_cost_bound.csv',optimistic)
    tests={}
    for th,m in enumerate(CFG['methods'][1:],1):
        h,bu,u,_=events([1,1,1,1],m,1);tests['contiguous_'+m]=sum(h)==4-th and sum(bu)==1
    h,bu,u,_=events([1,2,1], 'Window-Frequency',1,8);tests['frequency_rejects_one_off']=list(h)==[False,False,True] and sum(bu)==1
    h,bu,u,_=events([1,2,1,3,1], 'LRU-2',2);tests['lru2_retains_twice_used']=h[-1] and sum(bu)==3
    tiny=np.array([0,1,2,4.]);svc=np.array([2,1,3,1.]);tests['queue_scalar_matches']=abs(queue(tiny,svc)[1]-simulate.queue(tiny,svc,100)['p95_sojourn_ms'])<1e-10
    tests['exact_archive_policy_equivalence']=oldchecks==2160
    tests['all_primary_cost_identities']=True
    tests['qonly_saving_zero']=all(abs(r['cpu_saving_pct'])<1e-10 and r['difference_pp']==0 for r in primary if r['method']=='Q-only')
    assert all(tests.values()),tests
    js('revision_audit.json',{'passed':True,'tests':tests,'primary_runs':len(primary),'robustness_runs':len(robust),'joint_sensitivity_runs':len(joint),'window_runs':len(window),'optimistic_bound_evaluations':len(optimistic),'new_identity_traces':60,'empirical_service_draw_records':120,'old_policy_equivalence_checks':oldchecks,'wall_seconds':time.perf_counter()-start,'python':sys.version,'numpy':np.__version__,'platform':platform.platform(),'source_sha256':{f:hashlib.sha256((ROOT/f).read_bytes()).hexdigest() for f in ['revision_policies.py','run_revision_experiments.py','measure_revision.py']}})
    print('Finished',time.perf_counter()-start,flush=True)
if __name__=='__main__':main()
