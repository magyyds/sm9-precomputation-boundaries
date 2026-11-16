"""Round-two sensitivity: workload-specific overhead and retained timing dependence."""
from pathlib import Path
import json,csv,hashlib
import numpy as np
from revision_policies import METHODS,events
from run_revision_experiments import queue,stat,summarize,SEEDS,FAMS,N
ROOT=Path(__file__).resolve().parent;OUT=ROOT/'round2_results';OUT.mkdir(exist_ok=True)
DRAW=ROOT/'round2_traces';DRAW.mkdir(exist_ok=True)
def write(name,rows):
    with (OUT/name).open('w',newline='',encoding='utf-8-sig') as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
def js(name,obj):(OUT/name).write_text(json.dumps(obj,ensure_ascii=False,indent=2),encoding='utf-8')
def read(name):return list(csv.DictReader((ROOT/'revision_results'/name).open(encoding='utf-8-sig')))
proc=[json.loads(p.read_text()) for p in sorted((ROOT/'revision_measurements').glob('process_*.json'))]
M=json.loads((ROOT/'revision_results/measurement_summary.json').read_text());q=M['crypto']['q']['mean_ms'];d=M['crypto']['delta']['mean_ms'];B=M['crypto']['build']['mean_ms'];pmean={m:M['policy'][m]['mean_ms'] for m in METHODS}
boot=np.random.default_rng(811611).integers(0,12,(10000,12));overhead=[];raw=[];pmap={}
for m in METHODS:
    for f in FAMS:
        xs=[next(x['net_ns_per_message']/1e6 for x in r['policy'] if x['family']==f and x['method']==m) for r in proc]
        v,lo,hi=stat(xs,boot);pmap[f,m]=v
        overhead.append(dict(method=m,family=f,mean_ms=v,lo_ms=lo,hi_ms=hi,mean_us=v*1000,lo_us=lo*1000,hi_us=hi*1000,n_processes=12))
        for r,x in zip(proc,xs):raw.append(dict(process_index=r['process_index'],method=m,family=f,net_ms=x,net_us=x*1000))
    assert np.isclose(np.mean([pmap[f,m] for f in FAMS]),pmean[m],atol=1e-15,rtol=0)
write('overhead_by_workload.csv',overhead);write('overhead_process_values.csv',raw)
original=read('primary_runs.csv');lookup={(int(r['seed']),r['family'],int(r['slots']),float(r['rho']),r['method']):r for r in original}
new=[];masks={}
for seed in SEEDS:
    for fam in FAMS:
        with np.load(ROOT/'traces'/f'{seed}_{fam}.npz') as z:ids=z['ids'];gaps=z['unit_gaps']
        for k in [2,4,8]:
            for m in METHODS:
                h,b,_,_=events(ids,m,k);masks[seed,fam,k,m]=(np.array(h),np.array(b))
            for rho in [.5,.8,.95,1,1.05]:
                arr=np.cumsum(gaps*q/rho);base,_=queue(arr,np.full(N,q))
                for m in METHODS:
                    h,b=masks[seed,fam,k,m];svc=q-h*d+b*B+pmap[fam,m];v,tail=queue(arr,svc);o=lookup[seed,fam,k,rho,m]
                    saving=100*(q-svc.mean())/q
                    expected=float(o['cpu_saving_pct'])-100*(pmap[fam,m]-pmean[m])/q
                    assert abs(saving-expected)<1e-10
                    new.append(dict(seed=seed,family=fam,slots=k,rho=rho,method=m,policy_ms=pmap[fam,m],cpu_saving_pct=saving,ontime_pct=v,difference_pp=v-base,p95_sojourn_ms=tail,change_completion_pp=v-float(o['ontime_pct']),change_saving_pp=saving-float(o['cpu_saving_pct'])))
write('workload_overhead_runs.csv',new);write('workload_overhead_summary.csv',summarize(new,['family','slots','rho','method'],['cpu_saving_pct','ontime_pct','difference_pp','change_completion_pp','change_saving_pp']))
pair=[];nl={(r['seed'],r['family'],r['slots'],r['rho'],r['method']):r for r in new}
for fam in FAMS:
    for rho in [.8,.95,1.05]:
        for ref in ['Q-only','Immediate','LRU-2','Window-Frequency']:
            for metric in ['cpu_saving_pct','ontime_pct']:
                v,lo,hi=stat([nl[s,fam,8,rho,'Second-hit'][metric]-nl[s,fam,8,rho,ref][metric] for s in SEEDS]);pair.append(dict(family=fam,slots=8,rho=rho,target='Second-hit',reference=ref,metric=metric,mean=v,lo=lo,hi=hi))
write('workload_overhead_paired.csv',pair)
# One vector consists of the three serial operations measured in the same
# process and randomised operation-order cycle. It is NOT simultaneous data.
tensor=np.empty((12,64,3));ops=['q','table','build']
for i,r in enumerate(proc):
    for j in range(64):
        for k,op in enumerate(ops):tensor[i,j,k]=next(s['cpu_ns']/1e6 for s in r['crypto_samples'] if s['index']==j and s['op']==op)
assert np.isfinite(tensor).all() and (tensor>0).all()
robust=read('robustness_runs.csv');joint=[];corr=[]
families=['mixed_scan','shift8','rotating_hotspots','bursty_migration']
for seed in SEEDS:
    for fi,fam in enumerate(families):
        folder='traces' if fam in FAMS else 'revision_traces'
        with np.load(ROOT/folder/f'{seed}_{fam}.npz') as z:ids=z['ids'];gaps=z['unit_gaps']
        mh={m:tuple(np.array(x) for x in events(ids,m,8)[:2]) for m in METHODS}
        with np.load(ROOT/'revision_traces'/f'{seed}_{fam}_service.npz') as z:independent=np.column_stack([z[o] for o in ops])
        for model in ['independent','joint_cycle','process_block128']:
            rng=np.random.default_rng(np.random.SeedSequence([seed,811618,fi,{'independent':0,'joint_cycle':1,'process_block128':2}[model]]))
            if model=='independent':draw=independent;pi=np.full(N,-1);ci=np.full(N,-1)
            elif model=='joint_cycle':
                pi=rng.integers(0,12,N);ci=rng.integers(0,64,N);draw=tensor[pi,ci]
            else:
                # A 128-message block shares one process; two contiguous 64-cycle
                # segments are resampled with independent starts. Block length
                # is a stress-test choice, not an inferred hardware time scale.
                pi=np.repeat(rng.integers(0,12,N//128),128)
                starts=rng.integers(0,64,N//64);ci=np.concatenate([(s+np.arange(64))%64 for s in starts]);draw=tensor[pi,ci]
            if model!='independent':np.savez_compressed(DRAW/f'{seed}_{fam}_{model}.npz',q=draw[:,0],table=draw[:,1],build=draw[:,2],process_index=pi,cycle_index=ci)
            corr.append(dict(seed=seed,family=fam,service_model=model,q_table_correlation=float(np.corrcoef(draw[:,0],draw[:,1])[0,1]),q_build_correlation=float(np.corrcoef(draw[:,0],draw[:,2])[0,1])))
            for rho in [.8,.95,1.05]:
                arr=np.cumsum(gaps*q/rho);base,_=queue(arr,draw[:,0])
                for m in METHODS:
                    h,b=mh[m];svc=np.where(h,draw[:,1],draw[:,0])+b*draw[:,2]+pmean[m];v,tail=queue(arr,svc)
                    if model=='independent':
                        old=next(r for r in robust if int(r['seed'])==seed and r['family']==fam and r['service_model']=='empirical' and float(r['rho'])==rho and r['method']==m)
                        assert abs(v-float(old['ontime_pct']))<1e-10
                    joint.append(dict(seed=seed,family=fam,service_model=model,rho=rho,method=m,ontime_pct=v,difference_pp=v-base,cpu_saving_pct=100*(draw[:,0].mean()-svc.mean())/draw[:,0].mean(),p95_sojourn_ms=tail))
write('dependent_service_runs.csv',joint);write('dependent_service_summary.csv',summarize(joint,['family','service_model','rho','method'],['ontime_pct','difference_pp','cpu_saving_pct','p95_sojourn_ms']));write('draw_correlations.csv',corr)
jl={(r['seed'],r['family'],r['service_model'],r['rho'],r['method']):r for r in joint};contrasts=[]
for fam in families:
    for rho in [.8,.95,1.05]:
        for model in ['independent','joint_cycle','process_block128']:
            for ref in ['Q-only','LRU-2','Window-Frequency']:
                v,lo,hi=stat([jl[s,fam,model,rho,'Second-hit']['ontime_pct']-jl[s,fam,model,rho,ref]['ontime_pct'] for s in SEEDS]);contrasts.append(dict(family=fam,rho=rho,service_model=model,contrast='Second-hit minus '+ref,mean_pp=v,lo_pp=lo,hi_pp=hi))
            if model!='independent':
                v,lo,hi=stat([jl[s,fam,model,rho,'Second-hit']['difference_pp']-jl[s,fam,'independent',rho,'Second-hit']['difference_pp'] for s in SEEDS]);contrasts.append(dict(family=fam,rho=rho,service_model=model,contrast='gain change from independent',mean_pp=v,lo_pp=lo,hi_pp=hi))
write('dependent_service_paired.csv',contrasts)
js('round2_config.json',{'purpose':'Check second simulated review; primary estimands and original measured input records retained','seeds':SEEDS,'bootstrap_seed':811610,'bootstrap_resamples':10000,'overhead_replication':'12 process means within each workload; seed811611','joint_source_shape':list(tensor.shape),'joint_cycle':'Sample one (process,cycle) per message; q/table/build from the same serial measurement round','process_block128':'Hold process for128messages; within each64-message segment sample a cyclic consecutive set of64 retained cycles, with independent starting offsets','dependence_scope':'Timing-based stress models, not measured live CPU-state trajectories or simultaneous counterfactual verifications','policy_overhead':'Workload-specific p reruns full original primary matrix; dependent-service study retains equal-family mean p to isolate service dependence','conditional_intervals':True})
js('round2_audit.json',{'passed':True,'workload_overhead_runs':len(new),'dependent_service_runs':len(joint),'independent_service_exact_rechecks':2160,'new_dependent_service_runs':4320,'new_saved_service_arrays':240,'policy_mean_reconciliation':True,'all_overhead_cost_change_identities':True,'no_new_hardware_measurements':True,'source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest()})
print('Completed workload-specific overhead and dependent-service checks')
for r in pair:
    if r['family']=='mixed_scan' and r['rho']==.95 and r['metric']=='ontime_pct':print(json.dumps(r))
for r in contrasts:
    if r['rho']==.95 and r['contrast']=='Second-hit minus Q-only':print(json.dumps(r))
