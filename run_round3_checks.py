"""Local-only sensitivity, held-out configuration and joint uncertainty checks.

All calibration observations and original manuscript results are preserved.
No multi-host, multi-server, new algorithm or vehicular-deployment claim.
"""
from pathlib import Path
from collections import defaultdict
import argparse,csv,json,hashlib,time,sys,tracemalloc,platform
import numpy as np
from revision_policies import METHODS,Policy,events
from simulate import workload

ROOT=Path(__file__).resolve().parent;OUT=ROOT/'round3_results';TRACE=ROOT/'round3_traces'
SEEDS=list(range(271101,271131));TEST_SEEDS=list(range(281101,281131));N=4096
FAMS=['stable8','pressure64','short2','bursts4','mixed_scan','shift8']
THREE=['Q-only','Second-hit','Window-Frequency']
M=json.loads((ROOT/'revision_results/measurement_summary.json').read_text())
Q=M['crypto']['q']['mean_ms'];D=M['crypto']['delta']['mean_ms'];B=M['crypto']['build']['mean_ms'];P={m:M['policy'][m]['mean_ms'] for m in METHODS}
BOOT=np.random.default_rng(811610).integers(0,30,(10000,30))
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def js(name,obj):(OUT/name).write_text(json.dumps(obj,ensure_ascii=False,indent=2,allow_nan=False),encoding='utf-8')
def write(name,rows):
    with (OUT/name).open('w',newline='',encoding='utf-8') as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
def read(name):return list(csv.DictReader((ROOT/name).open(encoding='utf-8-sig')))
def stat(values):
    a=np.asarray(values,float);lo,hi=np.quantile(a[BOOT].mean(axis=1),[.025,.975]);return float(a.mean()),float(lo),float(hi)
def summarize(rows,keys,fields):
    groups=defaultdict(list)
    for row in rows:groups[tuple(row[k] for k in keys)].append(row)
    result=[]
    for key,group in groups.items():
        group.sort(key=lambda r:r['seed']);assert len(group)==30
        row=dict(zip(keys,key));row['n_seeds']=30
        for field in fields:
            v,lo,hi=stat([r[field] for r in group]);row.update({field:v,field+'_lo':lo,field+'_hi':hi})
        result.append(row)
    return result
def latency(arr,svc):
    total=np.cumsum(svc,axis=-1);prior=np.concatenate([np.zeros(total.shape[:-1]+(1,)),total[...,:-1]],axis=-1)
    return total+np.maximum.accumulate(np.maximum(arr-prior,0),axis=-1)-arr
def original(seed,family):
    with np.load(ROOT/'traces'/f'{seed}_{family}.npz') as z:return z['ids'].copy(),z['unit_gaps'].copy()
def mask(ids,m,k):
    h,b,_,_=events(ids,m,k);return np.asarray(h,float),np.asarray(b,float)

def sensitivity():
    rows=[]
    old={(int(r['seed']),float(r['rho']),r['method']):r for r in read('revision_results/primary_runs.csv') if r['family']=='mixed_scan' and int(r['slots'])==8}
    for seed in SEEDS:
        rng=np.random.default_rng(np.random.SeedSequence([seed,811701]));u=rng.random(N);scan_u=rng.random(N);gaps=rng.exponential(1,N);gaps[0]=0
        for hot in [4,8,16]:
            for scan in [.1,.2,.4]:
                if hot==8 and scan==.2:ids,g=original(seed,'mixed_scan')
                else:ids=np.floor(u*hot).astype(int);ids[scan_u<scan]=10000+np.arange(N)[scan_u<scan];g=gaps
                np.savez_compressed(TRACE/f'sensitivity_{seed}_H{hot}_S{int(scan*100)}.npz',ids=ids,unit_gaps=g)
                masks={m:mask(ids,m,8) for m in THREE}
                for rho in [.9,.95,1.]:
                    arr=np.cumsum(g*Q/rho);base=100*np.mean(latency(arr,np.full(N,Q))<=100)
                    for m in THREE:
                        h,b=masks[m];svc=Q+P[m]-h*D+b*B;soj=latency(arr,svc)
                        row=dict(seed=seed,hot=hot,scan=scan,k=8,rho=rho,method=m,cpu_saving_pct=100*(Q-svc.mean())/Q,ontime_pct=float(100*np.mean(soj<=100)),gain_pp=float(100*np.mean(soj<=100)-base),p95_ms=float(np.quantile(soj,.95)),hits=int(h.sum()),builds=int(b.sum()))
                        if hot==8 and scan==.2 and rho in [.95,1.]:
                            previous=old[seed,rho,m];assert abs(row['ontime_pct']-float(previous['ontime_pct']))<1e-10;assert abs(row['cpu_saving_pct']-float(previous['cpu_saving_pct']))<1e-10
                        rows.append(row)
    assert len(rows)==2430
    write('hotset_scan_runs.csv',rows);write('hotset_scan_summary.csv',summarize(rows,['hot','scan','k','rho','method'],['cpu_saving_pct','ontime_pct','gain_pp','hits','builds']))
    pairs=[];index={(r['seed'],r['hot'],r['scan'],r['rho'],r['method']):r for r in rows}
    for hot in [4,8,16]:
        for scan in [.1,.2,.4]:
            for rho in [.9,.95,1.]:
                for metric in ['cpu_saving_pct','ontime_pct']:
                    v,lo,hi=stat([index[s,hot,scan,rho,'Second-hit'][metric]-index[s,hot,scan,rho,'Window-Frequency'][metric] for s in SEEDS])
                    pairs.append(dict(hot=hot,scan=scan,rho=rho,metric=metric,target='Second-hit',reference='Window-Frequency',mean=v,lo=lo,hi=hi))
    write('hotset_scan_paired.csv',pairs);print('A hotset/scan: 2430 settings',flush=True)

def deadlines():
    rows=[]
    for seed in SEEDS:
        ids,g=original(seed,'mixed_scan');masks={m:mask(ids,m,8) for m in THREE}
        for rho in [.5,.8,.95,1.,1.05]:
            arr=np.cumsum(g*Q/rho);sojourn={m:latency(arr,Q+P[m]-masks[m][0]*D+masks[m][1]*B) for m in THREE}
            np.savez_compressed(TRACE/f'deadline_{seed}_rho{rho}.npz',arrivals_ms=arr,**{m.replace('-','_'):v for m,v in sojourn.items()})
            for threshold in [50,100,200,500]:
                base=float(np.mean(sojourn['Q-only']<=threshold)*100)
                for m in THREE:
                    value=float(np.mean(sojourn[m]<=threshold)*100)
                    rows.append(dict(seed=seed,rho=rho,deadline_ms=threshold,method=m,ontime_pct=value,gain_pp=value-base))
    write('deadline_runs.csv',rows);write('deadline_summary.csv',summarize(rows,['rho','deadline_ms','method'],['ontime_pct','gain_pp']))
    print('B deadlines: 450 queue paths, 1800 threshold readouts',flush=True)

def heldout():
    primary=read('revision_results/primary_runs.csv');train={};counts={};selection=[];rows=[]
    for family in FAMS:
        for k in [2,4,8]:
            costs=[]
            for m in METHODS:
                r=[r for r in primary if r['family']==family and int(r['slots'])==k and float(r['rho'])==.95 and r['method']==m]
                assert len(r)==30
                h=float(np.mean([float(x['hits']) for x in r]));b=float(np.mean([float(x['builds']) for x in r]));counts[family,k,m]=(h,b)
                costs.append(N*(Q+P[m])-h*D+b*B)
            chosen=int(np.argmin(costs));train[family,k]=chosen
            selection.append(dict(family=family,k=k,selected=METHODS[chosen],training_mean_work_ms=costs[chosen],training_seed_first=SEEDS[0],training_seed_last=SEEDS[-1],training_seed_count=30))
    write('offline_selection_training.csv',selection)
    # The chosen policy is frozen before any held-out trace is generated or read.
    for seed in TEST_SEEDS:
        for fi,family in enumerate(FAMS):
            rng=np.random.default_rng(np.random.SeedSequence([seed,fi]));ids=workload(family,N,rng);g=rng.exponential(1,N);g[0]=0
            np.savez_compressed(TRACE/f'heldout_{seed}_{family}.npz',ids=ids,unit_gaps=g)
            for k in [2,4,8]:
                costs=[]
                for m in METHODS:
                    h,b=mask(ids,m,k);costs.append(float(N*(Q+P[m])-h.sum()*D+b.sum()*B))
                choice=train[family,k];best=int(np.argmin(costs));loss=costs[choice]-costs[best]
                assert loss>=-1e-8
                rows.append(dict(seed=seed,family=family,k=k,selected=METHODS[choice],test_best=METHODS[best],selected_work_ms=costs[choice],best_work_ms=costs[best],qonly_work_ms=N*Q,regret_fraction=loss/(N*Q),regret_pct=100*loss/(N*Q),exact_best=int(choice==best),near_best_001pp=int(100*loss/(N*Q)<=.01),**{m+'_work_ms':v for m,v in zip(METHODS,costs)}))
    write('offline_selection_test.csv',rows);write('offline_selection_summary.csv',summarize(rows,['family','k','selected'],['regret_pct','exact_best','near_best_001pp']))
    print('C offline selection: 30 training / 30 disjoint test seeds; 540 test decisions',flush=True)
    return counts

def near_ties(counts):
    grids=[];summary=[];bs=np.linspace(0,.8,161);ds=np.linspace(0,.65,131)
    for family,k in [('mixed_scan',2),('mixed_scan',8),('bursts4',8),('pressure64',8)]:
        works=np.stack([N*(Q+P[m])-counts[family,k,m][0]*ds[:,None]+counts[family,k,m][1]*bs[None,:] for m in METHODS])
        order=np.argsort(works,axis=0,kind='stable');sort=np.sort(works,axis=0,kind='stable');gap=(sort[1]-sort[0])/(N*Q)*100
        np.savez_compressed(TRACE/f'near_ties_{family}_K{k}.npz',B_ms=bs,delta_ms=ds,best=order[0],runner_up=order[1],gap_pct=gap,work_ms=works)
        for epsilon in [.001,.01,.1]:summary.append(dict(family=family,k=k,tolerance_pp=epsilon,grid_fraction=float(np.mean(gap<=epsilon)),grid_points=int(gap.size),interpretation='Declared descriptive tolerance; not statistical equivalence'))
    write('near_tie_summary.csv',summary)
    actual=[]
    for family in FAMS:
        for k in [2,4,8]:
            costs=np.array([N*(Q+P[m])-counts[family,k,m][0]*D+counts[family,k,m][1]*B for m in METHODS]);order=np.argsort(costs,kind='stable')
            actual.append(dict(family=family,k=k,best=METHODS[order[0]],runner_up=METHODS[order[1]],gap_work_ms=float(costs[order[1]]-costs[order[0]]),gap_pct=float(100*(costs[order[1]]-costs[order[0]])/(N*Q))))
    write('measured_point_gaps.csv',actual)

def joint_uncertainty(draws=10000):
    processes=[json.loads(p.read_text()) for p in sorted((ROOT/'revision_measurements').glob('process_*.json'))]
    params=np.array([[r['crypto_means']['q']/1e6,(r['crypto_means']['q']-r['crypto_means']['table'])/1e6,r['crypto_means']['build']/1e6]+[np.mean([x['net_ns_per_message'] for x in r['policy'] if x['method']==m])/1e6 for m in THREE] for r in processes])
    assert params.shape==(12,6)
    rng=np.random.default_rng(811703);pi=rng.integers(0,12,(draws,12));si=rng.integers(0,30,(draws,30));draw=params[pi].mean(axis=1)
    np.savez_compressed(TRACE/'joint_bootstrap_indices.npz',process_indices=pi,seed_indices=si,parameters_ms=draw)
    weights=np.array([np.bincount(s,minlength=30)/30 for s in si]);gaps=[];masks={m:[] for m in THREE}
    for seed in SEEDS:
        ids,g=original(seed,'mixed_scan');gaps.append(np.cumsum(g))
        for m in THREE:masks[m].append(mask(ids,m,8))
    gaps=np.asarray(gaps)[None,:,:];masks={m:np.asarray(v) for m,v in masks.items()};rho=.95;rows=[];distributions={}
    for mode in ['fixed_lambda','fixed_rho']:
        samples={m:[] for m in THREE[1:]}
        for offset in range(0,draws,32):
            d=draw[offset:offset+32];w=weights[offset:offset+32]
            q=d[:,0,None,None];delta=d[:,1,None,None];build=d[:,2,None,None]
            arr=gaps*(Q if mode=='fixed_lambda' else q)/rho
            base=None
            for mi,m in enumerate(THREE):
                h=masks[m][:,0,:][None,:,:];b=masks[m][:,1,:][None,:,:]
                svc=q+d[:,3+mi,None,None]-h*delta+b*build
                soj=latency(arr,svc);completion=np.mean(soj<=100,axis=-1)*100
                if mi==0:base=completion
                else:samples[m].extend(np.sum((completion-base)*w,axis=1).tolist())
            if offset%1024==0:print('Joint bootstrap',mode,offset,'/',draws,flush=True)
        for m,values in samples.items():
            a=np.asarray(values);lo,hi=np.quantile(a,[.025,.975]);rows.append(dict(arrival_mode=mode,method=m,bootstrap_mean_pp=float(a.mean()),lo_pp=float(lo),hi_pp=float(hi),draws=draws,process_unit_count=12,seed_unit_count=30));distributions[mode+'_'+m.replace('-','_')]=a
    write('joint_uncertainty_summary.csv',rows);np.savez_compressed(TRACE/'joint_uncertainty_draws.npz',**distributions)
    conditional=[]
    for m in THREE[1:]:
        rs=[r for r in read('revision_results/primary_runs.csv') if r['family']=='mixed_scan' and int(r['slots'])==8 and float(r['rho'])==.95 and r['method']==m];rs.sort(key=lambda r:int(r['seed']))
        v,lo,hi=stat([float(r['difference_pp']) for r in rs]);conditional.append(dict(method=m,mean_pp=v,lo_pp=lo,hi_pp=hi))
    write('conditional_uncertainty_reference.csv',conditional)

def metadata_memory():
    rows=[]
    for seed in SEEDS:
        for family in FAMS:
            ids,_=original(seed,family);ids=[int(x) for x in ids]
            for m in METHODS:
                tracemalloc.start();p=Policy(m,8);max_hist=max_freq=max_window=max_cache=0
                for key in ids:
                    p.step(key);max_hist=max(max_hist,len(p.history));max_freq=max(max_freq,len(p.freq));max_window=max(max_window,len(p.recent));max_cache=max(max_cache,len(p.cache))
                retained,peak=tracemalloc.get_traced_memory();tracemalloc.stop()
                rows.append(dict(seed=seed,family=family,method=m,retained_python_bytes=retained,peak_python_bytes=peak,peak_history_entries=max_hist,peak_frequency_entries=max_freq,peak_window_entries=max_window,peak_table_state_entries=max_cache))
    write('metadata_memory_runs.csv',rows);write('metadata_memory_summary.csv',summarize(rows,['family','method'],['retained_python_bytes','peak_python_bytes','peak_history_entries','peak_frequency_entries','peak_window_entries']))
    js('metadata_memory_environment.json',{'python':sys.version,'platform':platform.platform(),'definition':'tracemalloc incremental allocations after input IDs exist, including Policy containers, retained metadata and transient Python work; no native acceleration-table allocation or complete process RSS','peak':'Observed at every policy step; tracemalloc peak is allocator-tracked peak, not a sum of object sizes','implementation_note':'The retained Immediate reference also fills the shared threshold-counter dictionary. This is an implementation cost, not a necessary property of immediate admission.'})
    print('Python metadata measurements: 1080 traces',flush=True)

def main():
    p=argparse.ArgumentParser();p.add_argument('--stage',choices=['all','sensitivity','deadlines','heldout','uncertainty','memory'],default='all');p.add_argument('--bootstrap-draws',type=int,default=10000);args=p.parse_args()
    OUT.mkdir(exist_ok=True);TRACE.mkdir(exist_ok=True)
    config={'scope':'Single-host calibration-driven single-server FCFS sensitivity; no cluster experiment','N':N,'train_seeds':SEEDS,'test_seeds':TEST_SEEDS,'hot_counts':[4,8,16],'scan_fractions':[.1,.2,.4],'sensitivity_methods':THREE,'sensitivity_loads':[.9,.95,1.],'K':8,'deadlines_ms':[50,100,200,500],'primary_loads':[.5,.8,.95,1.,1.05],'bootstrap_draws':args.bootstrap_draws,'joint_bootstrap_seed':811703,'arrival_modes':{'fixed_lambda':'Original absolute arrivals held fixed at q_mean/0.95; sampled q changes realized load','fixed_rho':'Arrivals rescaled with sampled q/0.95 to hold reference load fixed'},'process_resampling':'Sample whole process parameter vectors jointly, preserving q/table/build/p associations; then independently sample trace seed blocks','near_tie_tolerances_pp':[.001,.01,.1],'source_sha256':sha(__file__),'input_process_sha256':{p.name:sha(p) for p in sorted((ROOT/'revision_measurements').glob('process_*.json'))}}
    js('round3_config.json',config)
    if args.stage in ['all','sensitivity']:sensitivity()
    if args.stage in ['all','deadlines']:deadlines()
    if args.stage in ['all','heldout']:near_ties(heldout())
    if args.stage in ['all','uncertainty']:joint_uncertainty(args.bootstrap_draws)
    if args.stage in ['all','memory']:metadata_memory()
    js('round3_last_run.json',{'stage':args.stage,'source_sha256':sha(__file__),'completed':True})
if __name__=='__main__':main()
