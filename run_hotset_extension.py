"""Review-requested interior hot-set simulations; original inputs stay unchanged."""
from pathlib import Path
import argparse,csv,json,hashlib,sys,platform
import numpy as np

HERE=Path(__file__).resolve().parent
parser=argparse.ArgumentParser()
parser.add_argument('--source',type=Path,default=HERE)
parser.add_argument('--output',type=Path,default=HERE/'reproduced_hotset_extension')
args=parser.parse_args(); ROOT=args.source.resolve(); OUT=args.output.resolve()
if OUT.exists():raise SystemExit('Output directory already exists; choose a new --output path.')
OUT.mkdir(parents=True)
sys.path.insert(0,str(ROOT))
import run_round3_checks as original

def read(p):
    return list(csv.DictReader(p.open(encoding='utf-8-sig')))
def write(name,rows):
    with (OUT/name).open('w',newline='',encoding='utf-8') as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()

rows=[]; trace_hash={}; new_hot=[9,10,12,14]; hot_values=[4,8,*new_hot,16]
old={(int(r['seed']),int(r['hot']),float(r['scan']),float(r['rho']),r['method']):r for r in read(ROOT/'round3_results/hotset_scan_runs.csv')}
checks=0
for seed in original.SEEDS:
    rng=np.random.default_rng(np.random.SeedSequence([seed,811701]))
    u=rng.random(original.N); scan_u=rng.random(original.N); gaps=rng.exponential(1,original.N); gaps[0]=0
    for hot in hot_values:
        for scan in [.1,.2,.4]:
            if hot==8 and scan==.2: ids,g=original.original(seed,'mixed_scan')
            else:
                ids=np.floor(u*hot).astype(int); ids[scan_u<scan]=10000+np.arange(original.N)[scan_u<scan]; g=gaps
            trace=OUT/f'trace_{seed}_H{hot}_S{int(scan*100)}.npz'
            np.savez_compressed(trace,ids=ids,unit_gaps=g); trace_hash[trace.name]=sha(trace)
            masks={m:original.mask(ids,m,8) for m in original.THREE}
            for rho in [.9,.95,1.]:
                arr=np.cumsum(g*original.Q/rho); base=100*np.mean(original.latency(arr,np.full(original.N,original.Q))<=100)
                for method in original.THREE:
                    hit,build=masks[method]; svc=original.Q+original.P[method]-hit*original.D+build*original.B
                    soj=original.latency(arr,svc)
                    row=dict(seed=seed,hot=hot,scan=scan,k=8,rho=rho,method=method,cpu_saving_pct=float(100*(original.Q-svc.mean())/original.Q),ontime_pct=float(100*np.mean(soj<=100)),gain_pp=float(100*np.mean(soj<=100)-base),p95_ms=float(np.quantile(soj,.95)),hits=int(hit.sum()),builds=int(build.sum()))
                    if hot not in new_hot:
                        ref=old[seed,hot,scan,rho,method]
                        for metric in ['cpu_saving_pct','ontime_pct','gain_pp','p95_ms','hits','builds']:
                            assert abs(row[metric]-float(ref[metric]))<1e-9,(row,metric,ref[metric])
                        checks+=1
                    # Independent scalar FCFS check, including synchronous build.
                    if seed==original.SEEDS[0] and rho==.95:
                        release=0.; scalar=[]
                        for arrival,service in zip(arr,svc):
                            release=max(release,arrival)+service; scalar.append(release-arrival)
                        assert np.allclose(soj,scalar,rtol=0,atol=1e-7)
                    rows.append(row)
    print('Completed seed',seed,flush=True)
write('hotset_expanded_runs.csv',rows)
summary=original.summarize(rows,['hot','scan','k','rho','method'],['cpu_saving_pct','ontime_pct','gain_pp','hits','builds'])
write('hotset_expanded_summary.csv',summary)
index={(r['seed'],r['hot'],r['scan'],r['rho'],r['method']):r for r in rows};pairs=[]
for hot in hot_values:
    for scan in [.1,.2,.4]:
        for rho in [.9,.95,1.]:
            for metric in ['cpu_saving_pct','ontime_pct']:
                mean,lo,hi=original.stat([index[s,hot,scan,rho,'Second-hit'][metric]-index[s,hot,scan,rho,'Window-Frequency'][metric] for s in original.SEEDS])
                status='within_margin' if lo>=-.5 and hi<=.5 else ('Second-hit_above_margin' if lo>.5 else ('Window-Frequency_above_margin' if hi<-.5 else 'unresolved_at_margin'))
                pairs.append(dict(hot=hot,ratio=hot/8,scan=scan,rho=rho,metric=metric,target='Second-hit',reference='Window-Frequency',mean=mean,lo=lo,hi=hi,margin_pp=.5,descriptive_classification=status))
write('hotset_expanded_paired.csv',pairs)
baseline=[r for r in read(ROOT/'revision_results/paired_baseline_comparisons.csv') if r['family']=='mixed_scan' and float(r['rho'])==.95 and r['reference']=='Window-Frequency']
grid=[r for r in read(ROOT/'revision_results/joint_sensitivity_summary.csv') if r['family']=='mixed_scan' and r['method']=='Second-hit' and float(r['rho'])==.95]
assert len(grid)==36 and all(float(r['difference_pp_lo'])>0 for r in grid)
report={'new_hot_counts':new_hot,'new_ratios':[h/8 for h in new_hot],'new_runs':len([r for r in rows if r['hot'] in new_hot]),'anchor_rechecks':checks,'total_runs':len(rows),'n_messages':original.N,'seeds':original.SEEDS,'bootstrap_resamples':10000,'bootstrap_seed':811610,'scan_fractions':[.1,.2,.4],'reference_loads':[.9,.95,1.],'K':8,'service_model':'fixed calibrated service; original mean policy charges; 1024-request frequency window','practical_margin_pp':.5,'margin_status':'revision-stage descriptive interpretation; not preregistered or deployment validated; no formal equivalence test','multiplicity':'No FWER or FDR adjustment; all intervals descriptive and pointwise','scalar_queue_check_passed':True,'baseline_comparisons':baseline,'perturbation_interval_count':len(grid),'perturbation_min_lower_pp':min(float(r['difference_pp_lo']) for r in grid),'python':sys.version,'numpy':np.__version__,'platform':platform.platform(),'source_sha256':{name:sha(ROOT/name) for name in ['run_round3_checks.py','revision_policies.py','simulate.py','revision_results/measurement_summary.json']},'trace_sha256':trace_hash}
(OUT/'verification.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
print(json.dumps({k:v for k,v in report.items() if k!='trace_sha256'},indent=2))
print('INTERIOR COST AND COMPLETION CONTRASTS AT RHO .95')
for row in pairs:
    if row['rho']==.95:print(row)
