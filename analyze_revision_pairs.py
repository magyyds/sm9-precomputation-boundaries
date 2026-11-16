"""Paired comparisons in dynamic/empirical scenarios and window controls."""
from pathlib import Path
import csv,json
import numpy as np
ROOT=Path(__file__).resolve().parent/'revision_results'
def read(name):return list(csv.DictReader((ROOT/name).open(encoding='utf-8-sig')))
boot=np.random.default_rng(811610).integers(0,30,(10000,30))
def stats(x):
 a=np.array(x);lo,hi=np.quantile(a[boot].mean(axis=1),[.025,.975]);return float(a.mean()),float(lo),float(hi)
rows=read('robustness_runs.csv');win=read('frequency_window_runs.csv');out=[]
for fam in ['mixed_scan','shift8','rotating_hotspots','bursty_migration']:
 for model in ['fixed','empirical']:
  for rho in [.8,.95,1.05]:
   rr=[r for r in rows if r['family']==fam and r['service_model']==model and float(r['rho'])==rho]
   lookup={(int(r['seed']),r['method']):float(r['ontime_pct']) for r in rr}
   for target in ['Second-hit','Third-hit']:
    for ref in ['Immediate','LRU-2','Window-Frequency']:
     v,lo,hi=stats([lookup[s,target]-lookup[s,ref] for s in range(271101,271131)])
     out.append(dict(family=fam,service_model=model,rho=rho,target=target,reference=ref,window=1024 if ref=='Window-Frequency' else 0,gain_pp=v,lo_pp=lo,hi_pp=hi))
 for rho in [.95,1.05]:
  tr={int(r['seed']):float(r['difference_pp']) for r in rows if r['family']==fam and r['service_model']=='fixed' and r['method']=='Second-hit' and float(r['rho'])==rho}
  for w in [128,512,1024,4096]:
   ref={int(r['seed']):float(r['difference_pp']) for r in win if r['family']==fam and int(r['window'])==w and float(r['rho'])==rho}
   v,lo,hi=stats([tr[s]-ref[s] for s in range(271101,271131)])
   out.append(dict(family=fam,service_model='fixed',rho=rho,target='Second-hit',reference='Window-Frequency-window-check',window=w,gain_pp=v,lo_pp=lo,hi_pp=hi))
with (ROOT/'dynamic_paired_comparisons.csv').open('w',newline='',encoding='utf-8-sig') as f:
 w=csv.DictWriter(f,fieldnames=list(out[0]));w.writeheader();w.writerows(out)
for r in out:
 if r['family']=='bursty_migration' and r['rho']==.95 and r['target']=='Second-hit' and (r['service_model']=='empirical' and r['reference']=='Window-Frequency' or r['reference']=='Window-Frequency-window-check' and r['window']==128):print(json.dumps(r))
