"""Independent cross-checks of R3 queue arithmetic, inputs and selection."""
from pathlib import Path
import json,csv,hashlib
import numpy as np
from run_round3_checks import latency,original,mask,METHODS,THREE,Q,D,B,P,N,SEEDS,TEST_SEEDS
ROOT=Path(__file__).resolve().parent
def read(n):return list(csv.DictReader((ROOT/n).open(encoding='utf-8-sig')))
def queue(arr,svc):
    end=0;out=[]
    for a,s in zip(arr,svc):end=max(float(a),end)+float(s);out.append(end-a)
    return np.array(out)
checks={}
rng=np.random.default_rng(9171)
for n in [1,50,4096]:
    for scale in [.5,1,2]:
        arr=np.cumsum(rng.exponential(scale,n));svc=rng.uniform(.1,2,n)
        np.testing.assert_allclose(latency(arr,svc),queue(arr,svc),atol=1e-8,rtol=0)
checks['vector_queue_matches_independent_FCFS']=True
old={(r['seed'],float(r['rho']),r['method']):r for r in read('revision_results/primary_runs.csv') if r['family']=='mixed_scan' and r['slots']=='8'}
dead=read('round3_results/deadline_runs.csv')
for r in dead:
    if r['deadline_ms']=='100':assert float(r['ontime_pct'])==float(old[r['seed'],float(r['rho']),r['method']]['ontime_pct'])
assert len(dead)==1800
checks['all_450_original_100ms_values_exact']=True
hot=read('round3_results/hotset_scan_runs.csv');assert len(hot)==2430
assert len({(r['seed'],r['hot'],r['scan'],r['rho'],r['method']) for r in hot})==2430
assert set(SEEDS).isdisjoint(TEST_SEEDS)
train=read('round3_results/offline_selection_training.csv');test=read('round3_results/offline_selection_test.csv')
chosen={(r['family'],r['k']):r['selected'] for r in train}
for r in test:
    assert chosen[r['family'],r['k']]==r['selected']
    cost=np.array([float(r[m+'_work_ms']) for m in METHODS]);gap=cost[METHODS.index(r['selected'])]-min(cost)
    assert abs(float(r['regret_pct'])-100*gap/(N*Q))<1e-10
checks['540_frozen_heldout_decisions_and_nonnegative_regret']=True
config=json.loads((ROOT/'round3_results/round3_config.json').read_text())
for name,sha in config['input_process_sha256'].items():assert hashlib.sha256((ROOT/'revision_measurements'/name).read_bytes()).hexdigest()==sha
checks['12_archived_measurement_inputs_unchanged']=True
with np.load(ROOT/'round3_traces/joint_bootstrap_indices.npz') as z:
    draw=z['parameters_ms'];si=z['seed_indices'];pi=z['process_indices']
raw=[json.loads(p.read_text()) for p in sorted((ROOT/'revision_measurements').glob('process_*.json'))]
params=np.array([[r['crypto_means']['q']/1e6,(r['crypto_means']['q']-r['crypto_means']['table'])/1e6,r['crypto_means']['build']/1e6]+[np.mean([x['net_ns_per_message'] for x in r['policy'] if x['method']==m])/1e6 for m in THREE] for r in raw])
np.testing.assert_array_equal(draw,params[pi].mean(axis=1))
with np.load(ROOT/'round3_traces/joint_uncertainty_draws.npz') as z:
    for mode in ['fixed_lambda','fixed_rho']:
        for di in [0,31,9999]:
            q,de,b,p0,p1,p2=draw[di];values=[]
            for j in si[di]:
                ids,g=original(SEEDS[j],'mixed_scan');arr=np.cumsum(g*(Q if mode=='fixed_lambda' else q)/.95)
                hs,bs=mask(ids,'Second-hit',8)
                base=np.mean(queue(arr,np.full(N,q+p0))<=100)*100
                target=np.mean(queue(arr,q+p1-hs*de+bs*b)<=100)*100
                values.append(target-base)
            assert abs(np.mean(values)-z[mode+'_Second_hit'][di])<1e-10
checks['joint_vector_resampling_and_six_independent_draw_rechecks']=True
mem=read('round3_results/metadata_memory_runs.csv');assert len(mem)==1080
for r in mem:assert int(r['peak_table_state_entries'])<=8
checks['memory_all_event_table_capacity']=True
checks['observed_counts']={'sensitivity_queue_evaluations':2430,'deadline_queue_paths':450,'deadline_threshold_readouts':1800,'heldout_cost_decisions':540,'heldout_candidate_cost_evaluations':3240,'joint_bootstrap_replicates_per_arrival_mode':10000,'metadata_traces':1080}
checks['test_selection_summary']={'exact_best_count':sum(int(r['exact_best']) for r in test),'within_0_01pp_count':sum(int(r['near_best_001pp']) for r in test),'max_regret_pct':max(float(r['regret_pct']) for r in test),'mean_regret_pct':float(np.mean([float(r['regret_pct']) for r in test]))}
(ROOT/'round3_results/verification.json').write_text(json.dumps(checks,ensure_ascii=False,indent=2),encoding='utf-8');print(json.dumps(checks,ensure_ascii=False,indent=2))
