"""Self-contained current numerical records plus hashed external trace index."""
from pathlib import Path
import csv,json,hashlib
ROOT=Path(__file__).resolve().parent
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def rows(p):
    records=list(csv.DictReader(p.open(encoding='utf-8-sig')))
    for r in records:
        for k,v in r.items():
            try:
                x=float(v);r[k]=int(x) if x.is_integer() else x
            except (ValueError,AttributeError):pass
    return records
out={'schema':'sm9-review-revision-v1','scope':'Current reviewer-driven simulation results and process measurements. Not all historical project experiments. NPZ identity/arrival/service arrays remain external and are hash-indexed here.','units':{'service_time':'ms','calibration_raw_time':'ns','completion':'percent','paired_completion_difference':'percentage points'},'replication':{'simulation':'30 paired seeds; conditional bootstrap','measurement':'12 separately launched processes on one host'},'config':json.loads((ROOT/'revision_results/revision_config.json').read_text()),'results':{},'raw_measurements':{},'trace_files':[],'source_files':[],'figure_source_data':json.loads((ROOT/'revision_figure_source_data.json').read_text(encoding='utf-8'))}
for p in sorted((ROOT/'revision_results').iterdir()):
    if p.suffix=='.csv':out['results'][p.name]=rows(p)
    elif p.suffix=='.json':out['results'][p.name]=json.loads(p.read_text(encoding='utf-8'))
for p in sorted((ROOT/'revision_measurements').glob('*.json')):out['raw_measurements'][p.name]=json.loads(p.read_text(encoding='utf-8'))
out['schema']='sm9-review-revision-round2-v2'
out['round2_config']=json.loads((ROOT/'round2_results/round2_config.json').read_text(encoding='utf-8'))
for p in sorted((ROOT/'round2_results').iterdir()):
    if p.suffix=='.csv':out['results']['round2/'+p.name]=rows(p)
    elif p.suffix=='.json':out['results']['round2/'+p.name]=json.loads(p.read_text(encoding='utf-8'))
for folder in ['traces','revision_traces','round2_traces']:
    for p in sorted((ROOT/folder).glob('*.npz')):out['trace_files'].append({'path':p.relative_to(ROOT).as_posix(),'sha256':sha(p),'bytes':p.stat().st_size})
for p in [ROOT/x for x in ['revision_policies.py','run_revision_experiments.py','analyze_revision_pairs.py','measure_revision.py','plot_revision_figures.py','export_revision_json.py','run_round2_checks.py']]:out['source_files'].append({'path':p.name,'sha256':sha(p)})
(ROOT/'revision_experiment_data.json').write_text(json.dumps(out,ensure_ascii=False,separators=(',',':'),allow_nan=False),encoding='utf-8')
print('Exported current revision JSON:',len(out['trace_files']),'external trace records')
