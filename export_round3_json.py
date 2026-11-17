"""Current manuscript numerical data, with external array index and provenance."""
from pathlib import Path
import json,csv,hashlib
ROOT=Path(__file__).resolve().parent
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def read(p):
    rows=list(csv.DictReader(p.open(encoding='utf-8-sig')))
    for r in rows:
        for k,v in r.items():
            try:x=float(v);r[k]=int(x) if x.is_integer() else x
            except (ValueError,AttributeError):pass
    return rows
out=json.loads((ROOT/'revision_experiment_data.json').read_text(encoding='utf-8'))
out['schema']='sm9-local-review-round3-v3'
out['scope']='Numerical evidence for the current manuscript: retained R1/R2 evidence plus local R3 sensitivity, heldout selection, joint uncertainty and Python metadata measurements. Not all historical project experiments. External NPZ arrays are hash-indexed, not embedded.'
out['repository_version']='v3.0.0'
out['repository_url']='https://github.com/magyyds/sm9-precomputation-boundaries/tree/v3.0.0'
out['repository_status']='Version v3.0.0 includes the retained baseline/R2 evidence and the R3 single-host simulation extension.'
for p in sorted((ROOT/'round3_results').iterdir()):
    if p.suffix=='.csv':out['results']['round3/'+p.name]=read(p)
    elif p.suffix=='.json':out['results']['round3/'+p.name]=json.loads(p.read_text(encoding='utf-8'))
out['figure_source_data'].update(json.loads((ROOT/'round3_figure_source_data.json').read_text(encoding='utf-8')))
for p in sorted((ROOT/'round3_traces').glob('*.npz')):out['trace_files'].append({'path':p.relative_to(ROOT).as_posix(),'sha256':sha(p),'bytes':p.stat().st_size})
for n in ['run_round3_checks.py','plot_round3_figures.py','verify_round3.py','export_round3_json.py','reproduce_round3.py']:
    p=ROOT/n;out['source_files'].append({'path':n,'sha256':sha(p)})
out['figure_file_map']={n:{ext:f'revision_figures/{n}.{ext}' for ext in ['png','pdf','svg']} for n in ['fig1_boundaries','fig2_baselines','fig3_queue','fig4_robustness','fig5_scope','supp_joint','supp_window','supp_dependence','supp_deadlines','supp_nearties']}
out['data_roles']={'JSON':'All current table/plot aggregates and run-level CSV records plus 12 calibration records. Enough to redraw numerical manuscript plots.','NPZ':'Required for exact replay of identity/arrival/service arrays, parameter-grid arrays, and bootstrap sampled indices.','historical_json':'prior_manuscript_experiment_data.json and revision_experiment_data.json are retained earlier snapshots, not the complete R3 input.'}
(ROOT/'round3_experiment_data.json').write_text(json.dumps(out,ensure_ascii=False,separators=(',',':'),allow_nan=False),encoding='utf-8')
print('Exported R3 current manuscript JSON:',len(out['trace_files']),'external arrays;',len(out['figure_file_map']),'figure mappings')
