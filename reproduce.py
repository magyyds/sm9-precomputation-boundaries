"""One-command numerical/figure reproduction from preserved measured inputs."""
from pathlib import Path
import subprocess,sys,json,hashlib
ROOT=Path(__file__).resolve().parent
manifest=ROOT/'input_manifest.json'
if manifest.exists():
    for entry in json.loads(manifest.read_text(encoding='utf-8')):
        p=ROOT/entry['path'];assert hashlib.sha256(p.read_bytes()).hexdigest()==entry['sha256'],f'Input changed: {p}'
for name in ['run_revision_experiments.py','analyze_revision_pairs.py','run_round2_checks.py','plot_revision_figures.py','export_revision_json.py']:
    print('Running',name,flush=True);subprocess.run([sys.executable,str(ROOT/name)],cwd=ROOT,check=True)
print('Completed. See revision_results, revision_figures and revision_experiment_data.json.')
