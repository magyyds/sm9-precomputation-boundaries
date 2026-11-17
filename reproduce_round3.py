"""Run the local R3 extension in a new folder, retaining the supplied evidence."""
from pathlib import Path
import argparse,datetime,hashlib,json,shutil,subprocess,sys,csv,os
ROOT=Path(__file__).resolve().parent
FILES=['run_round3_checks.py','verify_round3.py','plot_round3_figures.py','export_round3_json.py','reproduce_round3.py','revision_policies.py','simulate.py','revision_experiment_data.json','revision_figure_source_data.json','requirements-reproduction.txt']
FOLDERS=['revision_results','revision_measurements','traces','revision_traces','round2_results','round2_traces','revision_figures','qa_helpers']
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    p=argparse.ArgumentParser();p.add_argument('--output',type=Path);p.add_argument('--no-plots',action='store_true');a=p.parse_args()
    dest=(a.output or ROOT/('reproduced_round3_'+datetime.datetime.now().strftime('%Y%m%d_%H%M%S'))).resolve()
    if dest.exists():raise SystemExit('Output directory already exists. Choose a new --output path to preserve previous data.')
    manifest=json.loads((ROOT/'round3_input_manifest.json').read_text())
    for name,digest in manifest.items():
        if sha(ROOT/name)!=digest:raise SystemExit('Input hash mismatch: '+name)
    dest.mkdir(parents=True)
    for n in FILES:shutil.copy2(ROOT/n,dest/n)
    for n in FOLDERS:shutil.copytree(ROOT/n,dest/n)
    (dest/'round3_results').mkdir();(dest/'round3_traces').mkdir();(dest/'revision_figure_qa').mkdir()
    shutil.copy2(ROOT/'round3_figure_source_data.json',dest/'round3_figure_source_data.json')
    # A local optional plot-tool path is used only in the verified desktop environment.
    # A portable installation uses the pinned requirements without this fallback.
    env=os.environ.copy();local=ROOT.parent.parent/'.paper_tools'
    if local.exists():env['SM9_PLOT_TOOLS']=str(local)
    for script,args in [('run_round3_checks.py',['--stage','all']),('verify_round3.py',[])]+([] if a.no_plots else [('plot_round3_figures.py',[])])+[('export_round3_json.py',[])]:
        print('Running',script,flush=True);subprocess.run([sys.executable,str(dest/script)]+args,cwd=dest,env=env,check=True)
    checks={}
    for f in sorted((ROOT/'round3_results').glob('*.csv')):
        other=dest/'round3_results'/f.name
        if f.name.startswith('metadata_memory_'):
            left=list(csv.DictReader(f.open()));right=list(csv.DictReader(other.open()));assert len(left)==len(right)
            cols=[k for k in left[0] if 'bytes' not in k]
            assert [[r[k] for k in cols] for r in left]==[[r[k] for k in cols] for r in right]
            checks[f.name]='All identities/counts match; allocator bytes are fresh observations.'
        else:
            assert sha(f)==sha(other),f.name;checks[f.name]='Byte-identical'
    if not a.no_plots:assert sha(ROOT/'round3_figure_source_data.json')==sha(dest/'round3_figure_source_data.json')
    report={'passed':True,'output':str(dest),'csv_checks':checks,'plots_regenerated':not a.no_plots,'scope':'R3 extension from retained baseline; original timing measurements not rerun'}
    (dest/'reproduction_round3_check.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8');print(json.dumps(report,ensure_ascii=False,indent=2))
if __name__=='__main__':main()
