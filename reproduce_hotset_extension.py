"""Verify and reproduce the review-requested interior hot-set simulations."""
from pathlib import Path
import argparse,csv,hashlib,json,subprocess,sys,tempfile
import numpy as np

ROOT=Path(__file__).resolve().parent
RETAINED=ROOT/'hotset_extension'/'retained_results'

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,help='New directory for reproduced results.')
    parser.add_argument('--verify-only',action='store_true',help='Verify retained file hashes without recomputing.')
    args=parser.parse_args()
    manifest=json.loads((ROOT/'hotset_extension'/'manifest.json').read_text(encoding='utf-8'))
    for name,digest in manifest.items():
        path=ROOT/name
        if not path.is_file() or sha(path)!=digest:
            raise SystemExit('Input or retained evidence hash mismatch: '+name)
    print('Verified',len(manifest),'input and retained evidence files.',flush=True)
    if args.verify_only:
        return
    if args.output:
        dest=args.output.resolve()
        if dest.exists():
            raise SystemExit('Output directory already exists; choose a new --output path.')
    else:
        # Reserve a unique parent; the simulator creates its results child.
        dest=Path(tempfile.mkdtemp(prefix='sm9_hotset_'))/'results'
    subprocess.run([sys.executable,str(ROOT/'run_hotset_extension.py'),'--source',str(ROOT),'--output',str(dest)],check=True)
    tables=['hotset_expanded_runs.csv','hotset_expanded_summary.csv','hotset_expanded_paired.csv']
    for name in tables:
        if (RETAINED/name).read_bytes()!=(dest/name).read_bytes():
            raise SystemExit('Reproduced CSV differs: '+name)
    traces=sorted(RETAINED.glob('trace_*.npz'))
    if len(traces)!=630:
        raise SystemExit('Expected 630 retained identity/arrival arrays.')
    for path in traces:
        with np.load(path) as a,np.load(dest/path.name) as b:
            if a.files!=b.files or any(not np.array_equal(a[k],b[k]) for k in a.files):
                raise SystemExit('Reproduced array differs: '+path.name)
    with (dest/tables[0]).open(encoding='utf-8') as f:
        runs=list(csv.DictReader(f))
    new_runs=sum(int(r['hot']) in [9,10,12,14] for r in runs)
    if len(runs)!=5670 or new_runs!=3240:
        raise SystemExit('Unexpected experiment counts.')
    report={'passed':True,'csv_comparison':'Three tables byte-identical','npz_array_comparison':'630 files have identical arrays','new_evaluations':new_runs,'anchor_rechecks':len(runs)-new_runs,'output':str(dest)}
    (dest/'reproduction_check.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps(report,indent=2))

if __name__=='__main__':
    main()
