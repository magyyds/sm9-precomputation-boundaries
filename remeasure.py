"""Optional Linux/WSL timing run in a NEW directory; archival timings are preserved."""
from pathlib import Path
import argparse,shutil,subprocess,sys
ROOT=Path(__file__).resolve().parent
p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);p.add_argument('--processes',type=int,default=12);a=p.parse_args()
a.output.mkdir(parents=True,exist_ok=False)
for name in ['measure_revision.py','revision_policies.py']:shutil.copy2(ROOT/name,a.output/name)
subprocess.run([sys.executable,str(a.output/'measure_revision.py'),'--lab',str(ROOT/'measurement_backend'),'--processes',str(a.processes)],check=True)
print('New measurements are in',a.output/'revision_measurements')
