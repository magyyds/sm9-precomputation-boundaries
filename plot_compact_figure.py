"""Reproduce the compact, single-column Fig. 2 from retained numerical results."""
from pathlib import Path
import argparse,csv,hashlib,json,sys
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'qa_helpers'))
from audit_panel_alignment import require_matplotlib_panel_alignment
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--output',type=Path,default=ROOT/'reproduced_compact_figure')
args=parser.parse_args()
R=args.output.resolve();R.mkdir(parents=True,exist_ok=True)
DATA=ROOT/'revision_results'/'primary_summary.csv'
rows=list(csv.DictReader(DATA.open(encoding='utf-8-sig')))
methods=['Immediate','Second-hit','Third-hit','LRU-2','Window-Frequency']
colors=['#45678B','#008C82','#CE5945','#998048','#876BA6']
families=['stable8','pressure64','short2','bursts4','mixed_scan','shift8']
labels=['Stable eight','Capacity pressure','Short contacts','Four-message bursts','Mixed scan','Hotspot shift']
# Contract: preserve every original six-family/five-policy mean and conditional
# 95% interval at K=8, rho=.95. Only the physical layout changes to one column.
plt.rcParams.update({'font.family':'sans-serif','font.sans-serif':['Arial','DejaVu Sans'],'font.size':7,'axes.labelsize':7,'legend.fontsize':6.5,'axes.spines.top':False,'axes.spines.right':False,'axes.linewidth':.6,'svg.fonttype':'none','pdf.fonttype':42,'legend.frameon':False})
fig,ax=plt.subplots(figsize=(3.45,2.50))
fig.subplots_adjust(left=.32,right=.98,bottom=.18,top=.77)
source=[]
for j,(method,color) in enumerate(zip(methods,colors)):
    rr=[next(r for r in rows if r['family']==f and r['method']==method and int(r['slots'])==8 and float(r['rho'])==.95) for f in families]
    source+=rr
    value=np.array([float(r['cpu_saving_pct']) for r in rr]);lo=np.array([float(r['cpu_saving_pct_lo']) for r in rr]);hi=np.array([float(r['cpu_saving_pct_hi']) for r in rr])
    ax.errorbar(value,np.arange(6)+(j-2)*.13,xerr=[value-lo,hi-value],fmt=['o','s','D','^','v'][j],color=color,ms=2.8,lw=.65,capsize=1.6,label=method)
ax.axvline(0,color='#777777',ls='--',lw=.65)
ax.set_yticks(range(6),labels);ax.invert_yaxis();ax.set_xticks([-6,-4,-2,0,2,4,6]);ax.tick_params(length=2,pad=2)
ax.set_xlabel('Service-cost saving relative to Q-only (%)',labelpad=4)
ax.grid(axis='x',alpha=.12)
fig.legend(*ax.get_legend_handles_labels(),loc='upper center',ncol=2,bbox_to_anchor=(.51,.99),columnspacing=1.2,handletextpad=.4,borderaxespad=0)
fig.canvas.draw()
require_matplotlib_panel_alignment(fig,json_out=str(R/'fig2_single_column.alignment.json'),strict=True)
fig.savefig(R/'fig2_single_column.pdf')
fig.savefig(R/'fig2_single_column.svg')
fig.savefig(R/'fig2_single_column.png',dpi=600)
fig.savefig(R/'fig2_single_column.tiff',dpi=600)
plt.close(fig)
(R/'fig2_source.json').write_text(json.dumps({'rows':source,'n':30,'intervals':'descriptive pointwise conditional 95%, unadjusted','input_sha256':hashlib.sha256(DATA.read_bytes()).hexdigest(),'excluded_original_data':0},indent=2),encoding='utf-8')
