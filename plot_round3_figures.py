"""Quantitative plots from retained R3 simulation outputs (no image generation)."""
from pathlib import Path
import sys,csv,json,os
import numpy as np
ROOT=Path(__file__).resolve().parent
if (ROOT.parent.parent/'.paper_tools').exists():sys.path.append(str(ROOT.parent.parent/'.paper_tools'))
if os.environ.get('SM9_PLOT_TOOLS'):sys.path.append(os.environ['SM9_PLOT_TOOLS'])
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.colors import TwoSlopeNorm,LogNorm
sys.path.insert(0,str(ROOT/'qa_helpers'))
from audit_panel_alignment import require_matplotlib_panel_alignment
OUT=ROOT/'revision_figures';QA=ROOT/'revision_figure_qa'
plt.rcParams.update({'font.family':'sans-serif','font.sans-serif':['Arial','DejaVu Sans'],'font.size':8,'axes.labelsize':8,'axes.titlesize':8.5,'legend.fontsize':8,'axes.spines.top':False,'axes.spines.right':False,'axes.linewidth':.6,'svg.fonttype':'none','pdf.fonttype':42,'legend.frameon':False,'savefig.facecolor':'white'})
DATA={}
def read(n):
    rows=list(csv.DictReader((ROOT/'round3_results'/n).open(encoding='utf-8-sig')))
    for r in rows:
        for k,v in r.items():
            try:r[k]=float(v)
            except ValueError:pass
    return rows
def save(fig,name,data):
    fig.canvas.draw();require_matplotlib_panel_alignment(fig,json_out=str(QA/(name+'.alignment.json')),strict=True,tolerance_pt=1.5,gutter_tolerance_pt=1.5)
    fig.savefig(OUT/(name+'.pdf'));fig.savefig(OUT/(name+'.svg'));fig.savefig(OUT/(name+'.png'),dpi=600)
    plt.close(fig);DATA[name]=data
def panel(ax,letter,title):
    ax.set_title(title,loc='left',pad=8);ax.text(-.15,1.06,letter,transform=ax.transAxes,fontweight='bold',fontsize=10)

rows=read('hotset_scan_summary.csv');source=[r for r in rows if r['rho']==.95]
fig,axs=plt.subplots(1,2,figsize=(7.0866,2.65));fig.subplots_adjust(left=.10,right=.87,bottom=.28,top=.84,wspace=.64)
for i,(ax,metric,title,lo,hi) in enumerate(zip(axs,['cpu_saving_pct','gain_pp'],['Service-cost saving (%)','Completion gain (pp)'],[-.5,-4],[5,16])):
    vals=np.array([[next(r[metric] for r in source if r['hot']==h and r['scan']==s and r['method']=='Second-hit') for s in [.1,.2,.4]] for h in [4,8,16]])
    im=ax.imshow(vals,cmap='RdBu',norm=TwoSlopeNorm(vmin=lo,vcenter=0,vmax=hi),aspect='auto')
    for y,h in enumerate([4,8,16]):
        for x,s in enumerate([.1,.2,.4]):
            choices=[r for r in source if r['hot']==h and r['scan']==s]
            best=max(r['cpu_saving_pct'] for r in choices)
            near=[r['method'] for r in choices if best-r['cpu_saving_pct']<=.01]
            mark='S/F' if len(near)==2 else ('S' if near==['Second-hit'] else 'F')
            v=vals[y,x];color='white' if abs(im.norm(v)-.5)>.28 else '#151515'
            ax.text(x,y,f'{v:+.2f}'+ ('\n'+mark if i==0 else ''),ha='center',va='center',fontsize=8,color=color)
    ax.set_xticks(range(3),['10','20','40']);ax.set_yticks(range(3),['0.5','1','2']);ax.set_xlabel('Scan share (%)');ax.set_ylabel('Hot set / table capacity (H/K)');panel(ax,'ab'[i],title)
    pos=ax.get_position();cax=fig.add_axes([pos.x1+.012,pos.y0,.012,pos.height]);fig.colorbar(im,cax=cax,ticks=[lo,0,hi])
fig.text(.5,.025,'S / F: Second-hit / Window frequency within 0.01 pp of best mean cost saving',ha='center',fontsize=7.5)
save(fig,'fig5_scope',{'rows':source,'K':8,'rho':.95,'deadline_ms':100,'n_seed_blocks':30,'mark_tolerance_pp':.01,'heatmap_uncertainty':'Cell means; conditional 95% intervals for every cell are in hotset_scan_summary.csv. Markers are descriptive, not equivalence tests.'})

rows=read('deadline_summary.csv');fig,axs=plt.subplots(1,3,figsize=(7.0866,2.65));fig.subplots_adjust(left=.075,right=.98,bottom=.23,top=.74,wspace=.30)
colors={'Q-only':'#666666','Second-hit':'#008C82','Window-Frequency':'#876BA6'}
for ax,threshold,letter in zip(axs,[50,100,200],'abc'):
    for m,style,marker in zip(colors,['-','-','--'],['o','o','s']):
        rr=[r for r in rows if r['deadline_ms']==threshold and r['method']==m];rr.sort(key=lambda r:r['rho'])
        x=np.array([r['rho'] for r in rr]);v=np.array([r['ontime_pct'] for r in rr]);lo=np.array([r['ontime_pct_lo'] for r in rr]);hi=np.array([r['ontime_pct_hi'] for r in rr])
        ax.fill_between(x,lo,hi,color=colors[m],alpha=.12,linewidth=0)
        ax.plot(x,v,ls=style,marker=marker,mfc='white' if m=='Window-Frequency' else colors[m],color=colors[m],lw=1,ms=3,label=m.replace('Window-Frequency','Window frequency'))
    ax.set_ylim(0,104);ax.set_xlim(.48,1.07);ax.set_xticks([.5,.8,.95,1.05],['0.50','0.80','0.95','1.05']);ax.tick_params(axis='x',labelsize=7);ax.set_yticks([0,25,50,75,100]);ax.set_xlabel('Reference load ρ');ax.grid(axis='y',alpha=.15);panel(ax,letter,f'Deadline {threshold} ms')
axs[0].set_ylabel('On-time completion (%)');fig.legend(*axs[0].get_legend_handles_labels(),loc='upper center',ncol=3,bbox_to_anchor=(.52,1.015))
save(fig,'supp_deadlines',{'rows':rows,'n_seed_blocks':30,'bands':'Conditional percentile 95% bootstrap intervals, 10000 resamples; policies share seeds and arrivals. 500 ms retained in source data.'})

fig,axs=plt.subplots(2,2,figsize=(7.0866,4.1));fig.subplots_adjust(left=.10,right=.84,bottom=.16,top=.92,wspace=.44,hspace=.55)
source=[]
for ax,(fam,k,title),letter in zip(axs.flat,[('mixed_scan',2,'Mixed scan, K = 2'),('mixed_scan',8,'Mixed scan, K = 8'),('bursts4',8,'Four-message bursts, K = 8'),('pressure64',8,'Capacity pressure, K = 8')],'abcd'):
    path=ROOT/'round3_traces'/f'near_ties_{fam}_K{k}.npz'
    with np.load(path) as z:bs=z['B_ms'];ds=z['delta_ms'];gap=z['gap_pct']
    im=ax.pcolormesh(bs,ds,np.maximum(gap,1e-4),norm=LogNorm(1e-4,10),cmap='viridis',shading='nearest',rasterized=True)
    if gap.min()<.01<gap.max():ax.contour(bs,ds,gap,levels=[.01],colors='white',linewidths=.7)
    ax.plot(.3842044088541667,.3178286054687502,'o',mfc='white',mec='black',ms=4)
    ax.set_xlim(0,.8);ax.set_ylim(0,.65);ax.set_xticks([0,.2,.4,.6,.8]);ax.set_yticks([0,.2,.4,.6]);ax.set_xlabel('Construction B (ms)');ax.set_ylabel('Hit saving δ (ms)');panel(ax,letter,title)
    source.append({'family':fam,'k':k,'B_ms':bs.tolist(),'delta_ms':ds.tolist(),'gap_pct':gap.tolist(),'input':path.relative_to(ROOT).as_posix()})
cax=fig.add_axes([.88,.30,.018,.50]);cb=fig.colorbar(im,cax=cax,ticks=[.0001,.001,.01,.1,1,10]);cb.ax.set_yticklabels(['≤0.0001','0.001','0.01','0.1','1','10']);cb.set_label('Runner-up minus best (% of Nq)')
fig.text(.5,.025,'White contour: 0.01 pp descriptive tolerance; circles: calibrated costs',ha='center',fontsize=8)
save(fig,'supp_nearties',{'panels':source,'normalization':'100 * (W_runnerup - W_best) / (N*q); six policies, mean counts over 30 traces','display_floor_pp':.0001,'tolerance_pp':.01,'uncertainty':'Deterministic mean-cost surfaces; tolerance is not a statistical equivalence margin.'})
(ROOT/'round3_figure_source_data.json').write_text(json.dumps(DATA,ensure_ascii=False,indent=2,allow_nan=False),encoding='utf-8')
print('Exported Fig. 5, Fig. S4 and Fig. S5 as 600 dpi PNG, PDF and SVG.')
