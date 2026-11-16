"""Figures for the reviewer-driven revision. Numeric marks use archived outputs."""
from pathlib import Path
import sys,json,csv
import numpy as np
ROOT=Path(__file__).resolve().parent
if (ROOT.parent.parent/'.paper_tools').exists():sys.path.append(str(ROOT.parent.parent/'.paper_tools'))
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.colors import ListedColormap,BoundaryNorm
from matplotlib.patches import Patch
sys.path.insert(0,str(ROOT/'qa_helpers'))
from audit_panel_alignment import require_matplotlib_panel_alignment
OUT=ROOT/'revision_figures';OUT.mkdir(exist_ok=True)
QA=ROOT/'revision_figure_qa';QA.mkdir(exist_ok=True)
def read(name):
    rows=list(csv.DictReader((ROOT/'revision_results'/name).open(encoding='utf-8-sig')))
    for r in rows:
        for k,v in r.items():
            try:r[k]=float(v)
            except ValueError:pass
    return rows
S=read('primary_summary.csv');R=read('robustness_summary.csv')
C=json.loads((ROOT/'revision_results/revision_config.json').read_text())
M=json.loads((ROOT/'revision_results/measurement_summary.json').read_text())
METHODS=['Q-only','Immediate','Second-hit','Third-hit','LRU-2','Window-Frequency']
COLOR=dict(zip(METHODS,['#EEEEEE','#45678B','#008C82','#CE5945','#998048','#876BA6']))
LABEL={'Window-Frequency':'Window frequency','Q-only':'Q-only',**{k:k for k in METHODS[1:-1]}}
FAMS=['stable8','pressure64','short2','bursts4','mixed_scan','shift8']
FLAB=['Stable eight','Capacity pressure','Short contacts','Four-message bursts','Mixed scan','Hotspot shift']
plt.rcParams.update({'font.family':'sans-serif','font.sans-serif':['Arial','DejaVu Sans'],'font.size':8,'axes.labelsize':8,'axes.titlesize':8.5,'legend.fontsize':7.5,'axes.spines.top':False,'axes.spines.right':False,'axes.linewidth':.6,'svg.fonttype':'none','pdf.fonttype':42,'legend.frameon':False,'savefig.facecolor':'white'})
DATA={}
def sel(f,m,k=8,rho=.95):return next(r for r in S if r['family']==f and r['method']==m and r['slots']==k and r['rho']==rho)
def save(fig,name,data):
    fig.canvas.draw();require_matplotlib_panel_alignment(fig,json_out=str(QA/(name+'.alignment.json')),strict=True,tolerance_pt=1.5,gutter_tolerance_pt=1.5)
    fig.savefig(OUT/(name+'.pdf'));fig.savefig(OUT/(name+'.svg'));fig.savefig(OUT/(name+'.png'),dpi=600);plt.close(fig);DATA[name]=data
def panel(ax,letter,title):ax.set_title(title,loc='left',pad=7);ax.text(-.17,1.06,letter,transform=ax.transAxes,fontweight='bold',fontsize=10)

# Exact service-cost envelope under the measured overheads. This is not an
# estimated online oracle or a deadline-optimal policy map.
fig,axs=plt.subplots(2,2,figsize=(7.0866,4.1));fig.subplots_adjust(left=.10,right=.98,bottom=.23,top=.91,hspace=.50,wspace=.32)
bgrid=np.linspace(0,.8,161);dgrid=np.linspace(0,.65,131);bb,dd=np.meshgrid(bgrid,dgrid);mapdata=[]
for ax,(f,k,title),letter in zip(axs.flat,[('mixed_scan',2,'Mixed scan, K = 2'),('mixed_scan',8,'Mixed scan, K = 8'),('bursts4',8,'Four-message bursts, K = 8'),('pressure64',8,'Capacity pressure, K = 8')],'abcd'):
    costs=[];lines=[]
    for method in METHODS:
        r=sel(f,method,k);pp=C['primary_costs_ms']['policy'][method]
        costs.append(r['builds']*bb-r['hits']*dd+4096*pp)
        if method=='Second-hit':
            boundary=(r['builds']*bgrid+4096*pp)/max(r['hits'],1)
            lines=boundary.tolist()
    winner=np.argmin(np.stack(costs),axis=0)
    ax.pcolormesh(bgrid,dgrid,winner,cmap=ListedColormap([COLOR[m] for m in METHODS]),norm=BoundaryNorm(np.arange(-.5,6.5),6),shading='nearest',rasterized=True)
    mask=np.array(lines)<=.65;ax.plot(bgrid[mask],np.array(lines)[mask],color='black',ls='--',lw=.8)
    ax.plot(C['primary_costs_ms']['build'],C['primary_costs_ms']['delta'],'o',mfc='white',mec='black',ms=4)
    ax.set_xlim(0,.8);ax.set_ylim(0,.65);ax.set_xticks([0,.2,.4,.6,.8]);ax.set_yticks([0,.2,.4,.6]);ax.set_xlabel('Construction B (ms)',fontsize=8.5);ax.set_ylabel('Hit saving δ (ms)',fontsize=8.5);panel(ax,letter,title)
    mapdata.append({'family':f,'slots':k,'b_grid':bgrid.tolist(),'delta_grid':dgrid.tolist(),'winner_index':winner.tolist(),'second_hit_zero_gain':lines})
fig.legend(handles=[Patch(facecolor=COLOR[m],edgecolor='#BBBBBB',label=LABEL[m]) for m in METHODS],loc='lower center',bbox_to_anchor=(.5,.015),ncol=3,fontsize=8)
save(fig,'fig1_boundaries',mapdata)

fig,ax=plt.subplots(figsize=(7.0866,2.85));fig.subplots_adjust(left=.225,right=.985,bottom=.19,top=.78)
source=[]
for j,m in enumerate(METHODS[1:]):
    rr=[sel(f,m) for f in FAMS];source+=rr;y=np.arange(6)+(j-2)*.13
    v=np.array([r['cpu_saving_pct'] for r in rr]);lo=np.array([r['cpu_saving_pct_lo'] for r in rr]);hi=np.array([r['cpu_saving_pct_hi'] for r in rr])
    ax.errorbar(v,y,xerr=[v-lo,hi-v],fmt=['o','s','D','^','v'][j],color=COLOR[m],ms=3.6,lw=.8,capsize=2,label=LABEL[m])
ax.axvline(0,color='#777777',ls='--',lw=.7);ax.set_yticks(range(6),FLAB);ax.invert_yaxis();ax.set_xlabel('Service-cost saving relative to Q-only (%)');ax.set_xticks([-6,-4,-2,0,2,4,6]);ax.grid(axis='x',alpha=.12)
fig.legend(*ax.get_legend_handles_labels(),loc='upper center',ncol=3,bbox_to_anchor=(.57,1.01))
save(fig,'fig2_baselines',source)

fig,axs=plt.subplots(1,2,figsize=(7.0866,2.8));fig.subplots_adjust(left=.10,right=.98,bottom=.20,top=.76,wspace=.60)
qsource=[]
for j,m in enumerate(METHODS):
    rr=[sel('mixed_scan',m,rho=r) for r in [.5,.8,.95,1,1.05]];qsource+=rr
    x=[r['rho'] for r in rr];y=[r['ontime_pct'] for r in rr];lo=[r['ontime_pct_lo'] for r in rr];hi=[r['ontime_pct_hi'] for r in rr]
    color='#6B7377' if m=='Q-only' else COLOR[m]
    axs[0].plot(x,y,color=color,lw=1,marker=['s','o','^','D','v','x'][j],ms=3,label=LABEL[m],ls='--' if m in ['Third-hit','Window-Frequency'] else '-')
    axs[0].fill_between(x,lo,hi,color=color,alpha=.08,linewidth=0)
for j,m in enumerate(METHODS[1:]):
    r=sel('mixed_scan',m);v=r['difference_pp']
    axs[1].errorbar(v,j,xerr=[[v-r['difference_pp_lo']],[r['difference_pp_hi']-v]],fmt='o',color=COLOR[m],ms=4,capsize=3)
axs[0].set_xticks([.5,.8,.95,1.05],['0.50','0.80','0.95','1.05']);axs[0].set_xlabel('Reference arrival load ρ');axs[0].set_ylabel('Completed within 100 ms (%)');axs[0].set_ylim(0,104)
axs[1].set_yticks(range(5),[LABEL[m] for m in METHODS[1:]]);axs[1].invert_yaxis();axs[1].axvline(0,color='#888888',ls='--',lw=.7);axs[1].set_xlabel('Paired gain over Q-only (pp)')
panel(axs[0],'a','Mixed scan, K = 8');panel(axs[1],'b','Paired gain at ρ = 0.95')
fig.legend(*axs[0].get_legend_handles_labels(),loc='upper center',bbox_to_anchor=(.52,1.01),ncol=3)
save(fig,'fig3_queue',qsource)

fig,axs=plt.subplots(1,2,figsize=(7.0866,2.8));fig.subplots_adjust(left=.20,right=.985,bottom=.20,top=.77,wspace=.47)
rob=[];families=['mixed_scan','shift8','rotating_hotspots','bursty_migration'];labels=['Mixed scan','Hotspot shift','Rotating hotspots','Bursty migration']
for ax,model,letter in zip(axs,['fixed','empirical'],'ab'):
    for j,m in enumerate(['Second-hit','Third-hit','Window-Frequency']):
        rr=[next(r for r in R if r['family']==f and r['method']==m and r['rho']==.95 and r['service_model']==model) for f in families];rob+=rr
        v=np.array([r['difference_pp'] for r in rr]);lo=np.array([r['difference_pp_lo'] for r in rr]);hi=np.array([r['difference_pp_hi'] for r in rr])
        ax.errorbar(v,np.arange(4)+(j-1)*.18,xerr=[v-lo,hi-v],fmt=['s','D','v'][j],ms=3.5,color=COLOR[m],capsize=2,lw=.9,label=LABEL[m])
    ax.set_xlim(0,26);ax.set_xticks([0,5,10,15,20,25]);ax.set_yticks(range(4),labels if letter=='a' else []);ax.invert_yaxis();ax.set_xlabel('Paired completion gain (pp)');panel(ax,letter,'Fixed service' if model=='fixed' else 'Empirical service draws')
fig.legend(*axs[0].get_legend_handles_labels(),loc='upper center',bbox_to_anchor=(.55,1.01),ncol=3)
save(fig,'fig4_robustness',rob)

# Supplementary joint perturbation matrix. Include all tested combinations.
J=read('joint_sensitivity_summary.csv');fig,axs=plt.subplots(1,3,figsize=(7.0866,2.7));fig.subplots_adjust(left=.08,right=.94,bottom=.28,top=.83,wspace=.38)
jsource=[]
for ax,bs,letter in zip(axs,[.5,1,1.5],'abc'):
    mat=np.empty((3,4))
    for i,ds in enumerate([.5,1,1.5]):
        for j,p in enumerate([0,.01,.05,.1]):
            r=next(r for r in J if r['family']=='mixed_scan' and r['method']=='Second-hit' and r['rho']==.95 and r['build_scale']==bs and r['delta_scale']==ds and r['policy_ms']==p);jsource.append(r);mat[i,j]=r['difference_pp']
    im=ax.imshow(mat,origin='lower',cmap='viridis',vmin=0,vmax=20,aspect='auto')
    for i in range(3):
        for j in range(4):ax.text(j,i,f'{mat[i,j]:.1f}',ha='center',va='center',fontsize=7,color='white' if mat[i,j]<9 else 'black')
    ax.set_xticks(range(4),['0','.01','.05','.10']);ax.set_yticks(range(3),['0.5','1','1.5']);ax.set_xlabel('Policy p (ms)');ax.set_ylabel('δ multiplier');panel(ax,letter,f'B × {bs:g}')
fig.text(.5,.05,'Colour shows paired 100-ms completion gain over Q-only (pp), range 0–20.',ha='center',fontsize=8)
save(fig,'supp_joint',jsource)
W=read('frequency_window_summary.csv');fig,axs=plt.subplots(1,2,figsize=(7.0866,2.6));fig.subplots_adjust(left=.10,right=.985,bottom=.22,top=.77,wspace=.38)
wsource=[]
for ax,field,letter in zip(axs,['cpu_saving_pct','difference_pp'],'ab'):
    for j,f in enumerate(families):
        rr=[r for r in W if r['family']==f and r['rho']==.95];rr.sort(key=lambda x:x['window']);wsource+=rr if letter=='a' else []
        xx=np.arange(4);yy=np.array([r[field] for r in rr]);lo=np.array([r[field+'_lo'] for r in rr]);hi=np.array([r[field+'_hi'] for r in rr]);ax.errorbar(xx,yy,yerr=[yy-lo,hi-yy],marker='o',ms=3,capsize=2,lw=.9,label=labels[j])
    ax.set_xticks(range(4),['128','512','1024','4096']);ax.set_xlabel('Frequency history window (messages)');ax.set_ylabel('Service saving (%)' if letter=='a' else 'Completion gain (pp)');panel(ax,letter,'Window-frequency sensitivity')
fig.legend(*axs[0].get_legend_handles_labels(),loc='upper center',bbox_to_anchor=(.52,1.01),ncol=2)
save(fig,'supp_window',wsource)
# Joint timing dependence check: one inferential question, one forest panel.
joint=list(csv.DictReader((ROOT/'round2_results/dependent_service_summary.csv').open(encoding='utf-8-sig')))
fig,ax=plt.subplots(figsize=(7.0866,2.8));fig.subplots_adjust(left=.23,right=.97,bottom=.20,top=.79)
source=[]
for j,(model,label,color,marker) in enumerate([('independent','Independent draws','#45678B','o'),('joint_cycle','Joint measurement cycle','#008C82','s'),('process_block128','Process blocks (128)','#CE5945','D')]):
    rr=[next(r for r in joint if r['family']==f and r['service_model']==model and r['method']=='Second-hit' and float(r['rho'])==.95) for f in families];source.extend(rr)
    v=np.array([float(r['difference_pp']) for r in rr]);lo=np.array([float(r['difference_pp_lo']) for r in rr]);hi=np.array([float(r['difference_pp_hi']) for r in rr])
    ax.errorbar(v,np.arange(4)+(j-1)*.2,xerr=[v-lo,hi-v],fmt=marker,color=color,ms=4,lw=1,capsize=2,label=label)
ax.set_yticks(range(4),labels);ax.invert_yaxis();ax.set_xlim(0,25);ax.set_xticks([0,5,10,15,20,25]);ax.set_xlabel('Second-hit completion gain over Q-only (pp)')
fig.legend(*ax.get_legend_handles_labels(),loc='upper center',ncol=3,bbox_to_anchor=(.55,1.0))
save(fig,'supp_dependence',source)
DATA['boundary_definition']={'objective':'argmin over methods of N*q + mean(N_B)*B - mean(N_H)*delta + N*p_method','mean_over':'30 seed traces, separately by workload and K','tie_order':METHODS,'grid_B_ms':[0,.8,161],'grid_delta_ms':[0,.65,131],'interpretation':'mean service cost only, not completion optimality or selection confidence'}
(ROOT/'revision_figure_source_data.json').write_text(json.dumps(DATA,ensure_ascii=False,indent=2),encoding='utf-8')
print('Saved four main and three supplementary figures')
