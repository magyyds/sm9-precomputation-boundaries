"""Saved-event diagnosis. The calibrated decomposition is analytical, not profiling."""
import json,statistics as S
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
DATA=ROOT/'results/siap-v3-20261021-02'
def read(p):return json.loads(p.read_text(encoding='utf-8'))
def diagnosis():
    blocks=[read(p) for p in sorted((DATA/'confirm').glob('*/summary.json'))]
    cal=read(DATA/'calibration/summary.json');delta=cal['delta_ns'];result={}
    for profile in ['stable_fit','stable_pressure','mixed','short','burst']:
        rows=[{r['method']:r for r in b['runs'] if r['profile']==profile} for b in blocks]
        comparisons={}
        for ref in ['twohit','tinylfu']:
            actual=[];miss=[];build=[];residual=[]
            for r in rows:
                actual.append(r['siap']['cpu_ns']-r[ref]['cpu_ns'])
                miss.append(delta*(r[ref]['table_hits']-r['siap']['table_hits']))
                build.append(r['siap']['a']['build_cpu_ns']-r[ref]['a']['build_cpu_ns'])
                residual.append(actual[-1]-miss[-1]-build[-1])
            comparisons[ref]={
                'measured_total_gap_ms_per_128':S.mean(actual)/1e6,
                'analytical_extra_miss_ms':S.mean(miss)/1e6,
                'measured_build_cpu_gap_ms':S.mean(build)/1e6,
                'UNATTRIBUTED_residual_ms':S.mean(residual)/1e6}
        abandoned=[];lost=[]
        for b in blocks:
            ev=read(DATA/'confirm'/str(b['seed'])/f'{profile}-siap.json');leases={};previous_credit=previous_build=0
            for e in ev:
                if e['token'] is not None:
                    lease=leases.setdefault(e['token'][0],{'credit':0,'built':False})
                    lease['credit']+=e['charged']-previous_credit
                    lease['built']|=e['builds']>previous_build
                previous_credit=e['charged'];previous_build=e['builds']
            abandoned.append(sum(not x['built'] for x in leases.values()))
            lost.append(sum(x['credit'] for x in leases.values() if not x['built']))
        result[profile]={
            'comparisons':comparisons,
            'mean_unbuilt_leases':S.mean(abandoned),
            'mean_charged_events_in_unbuilt_leases':S.mean(lost),
            'siap_mean_reservations':S.mean(r['siap']['a']['reservations'] for r in rows),
            'siap_mean_unused_builds':S.mean(r['siap']['a']['unused_builds'] for r in rows),
            'counts':{m:{'hits':S.mean(r[m]['table_hits'] for r in rows),'builds':S.mean(r[m]['a']['builds'] for r in rows)}
                      for m in ['siap','twohit','tinylfu']}}
    return {'source':'siap-v3-20261021-02','delta_ns':delta,'profiles':result,
            'warning':'Residual is not measured policy overhead. Includes calibration mismatch, native timing variation, common work and policy overhead.'}
if __name__=='__main__':
    p=Path(__file__).with_name('prior_diagnosis.json');p.write_text(json.dumps(diagnosis(),indent=2),encoding='utf-8');print(p)
