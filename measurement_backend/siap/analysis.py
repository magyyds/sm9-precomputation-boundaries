"""Plan-based denominator, explicit missing messages, run-level paired bootstrap."""
import json
import random
import statistics
from collections import Counter
from pathlib import Path

def rows(path):
    with Path(path).open() as f:
        for line in f:
            if line.strip(): yield json.loads(line)

def quantile(values,p):
    if not values: return None
    s=sorted(values); x=(len(s)-1)*p; lo=int(x); hi=min(lo+1,len(s)-1)
    return s[lo]+(s[hi]-s[lo])*(x-lo)

def summarize(scenario,sender,receiver,deadline_ms=100,same_host=False):
    scenario,sender,receiver=map(Path,(scenario,sender,receiver))
    plan=[p for p in rows(scenario/'plan.jsonl') if p['kind']=='legitimate' and p['phase']=='observe']
    if not plan: raise ValueError('empty observation denominator')
    sent={p['index']:p for p in rows(sender/'sender.jsonl')}
    events=list(rows(receiver/'events.jsonl')); grouped={}
    for e in events:
        if e.get('handed_off_ns') is not None and e.get('accepted_ns') is None: raise ValueError('handoff without acceptance')
        if e.get('accepted_ns') is not None and e.get('verified_ns') is None: raise ValueError('acceptance without verification')
    for e in events: grouped.setdefault(e['packet_sha256'],[]).append(e)
    if same_host:
        a=json.loads((sender/'inventory.json').read_text()); b=json.loads((receiver/'inventory.json').read_text())
        if not a.get('boot_id') or (a['boot_id'],a['hostname'])!=(b.get('boot_id'),b['hostname']):
            raise ValueError('cannot compare cross-host monotonic clocks')
    accepted=Counter((e.get('identity'),e.get('counter')) for e in events if e.get('accepted_ns') is not None)
    duplicates=sum(max(0,n-1) for n in accepted.values())
    terminal=Counter(); local_delays=[]; end_delays=[]; delivered=timely=local_timely=0
    for p in plan:
        candidates=grouped.get(sent.get(p['index'],{}).get('packet_sha256',p['packet_sha256']),[])
        successes=[e for e in candidates if e.get('handed_off_ns') is not None]
        if successes:
            e=min(successes,key=lambda e:e['handed_off_ns']); delivered+=1
            local=(e['handed_off_ns']-e['ingress_ns'])/1e6; local_delays.append(local)
            local_timely+=local<=deadline_ms
            if same_host:
                if p['index'] not in sent: raise ValueError('sender log missing schedule entry')
                latency=(e['handed_off_ns']-sent[p['index']]['scheduled_ns'])/1e6
                if latency<0: raise ValueError('negative planned latency')
                end_delays.append(latency); timely+=latency<=deadline_ms
                terminal['delivered' if latency<=deadline_ms else 'late_delivered']+=1
            else: terminal['delivered_unaligned_clocks']+=1
        elif candidates:
            terminal[candidates[0]['reason']]+=1
        else:
            reason=sent.get(p['index'],{}).get('reason')
            terminal['simulated_network_drop' if reason=='simulated_network_drop' else 'sender_missed' if reason in ('sender_missed','send_error') else 'network_missing']+=1
    if sum(terminal.values())!=len(plan): raise AssertionError('denominator not conserved')
    if duplicates: raise AssertionError(f'duplicate acceptance: {duplicates}')
    config=json.loads((scenario/'scenario.json').read_text())
    return {'evidence':'measured_crypto_with_simulated_network_trace' if config.get('network_trace') else 'measured_online_signed_udp' if config.get('mode')=='online_signing' else 'measured_offline_signed_udp','seed':config['seed'],
            'n_scheduled':len(plan),'n_delivered':delivered,'p_delivered':delivered/len(plan),
            'p_timely':timely/len(plan) if same_host else None,
            'receiver_timely_over_scheduled':local_timely/len(plan),'deadline_ms':deadline_ms,
            'latency_scope':'scheduled_send_to_handoff_same_boot' if same_host else 'ingress_to_handoff',
            'local_latency_ms':{'p50':quantile(local_delays,.5),'p95':quantile(local_delays,.95),
                               'p99':quantile(local_delays,.99) if len(local_delays)>=100 else None},
            'end_latency_ms':{'p50':quantile(end_delays,.5),'p95':quantile(end_delays,.95),
                             'p99':quantile(end_delays,.99) if len(end_delays)>=100 else None},
            'terminal_counts':dict(terminal),'duplicate_accepts':duplicates,
            'all_packet_reasons':dict(Counter(e['reason'] for e in events)),
            'worker_cpu_ns_total':sum(e.get('cpu_ns',0) for e in events),
            'cpu_ns_all_over_scheduled':sum(e.get('cpu_ns',0) for e in events)/len(plan),
            'signing_mode':config.get('mode','offline_signed_receiver_workload'),
            'note':'Online mode includes signing in scheduled-send latency; offline mode excludes it. Worker CPU excludes transport/controller/log I/O.'}

def paired_bootstrap(left,right,seed=20261015,repeats=10000):
    if set(left)!=set(right) or len(left)<2: raise ValueError('need >=2 matching independent run seeds')
    if any(v is None or not 0<=v<=1 for v in [*left.values(),*right.values()]): raise ValueError('invalid endpoint')
    diffs=[left[k]-right[k] for k in sorted(left)]; rng=random.Random(seed)
    samples=[statistics.mean(rng.choices(diffs,k=len(diffs))) for _ in range(repeats)]
    return {'n_pairs':len(diffs),'mean_difference':statistics.mean(diffs),
            'ci95':[quantile(samples,.025),quantile(samples,.975)],'unit':'independent_run',
            'exploratory':len(diffs)<30,'bootstrap_seed':seed,'replicates':repeats}


def compare_files(left,right):
    def load(paths):
        result={}
        for path in paths:
            s=json.loads(Path(path).read_text());seed=s['seed']
            if seed in result:raise ValueError('duplicate run seed')
            result[seed]=s
        return result
    a,b=load(left),load(right)
    if set(a)!=set(b):raise ValueError('unpaired seeds')
    for seed in a:
        for key in ('workload_sha256','n_scheduled','deadline_ms','signing_mode','comparison_parameters'):
            if a[seed].get(key)!=b[seed].get(key):raise ValueError('paired workload/configuration mismatch: '+key)
    return paired_bootstrap({k:v['p_timely'] for k,v in a.items()},{k:v['p_timely'] for k,v in b.items()})
