"""Seeded traffic schedules independent of cryptographic keys and runtime clocks."""
import hashlib
import json
import math
import random
from pathlib import Path

def generate(count, rate, seed=1, pattern='periodic', identities=8, churn=0,
             epoch_seconds=30, burst_size=8, trace=None):
    if not 0<count<=200000 or not math.isfinite(rate) or rate<=0 or identities<1 or churn<0:
        raise ValueError('schedule limits')
    if epoch_seconds<=0 or burst_size<1: raise ValueError('schedule epoch/burst')
    rng=random.Random(seed); offsets=[]; t=0.
    if trace:
        source=json.loads(Path(trace).read_text())
        if source.get('schema')!=1 or not source.get('messages'): raise ValueError('trace format')
        selected=source['messages'][:count]
        if len(selected)!=count: raise ValueError('trace shorter than requested count')
        rows=[]; previous=-1
        for row in selected:
            us=row['offset_us']; pid=row['pid']
            if type(us) is not int or us<previous or type(pid) is not int or not 0<pid<2**128:
                raise ValueError('noncanonical or unordered trace')
            if us<0:raise ValueError('negative trace timestamp')
            previous=us;item={'offset_us':us,'pid':pid,'epoch':1+int(us/(epoch_seconds*1e6))}
            if 'network_drop' in row or 'network_delay_us' in row:
                drop=row.get('network_drop',False);delay=row.get('network_delay_us',0)
                if type(drop) is not bool or type(delay) is not int or not 0<=delay<=60_000_000:raise ValueError('invalid network trace')
                item.update(network_drop=drop,network_delay_us=delay)
            rows.append(item)
        return rows
    if pattern not in ('periodic','poisson','burst'): raise ValueError('arrival pattern')
    seen_birth=0
    for i in range(count):
        if pattern=='periodic': t=i/rate
        elif pattern=='poisson': t+=rng.expovariate(rate)
        else: t=(i//burst_size)*burst_size/rate
        births=int(t*churn) if churn else 0
        # First packet after a birth uses the newest identity; old identities
        # remain selectable within a finite contact pool. Skipped births are logged.
        if births>seen_birth:
            pid=identities+births; seen_birth=births
        else: pid=rng.randrange(max(1,identities+births-identities+1),identities+births+1)
        offsets.append({'offset_us':round(t*1e6),'pid':pid,'epoch':1+int(t/epoch_seconds)})
    return offsets

def identity_envelope(rows, rate):
    seen=set(); times=[]
    for row in rows:
        key=(row['epoch'],row['pid'])
        if key not in seen: seen.add(key); times.append(row['offset_us']/1e6)
    # Sup over intervals of count - nu * length. Epoch changes count as new IDs.
    floor=float('inf'); excess=0.
    for j,t in enumerate(times):
        floor=min(floor,j-rate*t)
        excess=max(excess,j+1-rate*t-floor)
    return {'distinct_full_identities':len(seen),'nu_per_second':rate,
            'required_sigma_observed':math.ceil(max(0,excess)-1e-9)}

def digest(rows): return hashlib.sha256(json.dumps(rows,sort_keys=True,separators=(',',':')).encode()).hexdigest()
