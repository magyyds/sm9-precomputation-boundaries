import csv
import hashlib
import json
import math
import random
import statistics
import subprocess
import sys
import time
from pathlib import Path
from .crypto import keygen, extract, sign, Verifier
from .analysis import quantile
from .artifacts import write_json, inventory, manifest,code_fingerprint

def load_calibration(path):
    result=json.loads(Path(path).read_text())
    binary=Path(__file__).resolve().parents[1]/'build/libsiap_crypto.so'
    if result['native_sha256']!=hashlib.sha256(binary.read_bytes()).hexdigest():
        raise ValueError('calibration binary mismatch; recalibrate on this target')
    if result.get('code_fingerprint')!=code_fingerprint():
        raise ValueError('calibration source/dependency mismatch; recalibrate this version')
    current=inventory()
    if (result['inventory']['machine'],result['inventory']['hostname'])!=(current['machine'],current['hostname']):
        raise ValueError('calibration host mismatch; recalibrate on this target')
    return result

def micro(folder,samples=200,warmup=1,seed=1,precompute='q'):
    if samples<2 or warmup<0: raise ValueError('benchmark configuration')
    folder=Path(folder); folder.mkdir(parents=True,exist_ok=False)
    sk,pk=keygen(); identity=b'V2XSM9ID2-benchmark-identity'; key=extract(sk,identity)
    verifier=Verifier(pk,precompute); message=b'x'*200; sig=sign(key,message); q=verifier.build(identity)
    end=time.monotonic()+warmup
    while time.monotonic()<end: verifier.verify(identity,message,sig,q)
    rng=random.Random(seed); data={name:[] for name in ('build','cold','hot','sign')}
    with (folder/'samples.csv').open('x',newline='') as f:
        writer=csv.writer(f); writer.writerow(['sample','operation','thread_cpu_ns','wall_ns'])
        for i in range(samples):
            operations=list(data); rng.shuffle(operations)
            for op in operations:
                cpu=time.thread_time_ns(); wall=time.monotonic_ns()
                if op=='build': verifier.build(identity,q)
                elif op=='sign': sig=sign(key,message)
                else:
                    if not verifier.verify(identity,message,sig,q if op=='hot' else None): raise AssertionError('valid signature rejected')
                elapsed_wall=time.monotonic_ns()-wall; elapsed_cpu=time.thread_time_ns()-cpu
                data[op].append(elapsed_cpu); writer.writerow([i,op,elapsed_cpu,elapsed_wall])
    summary={op:{'mean_cpu_ns':statistics.mean(values),'p50_cpu_ns':quantile(values,.5),
                 'p95_cpu_ns':quantile(values,.95)} for op,values in data.items()}
    summary.update(samples=samples,seed=seed,warmup_seconds=warmup,q_bytes=verifier.q_size,
                   precompute=precompute,scope='ctypes_boundary_included_complete_SM9',evidence='single_process_measurement')
    write_json(folder/'summary.json',summary); write_json(folder/'inventory.json',inventory())
    manifest(folder); verifier.close(); return summary

def calibrate(folder,runs=3,samples=100,warmup=1,precompute='q'):
    if runs<2: raise ValueError('need at least two independent processes')
    folder=Path(folder); folder.mkdir(parents=True,exist_ok=False)
    summaries=[]
    for i in range(runs):
        out=folder/f'process-{i:03d}'
        subprocess.run([sys.executable,'-m','siap','micro','--out',str(out),'--samples',str(samples),
                        '--warmup',str(warmup),'--seed',str(i),'--precompute',precompute],check=True,stdout=subprocess.DEVNULL)
        summaries.append(json.loads((out/'summary.json').read_text()))
    deltas=[s['cold']['mean_cpu_ns']-s['hot']['mean_cpu_ns'] for s in summaries]
    rng=random.Random(20261015)
    boot=[statistics.mean(rng.choices(deltas,k=runs)) for _ in range(10000)]
    low,high=quantile(boot,.025),quantile(boot,.975)
    delta=statistics.mean(deltas); build=statistics.mean(s['build']['mean_cpu_ns'] for s in summaries)
    binary=Path(__file__).resolve().parents[1]/'build/libsiap_crypto.so'
    result={'runs':runs,'samples_per_process':samples,'warmup_seconds':warmup,
            'exploratory':runs<30 or samples<10000 or warmup<60,
            'build_mean_cpu_ns':build,'delta_mean_cpu_ns':delta,'delta_ci95_ns':[low,high],
            'enabled':low>0,'threshold':max(1,math.ceil(build/delta)) if low>0 else None,
            'native_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),
            'code_fingerprint':code_fingerprint(),
            'inventory':inventory(),'precompute':precompute,'scope':'ctypes_microbenchmark_not_system_capacity',
            'notes':'Threshold is from paired process means; this is not cold full receiver service rate mu0.'}
    write_json(folder/'calibration.json',result); manifest(folder); return result
