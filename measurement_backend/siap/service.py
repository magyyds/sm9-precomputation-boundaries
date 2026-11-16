"""Independent process calibration of the full cold receiver service path.

Policy clock is held fixed for a valid corpus; real CPU and wall time are measured.
This reference includes durable ledger commits, excludes socket/control refresh.
"""
import argparse
import hashlib
import json
import random
import statistics
import subprocess
import sys
import time
from pathlib import Path
from .artifacts import write_json,inventory,manifest,code_fingerprint
from .analysis import quantile


def sample(folder,count=100,seed=900001):
    from .crypto import keygen,extract,sign
    from .control import CONTROL_ID,signed_snapshot
    from .wire import Message
    from .receiver import Receiver
    folder=Path(folder);folder.mkdir(parents=True,exist_ok=False)
    now=time.time_ns()//1000;sk,pk=keygen();ask,apk=keygen();ak=extract(ask,CONTROL_ID)
    rng=random.Random(seed);keys={};counters={};packets=[]
    for n in range(count+5):
        pid=rng.randrange(1,9);c=counters.get(pid,0);counters[pid]=c+1
        m=Message(1,1,1,pid.to_bytes(16,'big'),now,c,b'x'*200)
        identity=m.identity()
        if identity not in keys: keys[identity]=extract(sk,identity)
        packets.append(m.encode(sign(keys[identity],m.signed_bytes())))
    r=Receiver(pk,apk,method='cold',clock=lambda:now,db=str(folder/'ledger.sqlite3'))
    r.install(signed_snapshot({'version':1,'issued_us':now,'expires_us':now+2_000_000,'domain':1,
               'key_version':1,'public_key':pk.hex(),'epochs':{'1':[now-1_000_000,now+1_000_000]},'revoked':[]},ak))
    records=[]
    try:
        for i,packet in enumerate(packets):
            cpu=time.process_time_ns();wall=time.monotonic_ns();e=r.process(packet)
            elapsed=time.monotonic_ns()-wall;used=time.process_time_ns()-cpu
            if e['reason']!='delivered':raise RuntimeError('calibration valid packet rejected: '+e['reason'])
            if i>=5:records.append({'wall_ns':elapsed,'cpu_ns':used})
    finally:r.close()
    write_json(folder/'samples.json',records)
    mean=statistics.mean(v['wall_ns'] for v in records)
    result={'seed':seed,'samples':count,'mean_wall_ns':mean,'mu0_reference_pps':1e9/mean,
            'mean_cpu_ns':statistics.mean(v['cpu_ns'] for v in records),'inventory':inventory()}
    write_json(folder/'summary.json',result);manifest(folder);return result


def calibrate(folder,runs=3,samples=100):
    if runs<2 or samples<2:raise ValueError('service calibration needs >=2 runs and samples')
    folder=Path(folder);folder.mkdir(parents=True,exist_ok=False);results=[]
    for n in range(runs):
        dest=folder/f'process-{n:03d}'
        subprocess.run([sys.executable,'-m','siap.service','--worker','--out',str(dest),'--samples',str(samples),
                        '--seed',str(900001+n)],check=True,stdout=subprocess.DEVNULL)
        results.append(json.loads((dest/'summary.json').read_text()))
    means=[r['mean_wall_ns'] for r in results];rng=random.Random(900000)
    boots=[1e9/statistics.mean(rng.choices(means,k=runs)) for _ in range(10000)]
    mu=1e9/statistics.mean(means)
    result={'runs':runs,'samples_per_process':samples,'mu0_reference_pps':mu,
            'mu0_ci95_pps':[quantile(boots,.025),quantile(boots,.975)],'rate_085_reference_pps':.85*mu,
            'exploratory':runs<30 or samples<10000,
            'scope':'full_cold_Receiver.process_with_SQLite_FULL_no_socket_no_control_refresh_frozen_policy_clock',
            'not_equivalent_to':'measured_network_sustainable_capacity',
            'native_sha256':hashlib.sha256((Path(__file__).resolve().parents[1]/'build/libsiap_crypto.so').read_bytes()).hexdigest(),
            'code_fingerprint':code_fingerprint(),
            'inventory':inventory()}
    write_json(folder/'service-calibration.json',result);manifest(folder);return result


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--out',required=True);p.add_argument('--worker',action='store_true')
    p.add_argument('--runs',type=int,default=3);p.add_argument('--samples',type=int,default=100);p.add_argument('--seed',type=int,default=900001)
    a=p.parse_args();result=sample(a.out,a.samples,a.seed) if a.worker else calibrate(a.out,a.runs,a.samples)
    print(json.dumps(result,indent=2))
