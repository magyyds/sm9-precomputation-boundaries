"""Process-isolated runner: receiver accounting excludes sender and authority."""
import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path
from .experiment import prepare
from .analysis import summarize
from .artifacts import write_json,manifest

def free_port():
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
        s.bind(('127.0.0.1',0));return s.getsockname()[1]

def run(folder, *, method='siap',build_mode='sync',count=24,rate=4,seed=1,lead=5,drain=2,
        warmup=0,algorithm='sm9',pattern='periodic',churn=0,burst_size=8,trace=None,
        identities=8,threshold=2,attack='none',attack_ratio=0,payload=200,cert_every=1,
        r_budget=262144,a_budget=262144,width=256,queue_capacity=1024,memory_audit=False,cpu=None,online=False,precompute='q'):
    folder=Path(folder).resolve();folder.mkdir(parents=True,exist_ok=False)
    scenario=prepare(folder/'scenario',count=count,rate=rate,seed=seed,lead=lead,identities=identities,
                     warmup=warmup,algorithm=algorithm,pattern=pattern,churn=churn,burst_size=burst_size,
                     trace=trace,attack=attack,attack_ratio=attack_ratio,payload=payload,cert_every=cert_every,online=online)
    cfg=json.loads((scenario/'scenario.json').read_text())
    duration=max(1,(cfg['end_us']-time.time_ns()//1000)/1e6)+drain
    dp,cp=free_port(),free_port()
    while dp==cp:cp=free_port()
    ready=folder/'ready.json'; processes=[];logs=[]
    def spawn(args,name,affinity=None):
        log=(folder/(name+'.log')).open('x');logs.append(log)
        cmd=[sys.executable,'-m','siap',*map(str,args)]
        if affinity is not None:cmd=['taskset','-c',str(affinity),*cmd]
        proc=subprocess.Popen(cmd,stdout=log,stderr=subprocess.STDOUT);processes.append(proc);return proc
    receiver_method='cold' if algorithm=='sm2' else method
    opts=['serve','--trust',scenario/'trust.json','--out',folder/'receiver','--port',dp,'--control-port',cp,
          '--duration',duration,'--method',receiver_method,'--build-mode',build_mode if algorithm=='sm9' else 'sync',
          '--threshold',threshold,'--r-budget',r_budget,'--a-budget',a_budget,'--width',width,
          '--queue-capacity',queue_capacity,'--ready-file',ready,'--precompute',precompute]
    if memory_audit:opts+=['--memory-audit']
    try:
        receiver=spawn(opts,'receiver-process',cpu)
        deadline=time.monotonic()+10
        while not ready.exists():
            if receiver.poll() is not None:raise RuntimeError('receiver startup failed; inspect receiver-process.log')
            if time.monotonic()>deadline:raise TimeoutError('receiver readiness')
            time.sleep(.02)
        controller=spawn(['control','--scenario',scenario,'--host','127.0.0.1','--port',cp,'--duration',duration+.5],'control-process')
        sender=spawn(['send','--scenario',scenario,'--host','127.0.0.1','--port',dp,'--out',folder/'sender'],'sender-process')
        end=time.monotonic()+duration+20
        for proc in (sender,receiver,controller):
            result=proc.wait(timeout=max(1,end-time.monotonic()))
            if result:raise RuntimeError(f'child process failed with exit {result}; inspect process logs')
    finally:
        for proc in processes:
            if proc.poll() is None:proc.terminate()
        for proc in processes:
            try:proc.wait(timeout=5)
            except subprocess.TimeoutExpired:proc.kill();proc.wait()
        for log in logs:log.close()
    result=summarize(scenario,folder/'sender',folder/'receiver',same_host=True)
    metrics=json.loads((folder/'receiver/receiver_metrics.json').read_text())
    window=json.loads((folder/'receiver/cpu-window.json').read_text())
    result.update(method=receiver_method,algorithm=algorithm,precompute=precompute,build_mode=build_mode if algorithm=='sm9' else 'sync',workload_sha256=cfg['workload_sha256'],
                  receiver_process_cpu_ns=metrics['process_cpu_ns'],receiver_peak_rss_kib=metrics['peak_rss_kib'],
                  receiver_process_cpu_per_observation_message_ns=metrics['process_cpu_ns']/result['n_scheduled'],
                  process_cpu_scope='whole_receiver_run_including_warmup_drain_and_control; denominator_observation_only',
                  receiver_affinity=cpu,observation_cpu=window,
                  observation_cpu_per_scheduled_ns=window.get('process_cpu_ns',0)/result['n_scheduled'] if 'process_cpu_ns' in window else None)
    result['comparison_parameters']={k:cfg[k] for k in ('count','rate','warmup_s','payload','epoch_seconds','attack','attack_ratio','mode','pattern','churn','burst_size')}
    result['comparison_parameters'].update(r_budget=r_budget,a_budget=a_budget,width=width,queue_capacity=queue_capacity,cpu=cpu)
    write_json(folder/'summary.json',result);manifest(folder);return result
