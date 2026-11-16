"""Real open-loop UDP transport and offline signed workload preparation."""
import hashlib
import json
import os
import queue
import random
import socket
import threading
import time
from pathlib import Path
from .artifacts import write_json, inventory, manifest, JsonLog
from .crypto import keygen, extract, sign
from .control import CONTROL_ID, signed_snapshot
from .wire import Message, MAX_PACKET
from .receiver import Receiver
from . import workload

def prepare(folder, count=80, rate=40, seed=1, identities=8, payload=200, lead=30,
            epoch_seconds=30, attack='none', attack_ratio=0.0, warmup=0,
            pattern='periodic', churn=0, burst_size=8, trace=None, algorithm='sm9', cert_every=1, online=False):
    if algorithm not in ('sm9','sm2') or cert_every<1: raise ValueError('algorithm/certificate period')
    if not 1 <= count <= 200000 or rate<=0 or not 1<=identities<=10000 or not 0<=payload<=1200:
        raise ValueError('workload limits')
    if lead<=0 or epoch_seconds<=0 or warmup<0 or not 0<=attack_ratio<=5: raise ValueError('time/attack bounds')
    schedule=workload.generate(count,rate,seed,pattern,identities,churn,epoch_seconds,burst_size,trace)
    network_trace=any('network_drop' in s for s in schedule)
    if network_trace and (online or attack!='none' or algorithm!='sm9' or payload!=200):
        raise ValueError('network trace is for offline SM9 200-byte legitimate traffic; regenerate simulation for other wire traffic')
    if warmup*1e6>schedule[-1]['offset_us']: raise ValueError('no observation messages after warmup')
    folder=Path(folder); folder.mkdir(parents=True,exist_ok=False)
    rng=random.Random(seed); sk,pk=keygen(); ask,apk=keygen(); ak=extract(ask,CONTROL_ID)
    start=time.time_ns()//1000+int(lead*1e6)
    epochs={}; keys={}; counters={}; plans=[]
    pki=None; ca_der=None
    if algorithm=='sm2':
        from . import sm2
        ids=sorted({Message(1,1,s['epoch'],s['pid'].to_bytes(16,'big'),0,0,b'',suite=2).identity() for s in schedule})
        ca_der,pki=sm2.make_pki(folder/'pki',ids)
    for i, item in enumerate(schedule):
        offset=item['offset_us']/1e6; epoch=item['epoch']
        a=start+int((epoch-1)*epoch_seconds*1e6); b=a+int(epoch_seconds*1e6)-1
        epochs[str(epoch)]=[a,b]
        pid=item['pid'].to_bytes(16,'big')
        key_id=(epoch,pid); c=counters.get(key_id,0); counters[key_id]=c+1
        ts=start+round(offset*1e6)
        m=Message(1,1,epoch,pid,ts,c,bytes([i%256])*payload,suite=2 if algorithm=='sm2' else 1)
        identity=m.identity()
        if algorithm=='sm2':
            secret,cert=pki[identity]
            packet=sm2.encode(m,sm2.sign(secret,identity,m.signed_bytes()),cert if c%cert_every==0 else b'')
        else:
            if identity not in keys: keys[identity]=extract(sk,identity)
            packet=m.encode(sign(keys[identity],m.signed_bytes()))
        plans.append({'index':len(plans),'scheduled_us':ts,'phase':'observe' if offset>=warmup else 'warmup',
                      'kind':'legitimate','identity':identity.hex(),'counter':c,'packet':packet.hex(),
                      'packet_sha256':hashlib.sha256(packet).hexdigest()})
        if network_trace:plans[-1].update(network_drop=item['network_drop'],network_delay_us=item['network_delay_us'])
        if attack!='none':
            n=int(attack_ratio)+(rng.random()<attack_ratio%1)
            for _ in range(n):
                signature_offset=54+payload
                bad=packet if attack=='replay' else packet[:signature_offset]+b'\0'*32+packet[signature_offset+32:]
                plans.append({'index':len(plans),'scheduled_us':ts+100,'phase':'attack','kind':attack,
                              'identity':identity.hex(),'counter':c,'packet':bad.hex(),
                              'packet_sha256':hashlib.sha256(bad).hexdigest()})
    if len(epochs)>1024: raise ValueError('too many epochs; split into separate key namespaces')
    with (folder/'plan.jsonl').open('x') as f:
        for row in sorted(plans,key=lambda x:(x['scheduled_us']+x.get('network_delay_us',0),x['index'])): f.write(json.dumps(row)+'\n')
    trust={'public_key':pk.hex(),'authority_public':apk.hex(),'epochs':epochs,'domain':1,'key_version':1}
    trust['measurement']={'start_us':start+round(warmup*1e6),'end_us':start+schedule[-1]['offset_us']+round(1e6/rate)}
    if algorithm=='sm2': trust.update(algorithm='sm2',ca_der=ca_der.hex())
    write_json(folder/'trust.json',trust)
    # Synthetic experiment keys stay with the generator, never the receiver.
    path=folder/'authority-private.json'
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'w') as f: json.dump({'key':ak.hex()},f)
    if online:
        secrets={k.hex():v[0].hex() for k,v in pki.items()} if pki is not None else {k.hex():v.hex() for k,v in keys.items()}
        fd=os.open(folder/'vehicle-private.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'w') as f: json.dump(secrets,f)
    write_json(folder/'scenario.json',{'seed':seed,'count':count,'rate':rate,'start_us':start,
               'end_us':start+schedule[-1]['offset_us']+round(1e6/rate),'warmup_s':warmup,'identities':identities,
               'payload':payload,'epoch_seconds':epoch_seconds,'attack':attack,'attack_ratio':attack_ratio,
               'mode':'online_signing' if online else 'offline_signed_receiver_workload','pattern':pattern,'churn':churn,'burst_size':burst_size,
               'workload_sha256':workload.digest(schedule),'identity_envelope':workload.identity_envelope(schedule,churn),
               'trace_sha256':hashlib.sha256(Path(trace).read_bytes()).hexdigest() if trace else None})
    config=json.loads((folder/'scenario.json').read_text());config.update(algorithm=algorithm,cert_every=cert_every,network_trace=network_trace)
    write_json(folder/'scenario.json',config)
    write_json(folder/'inventory.json',inventory()); manifest(folder)
    if time.time_ns()//1000>=start: raise RuntimeError('preparation exceeded lead time; prepare a NEW directory with larger --lead')
    return folder

def refresh_control(scenario, output=None, duration=300, interval=0.25, revoked=(), host=None, port=9998):
    if not output and not host: raise ValueError('control requires --output or --host')
    if interval<=0 or duration<=0: raise ValueError('control interval/duration')
    scenario=Path(scenario); output=Path(output) if output else None
    trust=json.loads((scenario/'trust.json').read_text())
    key=bytes.fromhex(json.loads((scenario/'authority-private.json').read_text())['key'])
    stop=time.monotonic()+duration
    while time.monotonic()<stop:
        now=time.time_ns()//1000
        data={'version':now,'issued_us':now,'expires_us':now+2_000_000,
              **{k:trust[k] for k in ('public_key','epochs','domain','key_version')},'revoked':list(revoked)}
        raw=signed_snapshot(data,key)
        if output:
            tmp=output.with_suffix('.tmp'); tmp.write_bytes(raw); os.replace(tmp,output)
        if host:
            if len(raw)>65507: raise ValueError('snapshot too large for UDP; use authenticated file transport')
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock: sock.sendto(raw,(host,port))
        time.sleep(interval)

def send(scenario, host, port, output):
    scenario=Path(scenario); output=Path(output); output.mkdir(parents=True,exist_ok=False)
    write_json(output/'inventory.json',inventory())
    plans=[json.loads(line) for line in (scenario/'plan.jsonl').read_text().splitlines()]
    config=json.loads((scenario/'scenario.json').read_text())
    online=config['mode']=='online_signing';generated={}
    secrets=json.loads((scenario/'vehicle-private.json').read_text()) if online else {}
    now_us=time.time_ns()//1000; mono=time.monotonic_ns()
    log=JsonLog(output/'sender.jsonl'); sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    sock.setblocking(False)
    try:
        for row in plans:
            planned_ns=mono+(row['scheduled_us']-now_us)*1000
            due_ns=planned_ns+row.get('network_delay_us',0)*1000
            wait=(due_ns-time.monotonic_ns())/1e9
            if wait>0: time.sleep(wait)
            actual=time.monotonic_ns()
            entry={k:v for k,v in row.items() if k!='packet'}
            entry.update(scheduled_ns=planned_ns,send_ns=actual,lag_ns=max(0,actual-planned_ns))
            if row.get('network_drop'):
                entry['reason']='simulated_network_drop';log.write(entry);continue
            # Expired packets are recorded as missed; the schedule denominator is preserved.
            if actual-due_ns>100_000_000: entry['reason']='sender_missed'
            else:
                packet=bytes.fromhex(row['packet'])
                if online:
                    key=(row['identity'],row['counter']);entry['generated_ns']=time.monotonic_ns()
                    if row['kind']=='legitimate':
                        if config['algorithm']=='sm2':
                            from . import sm2
                            m,tail=sm2.decode(packet)
                            packet=sm2.encode(m,sm2.sign(bytes.fromhex(secrets[row['identity']]),m.identity(),m.signed_bytes()),tail[66:])
                        else:
                            from .wire import decode
                            m,_=decode(packet);packet=m.encode(sign(bytes.fromhex(secrets[row['identity']]),m.signed_bytes()))
                        generated[key]=packet
                    else:
                        packet=generated.get(key,packet)
                        if row['kind']=='invalid':
                            offset=54+config['payload'];packet=packet[:offset]+b'\0'*32+packet[offset+32:]
                    entry.update(sign_done_ns=time.monotonic_ns(),packet_sha256=hashlib.sha256(packet).hexdigest())
                entry['send_ns']=time.monotonic_ns();entry['lag_ns']=max(0,entry['send_ns']-planned_ns)
                if entry['send_ns']-due_ns>100_000_000:
                    entry['reason']='sender_missed';log.write(entry);continue
                try: sock.sendto(packet,(host,port)); entry['reason']='sent'
                except (BlockingIOError,OSError) as e: entry.update(reason='send_error',error=str(e))
            log.write(entry)
    finally: sock.close(); log.close(); manifest(output)

def serve(trust_path, control_path, output, host='127.0.0.1', port=9999, duration=20,
          method='siap', threshold=2, r_budget=262144, a_budget=262144, width=256,
          queue_capacity=1024, db=None, ready=None, control_port=9998, build_mode='sync', ready_file=None,
          memory_audit=False,precompute='q'):
    if not 1<=queue_capacity<=100000 or duration<=0: raise ValueError('queue/duration')
    output=Path(output); output.mkdir(parents=True,exist_ok=False)
    if memory_audit:
        import tracemalloc
        tracemalloc.start()
    trust=json.loads(Path(trust_path).read_text())
    write_json(output/'inventory.json',inventory())
    write_json(output/'config.json',{'method':method,'threshold':threshold,'r_budget':r_budget,
               'a_budget':a_budget,'width':width,'queue_capacity':queue_capacity,'host':host,
               'port':port,'duration':duration,'build_mode':build_mode,'precompute':precompute,'clock':'monotonic_ns',
               'db':str(db or output/'ledger.sqlite3')})
    events=JsonLog(output/'events.jsonl'); controls=JsonLog(output/'control.jsonl')
    backend=None
    if trust.get('algorithm')=='sm2':
        from .sm2 import CertificateVerifier
        backend=CertificateVerifier(bytes.fromhex(trust['public_key']),bytes.fromhex(trust['ca_der']),a_budget)
        if method!='cold': raise ValueError('SM2 receiver must select method cold; certificate cache is independent')
    r=Receiver(bytes.fromhex(trust['public_key']),bytes.fromhex(trust['authority_public']),
               method=method,threshold=threshold,r_budget=r_budget,a_budget=a_budget,width=width,
               db=str(db or output/'ledger.sqlite3'),build_mode=build_mode,signature_backend=backend,precompute=precompute)
    import resource
    process_start=time.process_time_ns(); wall_start=time.monotonic_ns()
    q=queue.Queue(queue_capacity); errors=[]; stop=threading.Event()
    cpu_window={};bounds=trust.get('measurement')
    def observe_cpu():
        if not bounds:return
        for label in ('start','end'):
            target=bounds[label+'_us']
            while not stop.is_set():
                now=time.time_ns()//1000
                if now>=target:
                    cpu_window[label]={'unix_us':now,'offset_us':now-target,'process_cpu_ns':time.process_time_ns()}
                    break
                stop.wait(min(.01,(target-now)/1e6))
    observer=threading.Thread(target=observe_cpu)
    control_socket=None
    if not control_path:
        control_socket=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        control_socket.bind((host,control_port)); control_socket.settimeout(.05)
    def worker():
        while True:
            item=q.get()
            if item is None: q.task_done(); return
            packet,ingress,digest=item
            try:
                e=r.process(packet,ingress); e['packet_sha256']=digest; events.write(e)
            except Exception as exc:
                errors.append(repr(exc)); r.closed=True
                events.write({'packet_sha256':digest,'ingress_ns':ingress,'reason':'internal_error','error':repr(exc)})
            finally: q.task_done()
    def control_worker():
        previous=None
        csock=control_socket
        try:
            while not stop.is_set():
                try:
                    raw=None
                    if csock:
                        try: raw,_=csock.recvfrom(65508)
                        except socket.timeout: continue
                    else:
                        p=Path(control_path)
                        if p.exists():
                            if p.stat().st_size>1024*1024: raise ValueError('control file oversized')
                            raw=p.read_bytes()
                    if raw:
                        digest=hashlib.sha256(raw).hexdigest()
                        if digest!=previous:
                            previous=digest
                            try:
                                r.install(raw)
                                controls.write({'installed_ns':time.monotonic_ns(),'version':r.control['version'],'sha256':digest})
                            except (ValueError,KeyError,TypeError,OverflowError,RecursionError) as exc:
                                controls.write({'rejected_ns':time.monotonic_ns(),'error':str(exc),'sha256':digest})
                except OSError as exc: controls.write({'error':str(exc)})
                except Exception as exc: errors.append(repr(exc)); r.closed=True; return
                if not csock: stop.wait(.05)
        finally:
            if csock: csock.close()
    thread=threading.Thread(target=worker); controller=threading.Thread(target=control_worker)
    sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); sock.bind((host,port)); sock.settimeout(0.1)
    thread.start(); controller.start();observer.start()
    if ready: ready.set()
    if ready_file: write_json(ready_file,{'pid':os.getpid(),'port':port})
    end=time.monotonic()+duration; peak=0
    try:
        while time.monotonic()<end:
            try: packet,_=sock.recvfrom((3368 if backend else MAX_PACKET)+1)
            except socket.timeout: continue
            ingress=time.monotonic_ns(); digest=hashlib.sha256(packet).hexdigest()
            try: q.put_nowait((packet,ingress,digest)); peak=max(peak,q.qsize())
            except queue.Full: events.write({'packet_sha256':digest,'ingress_ns':ingress,'reason':'queue_drop'})
    finally:
        sock.close(); q.put(None); thread.join(); stop.set(); controller.join();observer.join()
        r.drain_builds()
        from .resources import snapshot
        write_json(output/'memory.json',snapshot(r,queue_capacity))
        write_json(output/'receiver_metrics.json',{**r.metrics(),'queue_peak':peak,'errors':errors,
                   'process_cpu_ns':time.process_time_ns()-process_start,'process_wall_ns':time.monotonic_ns()-wall_start,
                   'peak_rss_kib':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
                   'measurement_process_id':os.getpid(), 'cpu_scope':'serve_interval_process_includes_control_io_builds'})
        if 'start' in cpu_window and 'end' in cpu_window:
            cpu_window['process_cpu_ns']=cpu_window['end']['process_cpu_ns']-cpu_window['start']['process_cpu_ns']
        cpu_window['scope']='process_CPU_between_sampled_observation_bounds; excludes_post_window_drain; offsets_reported'
        write_json(output/'cpu-window.json',cpu_window)
        r.close(); events.close(); controls.close(); manifest(output)
        if memory_audit: tracemalloc.stop()
    if errors: raise RuntimeError('; '.join(errors))

def demo(folder, method='siap', count=24, rate=4, seed=1, warmup=0, lead=8, drain=2,
         attack='replay', attack_ratio=.25, identities=8, threshold=2):
    folder=Path(folder); folder.mkdir(parents=True,exist_ok=False)
    scenario=prepare(folder/'scenario',lead=lead,count=count,rate=rate,seed=seed,identities=identities,
                     warmup=warmup,attack=attack,attack_ratio=attack_ratio)
    finish=json.loads((scenario/'scenario.json').read_text())['end_us']
    duration=max(1,(finish-time.time_ns()//1000)/1e6)+drain
    control=folder/'live-control.json'; ready=threading.Event(); errors=[]
    def guarded(fn,*args,**kwargs):
        try: fn(*args,**kwargs)
        except Exception as e: errors.append(repr(e)); ready.set()
    updater=threading.Thread(target=guarded,args=(refresh_control,scenario,control,duration+1))
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as probe:
        probe.bind(('127.0.0.1',0)); port=probe.getsockname()[1]
    server=threading.Thread(target=guarded,args=(serve,scenario/'trust.json',control,folder/'receiver'),
                            kwargs={'port':port,'duration':duration,'method':method,'threshold':threshold,'ready':ready})
    updater.start(); server.start(); ready.wait(10)
    if not errors: send(scenario,'127.0.0.1',port,folder/'sender')
    server.join(); updater.join()
    if errors: raise RuntimeError(str(errors))
    from .analysis import summarize
    summary=summarize(scenario,folder/'sender',folder/'receiver',same_host=True)
    write_json(folder/'summary.json',summary); manifest(folder)
    if summary['duplicate_accepts']!=0: raise RuntimeError('duplicate acceptance')
    return summary
