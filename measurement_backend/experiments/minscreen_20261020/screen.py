"""Auditable performance screening; not a full receiver or an ARM result."""
import argparse
import csv
import ctypes as C
import hashlib
import itertools
import json
import math
import os
from pathlib import Path
import platform
import random
import resource
import statistics as S
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT))
from siap.crypto import Verifier, keygen, extract, sign, lib
from siap.cache import Cache
from siap.state import Ledger, Record

METHODS = ["qonly", "tinylfu", "siap"]
PROFILES = ["stable", "mixed", "short"]
def dump(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")
def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()
def bridge():
    b = C.CDLL(str(HERE / "bridge.so"))
    for n in ("screen_q_size", "screen_table_size"):
        getattr(b,n).argtypes=[]; getattr(b,n).restype=C.c_size_t
    b.screen_from_q.argtypes=[C.c_void_p,C.c_void_p]; b.screen_from_q.restype=None
    assert b.screen_q_size()==lib().lab_q_size()
    assert b.screen_table_size()==lib().lab_miller_size()
    return b
def boot(values, seed=71020):
    rng=random.Random(seed); n=len(values)
    x=sorted(S.mean(rng.choices(values,k=n)) for _ in range(10000))
    return [x[249],x[9749]]
def environment():
    return {"platform":platform.platform(),"python":sys.version,
            "affinity":sorted(os.sched_getaffinity(0)),
            "cpuinfo":Path("/proc/cpuinfo").read_text(),
            "native_sha256":digest(ROOT/"build/libsiap_crypto.so"),
            "gmssl_sha256":digest(ROOT/"build/vendor/gmssl-src/bin/libgmssl.so.3"),
            "script_sha256":digest(Path(__file__)),
            "bridge_sha256":digest(HERE/"bridge.so"),
            "plan_sha256":digest(HERE/"PLAN.md")}
def warm(v, identity, msg, sig, q, seconds):
    end=time.monotonic()+seconds
    while time.monotonic()<end:
        assert v.verify(identity,msg,sig,q)
def timed(call):
    c=time.thread_time_ns(); w=time.monotonic_ns()
    value=call()
    return time.thread_time_ns()-c,time.monotonic_ns()-w,value
def sentinel(v, identity, msg, sig, q):
    values=[]
    for _ in range(32):
        c,_,ok=timed(lambda:v.verify(identity,msg,sig,q)); assert ok
        values.append(c)
    return S.mean(values)
def make_material(seed,profile):
    rng=random.Random(seed)
    counts=([16]*8 if profile=="stable" else [24]*4+[1]*32 if profile=="mixed" else [2]*64)
    order=[i for i,n in enumerate(counts) for _ in range(n)]; rng.shuffle(order)
    sk,pk=keygen()
    ids=[hashlib.sha256(f"{seed}:{profile}:{i}".encode()).digest()+i.to_bytes(8,"big")
         for i in range(len(counts))]
    keys=[extract(sk,i) for i in ids]; seq=[0]*len(ids); data=[]
    for i in order:
        c=seq[i]; seq[i]+=1
        payload=rng.randbytes(200); msg=ids[i]+c.to_bytes(8,"big")+payload
        data.append((ids[i],c,msg,sign(keys[i],msg)))
    return pk,data
def correctness(out):
    b=bridge(); sk,pk=keygen(); qv=Verifier(pk); tv=Verifier(pk,"miller")
    checked=0
    for k in range(8):
        identity=hashlib.sha256(f"correct:{k}".encode()).digest()+k.to_bytes(8,"big")
        msg=b"correctness"+bytes([k])*200; sig=sign(extract(sk,identity),msg)
        q=qv.build(identity); t=C.create_string_buffer(tv.q_size); b.screen_from_q(q,t)
        full=tv.build(identity); assert t.raw==full.raw
        for v,cache,ref in [(qv,None,False),(qv,q,False),(tv,t,False),(qv,None,True)]:
            assert v.verify(identity,msg,sig,cache,reference=ref)
            assert not v.verify(identity,msg+b"x",sig,cache,reference=ref)
            checked+=2
    ledger=Ledger(65536,256)
    assert ledger.consume(identity,0,10000,0)[0]=="consumed"
    assert ledger.consume(identity,0,10000,1)[0]=="replay_reject"
    dump(out/"correctness.json",{"checks":checked+2,"bridge_table_bytes_equal":True,
          "q_size":qv.q_size,"table_size":tv.q_size,"r_record_size":C.sizeof(Record),
          "scope":"sampled algebra and sequential replay, not full protocol proof"})
    qv.close();tv.close();ledger.close()
def calibration(out,seed):
    rng=random.Random(seed); b=bridge();pk,data=make_material(seed,"stable")
    qv=Verifier(pk);tv=Verifier(pk,"miller"); identity,_,msg,sig=data[0]
    q=qv.build(identity); table=C.create_string_buffer(tv.q_size);b.screen_from_q(q,table)
    warm(qv,identity,msg,sig,q,1)
    def build():
        obj=C.create_string_buffer(tv.q_size);b.screen_from_q(q,obj);return obj
    samples=[]
    for i in range(64):
        ops=["q","table","build"];rng.shuffle(ops)
        for op in ops:
            fn=(lambda:qv.verify(identity,msg,sig,q)) if op=="q" else (
                (lambda:tv.verify(identity,msg,sig,table)) if op=="table" else build)
            cpu,wall,result=timed(fn); assert result
            samples.append({"i":i,"operation":op,"cpu_ns":cpu,"wall_ns":wall})
    dump(out/"samples.json",samples)
    dump(out/"summary.json",{op:S.mean(r["cpu_ns"] for r in samples if r["operation"]==op)
                             for op in ("q","table","build")})
    qv.close();tv.close()

class FromQ:
    def __init__(self,tv,qpool,b):
        self.q_size=tv.q_size;self.qpool=qpool;self.b=b
    def build(self,identity,out):
        self.b.screen_from_q(self.qpool[identity],out)
        return out

def run_method(pk,data,method,qthreshold):
    b=bridge();qv=Verifier(pk);tv=Verifier(pk,"miller");qpool={}
    cache=Cache(FromQ(tv,qpool,b),"cold" if method=="qonly" else method,65536,qthreshold)
    ledger=Ledger(65536,256); events=[];qhits=thits=qbuilds=0
    start_cpu=time.thread_time_ns(); start_proc=time.process_time_ns(); start_wall=time.monotonic_ns()
    for j,(identity,counter,msg,sig) in enumerate(data):
        item_start=time.thread_time_ns()
        cache.expire(j)
        q=qpool.get(identity); qhit=q is not None; qhits+=qhit
        if q is None:q=qv.build(identity);qbuilds+=1
        t=cache.lookup(identity);thit=t is not None;thits+=thit
        ok=tv.verify(identity,msg,sig,t) if thit else qv.verify(identity,msg,sig,q)
        assert ok, "valid verification failed"
        state,fresh=ledger.consume(identity,counter,100000,j)
        assert state=="consumed"
        if not qhit:
            # Allocation is performed by build; keeping its owned buffer avoids a needless copy.
            qpool[identity]=q
            assert len(qpool)*(qv.q_size+40+32)<=65536
        cache.accepted(identity,fresh,thit,j+1,100000)
        events.append({"index":j,"id":identity.hex(),"counter":counter,
                       "qhit":qhit,"table_hit":thit,"cpu_ns":time.thread_time_ns()-item_start,
                       "accepted":True})
    cpu=time.thread_time_ns()-start_cpu; proc=time.process_time_ns()-start_proc
    wall=time.monotonic_ns()-start_wall
    # Diagnostic replay checks outside performance window; no counter reset.
    assert all(ledger.consume(i,c,100000,1000)[0]=="replay_reject" for i,c,_,_ in data)
    result={"method":method,"count":len(data),"cpu_ns":cpu,"process_cpu_ns":proc,"wall_ns":wall,
            "cpu_per_message_ns":cpu/len(data),"q_hits":qhits,"table_hits":thits,
            "q_builds":qbuilds,"q_entries":len(qpool),"q_native_bytes":len(qpool)*qv.q_size,
            "q_python_metadata_in_total_rss_not_strict_budget":True,
            "r_bytes":ledger.allocated_bytes,"r_capacity":ledger.capacity,"r_peak":len(qpool),
            "cache":cache.metrics(),"all_unique_accepted":True,"all_replays_rejected":True,
            "peak_rss_kib":resource.getrusage(resource.RUSAGE_SELF).ru_maxrss}
    qv.close();tv.close();ledger.close()
    return result,events
def worker(out,seed,qthreshold,orders):
    pk,probe=make_material(seed,"stable");v=Verifier(pk)
    i,_,m,s=probe[0];q=v.build(i);warm(v,i,m,s,q,2)
    before=sentinel(v,i,m,s,q);results=[]
    for profile in orders["profiles"]:
        pkey,data=make_material(seed*17+PROFILES.index(profile),profile)
        encoded={"public_key":pkey.hex(),"messages":[[i.hex(),c,m.hex(),s.hex()] for i,c,m,s in data]}
        dump(out/f"{profile}-input.json",encoded)
        for method in orders["methods"]:
            result,events=run_method(pkey,data,method,qthreshold)
            result.update(seed=seed,profile=profile,order=orders["methods"],
                          input_sha256=digest(out/f"{profile}-input.json"))
            dump(out/f"{profile}-{method}-events.json",events)
            results.append(result)
    after=sentinel(v,i,m,s,q);v.close()
    dump(out/"summary.json",{"seed":seed,"runs":results,"sentinel_before_ns":before,
            "sentinel_after_ns":after,"sentinel_relative_drift":after/before-1,
            "drift_flag":abs(after/before-1)>.05,"affinity":sorted(os.sched_getaffinity(0)),
            "rusage":list(resource.getrusage(resource.RUSAGE_SELF))})

def analyze(out):
    blocks=[json.loads(p.read_text()) for p in sorted((out/"confirm").glob("*/summary.json"))]
    assert len(blocks)==30
    comparisons={}
    for profile in PROFILES:
        for reference in ("tinylfu","qonly"):
            gains=[];diffs=[];details=[]
            for block in blocks:
                runs={r["method"]:r for r in block["runs"] if r["profile"]==profile}
                a=runs["siap"]["cpu_per_message_ns"];z=runs[reference]["cpu_per_message_ns"]
                gains.append((z-a)/z);diffs.append(z-a);details.append({"seed":block["seed"],"siap":a,"reference":z})
            comparisons[f"{profile}:siap_vs_{reference}"]={
                "mean_relative_cpu_saving":S.mean(gains),"ci95_relative":boot(gains),
                "mean_absolute_saving_ns":S.mean(diffs),"ci95_absolute_ns":boot(diffs),
                "pairs":details}
    aggregates={}
    for profile in PROFILES:
        aggregates[profile]={}
        for method in METHODS:
            rows=[r for b in blocks for r in b["runs"] if r["profile"]==profile and r["method"]==method]
            aggregates[profile][method]={
                "mean_cpu_ms_per_message":S.mean(r["cpu_per_message_ns"] for r in rows)/1e6,
                "mean_wall_ms_per_message":S.mean(r["wall_ns"]/r["count"] for r in rows)/1e6,
                "mean_builds":S.mean(r["cache"]["builds"] for r in rows),
                "mean_table_hits":S.mean(r["table_hits"] for r in rows),
                "mean_unused_builds":S.mean(r["cache"]["unused_builds"] for r in rows),
                "a_capacity":rows[0]["cache"]["a_capacity"],
                "a_allocated_bytes":rows[0]["cache"]["a_allocated_bytes"]}
    result={"n_blocks":30,"primary":"mixed:siap_vs_tinylfu","comparisons":comparisons,
            "aggregates":aggregates,"drift_flags":sum(b["drift_flag"] for b in blocks),
            "all_correct":all(r["all_unique_accepted"] and r["all_replays_rejected"] for b in blocks for r in b["runs"]),
            "total_unique_verifications":sum(r["count"] for b in blocks for r in b["runs"]),
            "scope":"WSL single-thread verifier/admission kernel screening, not v3 receiver"}
    dump(out/"analysis.json",result)
    return result
def orchestrate(out):
    out.mkdir(parents=True,exist_ok=False);dump(out/"environment.json",environment())
    dump(out/"source_manifest.json",{str(p.relative_to(ROOT)):digest(p) for p in
         [HERE/"PLAN.md",HERE/"screen.py",HERE/"bridge.c",ROOT/"siap/cache.py",
          ROOT/"siap/state.py",ROOT/"siap/crypto.py",ROOT/"native/crypto.c",ROOT/"native/miller.c"]})
    correctness(out)
    summaries=[]
    for n in range(5):
        folder=out/"calibration"/str(n);folder.mkdir(parents=True)
        subprocess.run([sys.executable,__file__,"calibration",str(folder),"--seed",str(10001+n)],check=True)
        summaries.append(json.loads((folder/"summary.json").read_text()))
    delta=[r["q"]-r["table"] for r in summaries]; ci=boot(delta)
    config={"delta_ns":S.mean(delta),"delta_ci95_ns":ci,"build_from_q_ns":S.mean(r["build"] for r in summaries)}
    config["threshold"]=max(1,math.ceil(config["build_from_q_ns"]/config["delta_ns"])) if ci[0]>0 else None
    dump(out/"frozen_calibration.json",config);print("CALIBRATION",json.dumps(config),flush=True)
    if config["threshold"] is None:return
    perms=list(itertools.permutations(METHODS))*5
    pperms=list(itertools.permutations(PROFILES))*5
    random.Random(20261020).shuffle(perms);random.Random(20261021).shuffle(pperms)
    orders=[{"seed":30001+n,"methods":perms[n],"profiles":pperms[n]} for n in range(30)]
    dump(out/"frozen_orders.json",orders)
    for order in orders:
        folder=out/"confirm"/str(order["seed"]);folder.mkdir(parents=True)
        dump(folder/"order.json",order)
        subprocess.run([sys.executable,__file__,"worker",str(folder),"--seed",str(order["seed"]),
                        "--threshold",str(config["threshold"])],check=True)
        print("BLOCK_COMPLETE",order["seed"],flush=True)
    result=analyze(out)
    dump(out/"file_manifest.json",{str(p.relative_to(out)):digest(p) for p in out.rglob("*") if p.is_file()})
    print("DONE",json.dumps({k:v for k,v in result.items() if k not in ("comparisons","aggregates")}),flush=True)

if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("mode",choices=["orchestrate","calibration","worker","analyze"])
    p.add_argument("out",type=Path);p.add_argument("--seed",type=int,default=1);p.add_argument("--threshold",type=int,default=2)
    a=p.parse_args()
    if a.mode=="orchestrate":orchestrate(a.out)
    elif a.mode=="calibration":calibration(a.out,a.seed)
    elif a.mode=="worker":worker(a.out,a.seed,a.threshold,json.loads((a.out/"order.json").read_text()))
    else:analyze(a.out)
