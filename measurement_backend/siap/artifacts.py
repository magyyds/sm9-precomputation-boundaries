import hashlib
import json
import os
import platform
import sys
import time
from pathlib import Path

def write_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2, ensure_ascii=False)+'\n', encoding='utf-8')


def code_fingerprint():
    root=Path(__file__).resolve().parents[1]
    files=[*sorted((root/'siap').glob('*.py')),*sorted((root/'native').glob('*.c')),*sorted((root/'native').glob('*.h')),
           root/'build/libsiap_crypto.so',root/'build/libsiap_x509.so',root/'build/vendor/gmssl-src/bin/libgmssl.so']
    data={p.relative_to(root).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in files}
    return hashlib.sha256(json.dumps(data,sort_keys=True).encode()).hexdigest()

def inventory():
    result={'platform':platform.platform(),'python':sys.version,'machine':platform.machine(),
            'hostname':platform.node(),'pid':os.getpid(),'created_unix_us':time.time_ns()//1000}
    for name,path in [('boot_id','/proc/sys/kernel/random/boot_id'),('cpuinfo','/proc/cpuinfo')]:
        if Path(path).exists(): result[name]=Path(path).read_text()[:16000].strip()
    if hasattr(os,'sched_getaffinity'): result['cpu_affinity']=sorted(os.sched_getaffinity(0))
    return result

def manifest(folder):
    folder=Path(folder); files={}
    for p in sorted(folder.rglob('*')):
        if p.is_file() and p.name != 'manifest.json' and not p.name.endswith(('-wal','-shm')):
            files[str(p.relative_to(folder))]={'bytes':p.stat().st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}
    write_json(folder/'manifest.json',{'schema':1,'files':files})

class JsonLog:
    def __init__(self,path):
        import threading
        self.lock=threading.Lock(); self.file=open(path,'x',encoding='utf-8',buffering=1)
    def write(self,event):
        with self.lock: self.file.write(json.dumps(event,separators=(',',':'))+'\n')
    def close(self): self.file.close()
