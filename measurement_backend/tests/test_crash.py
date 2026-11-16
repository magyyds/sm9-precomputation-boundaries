import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from siap.crypto import keygen,extract,sign
from siap.control import CONTROL_ID,signed_snapshot
from siap.wire import Message
from siap.receiver import Receiver

class CrashTest(unittest.TestCase):
    def test_real_process_exit_after_durable_commit(self):
        sk,pk=keygen(); ask,apk=keygen(); now=1_000_000
        m=Message(1,1,1,b'\x01'*16,now,0,b'crash')
        packet=m.encode(sign(extract(sk,m.identity()),m.signed_bytes()))
        data={'version':1,'issued_us':now,'expires_us':now+2_000_000,'domain':1,'key_version':1,
              'public_key':pk.hex(),'epochs':{'1':[0,2_000_000]},'revoked':[]}
        with tempfile.TemporaryDirectory() as folder:
            folder=Path(folder); db=folder/'r.db'
            (folder/'input.json').write_text(json.dumps({'public':pk.hex(),'authority':apk.hex(),'packet':packet.hex(),
                'control':signed_snapshot(data,extract(ask,CONTROL_ID)).hex()}))
            script='''import json,os,sys
from pathlib import Path
from siap.receiver import Receiver
p=Path(sys.argv[1]); d=json.loads((p/'input.json').read_text())
def hook(stage,r,m):
 if stage=='consumed': os._exit(77)
r=Receiver(bytes.fromhex(d['public']),bytes.fromhex(d['authority']),db=str(p/'r.db'),clock=lambda:1000000,hook=hook)
r.install(bytes.fromhex(d['control'])); r.process(bytes.fromhex(d['packet']))
'''
            result=subprocess.run([sys.executable,'-c',script,str(folder)])
            self.assertEqual(result.returncode,77)
            r=Receiver(pk,apk,db=str(db),clock=lambda:now)
            self.assertEqual(r.process(packet)['reason'],'replay_reject'); r.close()
