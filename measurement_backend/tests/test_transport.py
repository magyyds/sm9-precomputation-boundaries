import json
import socket
import tempfile
import threading
import unittest
from pathlib import Path
from siap.experiment import prepare,refresh_control,serve,send
from siap.analysis import summarize

class TransportTests(unittest.TestCase):
    def test_udp_data_and_signed_control(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            scenario=prepare(root/'scenario',count=6,rate=2,lead=3,identities=1,attack='replay',attack_ratio=1)
            def port():
                with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
                    s.bind(('127.0.0.1',0)); return s.getsockname()[1]
            dp,cp=port(),port(); ready=threading.Event(); errors=[]
            def run(fn,*args,**kwargs):
                try: fn(*args,**kwargs)
                except Exception as e: errors.append(repr(e)); ready.set()
            server=threading.Thread(target=run,args=(serve,scenario/'trust.json',None,root/'receiver'),
                                    kwargs={'port':dp,'control_port':cp,'duration':7,'ready':ready})
            controller=threading.Thread(target=run,args=(refresh_control,scenario),
                                        kwargs={'host':'127.0.0.1','port':cp,'duration':7})
            server.start(); self.assertTrue(ready.wait(3)); controller.start()
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s: s.sendto(b'bad json',('127.0.0.1',cp))
            send(scenario,'127.0.0.1',dp,root/'sender')
            server.join(10); controller.join(10)
            self.assertFalse(errors); self.assertFalse(server.is_alive())
            summary=summarize(scenario,root/'sender',root/'receiver',same_host=True)
            if summary['n_delivered']!=6:
                # Preserve the concrete rejection/timing evidence before temp cleanup.
                import shutil,time
                failure=Path(__file__).resolve().parents[1]/'results'/f'transport-failure-{time.time_ns()}'
                shutil.copytree(root,failure)
                print('Transport failure evidence:',failure,summary,flush=True)
            self.assertEqual(summary['n_scheduled'],6)
            self.assertEqual(summary['n_delivered'],6)
            self.assertEqual(summary['duplicate_accepts'],0)
            self.assertEqual(summary['all_packet_reasons'].get('replay_reject'),6)
