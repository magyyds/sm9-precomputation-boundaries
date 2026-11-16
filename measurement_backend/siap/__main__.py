import argparse
import json
from pathlib import Path
from .artifacts import write_json

def main():
    p=argparse.ArgumentParser(description='SM9 SIAP reproducible experiment tools')
    sub=p.add_subparsers(dest='command',required=True)
    a=sub.add_parser('demo'); a.add_argument('--out',required=True); a.add_argument('--method',default='siap')
    a=sub.add_parser('run-local'); a.add_argument('--out',required=True)
    a.add_argument('--method',choices=['cold','immediate','lru','tinylfu','siap','noreserve'],default='siap')
    for name,default,kind in [('count',120,int),('rate',4,float),('seed',1,int),('warmup',0,float),
                            ('lead',15,float),('drain',5,float),('identities',8,int),('threshold',2,int)]:
        a.add_argument('--'+name,default=default,type=kind)
    a.add_argument('--attack',choices=['none','replay','invalid'],default='none')
    a.add_argument('--attack-ratio',type=float,default=0)
    a=sub.add_parser('run-case');a.add_argument('--out',required=True)
    a.add_argument('--method',choices=['cold','immediate','lru','tinylfu','siap','noreserve'],default='siap')
    a.add_argument('--algorithm',choices=['sm9','sm2'],default='sm9')
    a.add_argument('--precompute',choices=['q','miller'],default='q');a.add_argument('--build-mode',choices=['sync','async'],default='sync')
    a.add_argument('--pattern',choices=['periodic','poisson','burst'],default='periodic')
    a.add_argument('--attack',choices=['none','replay','invalid'],default='none')
    a.add_argument('--trace');a.add_argument('--cpu',type=int);a.add_argument('--memory-audit',action='store_true')
    a.add_argument('--online',action='store_true')
    for name,default,kind in [('count',24,int),('rate',4,float),('seed',1,int),('lead',5,float),('drain',2,float),
                             ('warmup',0,float),('identities',8,int),('threshold',2,int),('churn',0,float),
                             ('burst-size',8,int),('attack-ratio',0,float),('payload',200,int),('cert-every',1,int),
                             ('r-budget',262144,int),('a-budget',262144,int),('width',256,int),('queue-capacity',1024,int)]:
        a.add_argument('--'+name,default=default,type=kind)
    a=sub.add_parser('prepare'); a.add_argument('--out',required=True)
    for name,default,kind in [('count',80,int),('rate',40,float),('seed',1,int),('identities',8,int),
                              ('payload',200,int),('lead',30,float),('epoch-seconds',30,float),('warmup',0,float)]:
        a.add_argument('--'+name,default=default,type=kind)
    a.add_argument('--attack',choices=['none','replay','invalid'],default='none'); a.add_argument('--attack-ratio',type=float,default=0)
    a.add_argument('--pattern',choices=['periodic','poisson','burst'],default='periodic');a.add_argument('--churn',type=float,default=0)
    a.add_argument('--burst-size',type=int,default=8);a.add_argument('--trace')
    a.add_argument('--algorithm',choices=['sm9','sm2'],default='sm9');a.add_argument('--cert-every',type=int,default=1)
    a.add_argument('--online',action='store_true')
    a=sub.add_parser('control'); a.add_argument('--scenario',required=True); a.add_argument('--output')
    a.add_argument('--host'); a.add_argument('--port',type=int,default=9998)
    a.add_argument('--duration',type=float,default=300); a.add_argument('--interval',type=float,default=.25)
    a.add_argument('--revoke',action='append',default=[])
    a=sub.add_parser('send'); a.add_argument('--scenario',required=True); a.add_argument('--host',required=True)
    a.add_argument('--port',type=int,default=9999); a.add_argument('--out',required=True)
    a=sub.add_parser('serve'); a.add_argument('--trust',required=True); a.add_argument('--control')
    a.add_argument('--control-port',type=int,default=9998)
    a.add_argument('--out',required=True); a.add_argument('--host',default='127.0.0.1'); a.add_argument('--port',type=int,default=9999)
    a.add_argument('--duration',type=float,default=60); a.add_argument('--method',choices=['cold','immediate','lru','tinylfu','siap','noreserve'],default='siap')
    a.add_argument('--threshold',type=int,default=2); a.add_argument('--calibration'); a.add_argument('--db')
    a.add_argument('--r-budget',type=int,default=262144); a.add_argument('--a-budget',type=int,default=262144)
    a.add_argument('--width',type=int,default=256); a.add_argument('--queue-capacity',type=int,default=1024)
    a.add_argument('--precompute',choices=['q','miller'],default='q');a.add_argument('--build-mode',choices=['sync','async'],default='sync');a.add_argument('--ready-file');a.add_argument('--memory-audit',action='store_true')
    a=sub.add_parser('summarize'); a.add_argument('--scenario',required=True); a.add_argument('--sender',required=True)
    a.add_argument('--receiver',required=True); a.add_argument('--out',required=True); a.add_argument('--same-host',action='store_true')
    a.add_argument('--deadline-ms',type=float,default=100)
    for command in ('micro','calibrate'):
        a=sub.add_parser(command); a.add_argument('--out',required=True); a.add_argument('--samples',type=int,default=100)
        a.add_argument('--precompute',choices=['q','miller'],default='q')
        a.add_argument('--warmup',type=float,default=1)
        if command=='calibrate': a.add_argument('--runs',type=int,default=3)
        else: a.add_argument('--seed',type=int,default=1)
    a=sub.add_parser('compare'); a.add_argument('--left',nargs='+',required=True); a.add_argument('--right',nargs='+',required=True)
    a.add_argument('--out',required=True)
    args=vars(p.parse_args()); command=args.pop('command')
    from . import experiment,benchmark,analysis
    if command in ('demo','run-local'):
        result=experiment.demo(args.pop('out'),**args)
        if command=='demo' and result['n_delivered']==0: raise RuntimeError('demo delivered no legitimate message')
    elif command=='run-case':
        from .campaign import run
        result=run(args.pop('out'),**args)
    elif command=='prepare': result=str(experiment.prepare(args.pop('out'),**args))
    elif command=='control':
        args['revoked']=args.pop('revoke'); result=experiment.refresh_control(**args)
    elif command=='send': args['output']=args.pop('out'); result=experiment.send(**args)
    elif command=='serve':
        calibration=args.pop('calibration')
        if calibration:
            c=benchmark.load_calibration(calibration)
            if c.get('precompute','q')!=args['precompute']:raise ValueError('calibration precomputation mismatch')
            if args['method']=='siap':
                if c['enabled']: args['threshold']=c['threshold']
                else: args['method']='cold'
        args['output']=args.pop('out'); args['trust_path']=args.pop('trust'); args['control_path']=args.pop('control')
        result=experiment.serve(**args)
    elif command in ('micro','calibrate'): result=getattr(benchmark,command)(args.pop('out'),**args)
    elif command=='summarize':
        out=args.pop('out'); result=analysis.summarize(**args); write_json(out,result)
    elif command=='compare':
        result=analysis.compare_files(args['left'],args['right']); write_json(args['out'],result)
    if result is not None: print(json.dumps(result,indent=2,ensure_ascii=False))

if __name__=='__main__': main()
