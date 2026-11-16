"""Real SUMO grid simulation -> receiver contact traffic; no radio model."""
import argparse
import hashlib
import os
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from .artifacts import write_json, manifest


def convert(fcd, radius=180, center=(200,200), interval=.5):
    if radius<=0 or interval<=0: raise ValueError('contact geometry/interval')
    messages=[]; mapping={}; last={}; contacts=set()
    for _,elem in ET.iterparse(fcd,events=('end',)):
        if elem.tag!='timestep': continue
        t=float(elem.attrib['time'])
        for v in elem.findall('vehicle'):
            x,y=float(v.attrib['x']),float(v.attrib['y'])
            if (x-center[0])**2+(y-center[1])**2>radius**2: continue
            name=v.attrib['id'];contacts.add(name)
            if name not in mapping: mapping[name]=len(mapping)+1
            if t-last.get(name,-interval)>=interval-1e-8:
                messages.append({'offset_us':round(t*1e6),'pid':mapping[name]});last[name]=t
        elem.clear()
    messages.sort(key=lambda r:(r['offset_us'],r['pid']))
    if not messages: raise ValueError('empty contact trace')
    return {'schema':1,'messages':messages,'vehicles_in_contact':len(contacts),
            'radius_m':radius,'center_m':list(center),'beacon_interval_s':interval,
            'scope':'SUMO_geometry_contact_application_replay_no_wireless_loss',
            'fcd_sha256':hashlib.sha256(Path(fcd).read_bytes()).hexdigest()}


def generate(folder, runtime='.runtime/sumo/sumo', seed=101, duration=30):
    folder=Path(folder).resolve();folder.mkdir(parents=True,exist_ok=False)
    runtime=Path(runtime).resolve();binary=runtime/'bin';log=folder/'commands.log'
    def run(cmd):
        with log.open('a') as f:
            f.write(' '.join(map(str,cmd))+'\n');f.flush()
            subprocess.run(list(map(str,cmd)),check=True,stdout=f,stderr=subprocess.STDOUT)
    version=subprocess.check_output([str(binary/'sumo'),'--version'],text=True)
    run([binary/'netgenerate','--grid','--grid.number','3','--grid.length','200',
         '--default.speed','13.9','--seed',seed,'--output-file',folder/'grid.net.xml'])
    # Explicit routes across the grid, using edge IDs verified in generated net.
    edges={e.attrib['id'] for e in ET.parse(folder/'grid.net.xml').getroot().findall('edge')}
    routes=['A0B0 B0C0','C1B1 B1A1','A2B2 B2C2','B0B1 B1B2']
    if any(e not in edges for route in routes for e in route.split()): raise RuntimeError('SUMO grid naming changed')
    root=ET.Element('routes');ET.SubElement(root,'vType',id='car',accel='2.6',decel='4.5',sigma='0.5',length='5',maxSpeed='13.9')
    for n,route in enumerate(routes): ET.SubElement(root,'route',id=f'r{n}',edges=route)
    for n in range(int(duration)):
        ET.SubElement(root,'vehicle',id=f'v{n}',type='car',route=f'r{n%len(routes)}',depart=str(n),departSpeed='max')
    ET.ElementTree(root).write(folder/'routes.rou.xml',encoding='utf-8',xml_declaration=True)
    run([binary/'sumo','--net-file',folder/'grid.net.xml','--route-files',folder/'routes.rou.xml',
         '--seed',seed,'--step-length','.1','--end',duration,'--fcd-output',folder/'fcd.xml','--no-step-log'])
    trace=convert(folder/'fcd.xml')
    write_json(folder/'trace.json',trace)
    write_json(folder/'provenance.json',{'seed':seed,'duration_s':duration,'version':version,
               'sumo_sha256':hashlib.sha256((binary/'sumo').read_bytes()).hexdigest(),
               'trace_messages':len(trace['messages']),'scope':trace['scope']})
    manifest(folder);return trace


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--out',required=True);p.add_argument('--runtime',default='.runtime/sumo/sumo')
    p.add_argument('--seed',type=int,default=101);p.add_argument('--duration',type=float,default=30)
    a=vars(p.parse_args());result=generate(a.pop('out'),**a)
    print(f"SUMO contact trace: {len(result['messages'])} messages, {result['vehicles_in_contact']} vehicles")
