"""SUMO FCD -> actual ns-3 802.11p simulation -> loss/delay replay trace."""
import argparse
import csv
import hashlib
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from .artifacts import write_json,manifest

def run(folder,fcd='examples/sumo/fcd.xml',seed=1,tx_power=16,exponent=2.7):
    folder=Path(folder);folder.mkdir(parents=True,exist_ok=False)
    positions={};messages=[];last={}
    for _,step in ET.iterparse(fcd,events=('end',)):
        if step.tag!='timestep':continue
        us=round(float(step.attrib['time'])*1e6)+1_000_000
        for v in step.findall('vehicle'):
            name=v.attrib['id'];positions.setdefault(name,[]).append((us,float(v.attrib['x']),float(v.attrib['y'])))
            if us-last.get(name,0)>=500000:messages.append((us,name));last[name]=us
        step.clear()
    mapping={name:n+1 for n,name in enumerate(sorted(positions))}
    with (folder/'positions.csv').open('w') as f:
        for name in sorted(positions):
            for us,x,y in positions[name]:f.write(f'{mapping[name]},{us},{x},{y}\n')
    rows=[]
    with (folder/'traffic.csv').open('w') as f:
        for index,(us,name) in enumerate(sorted(messages)):
            f.write(f'{index},{us},{mapping[name]},351\n')
            rows.append({'offset_us':us,'pid':mapping[name],'network_drop':True,'network_delay_us':0})
    binary=Path(__file__).resolve().parents[1]/'build/siap-wireless'
    with (folder/'simulator.log').open('w') as f:
        subprocess.run([str(binary),'--positions='+str(folder/'positions.csv'),'--traffic='+str(folder/'traffic.csv'),
                        '--out='+str(folder/'network-events.csv'),'--vehicles='+str(len(mapping)),
                        '--seed='+str(seed),'--txPower='+str(tx_power),'--exponent='+str(exponent)],check=True,stdout=f,stderr=subprocess.STDOUT)
    for e in csv.DictReader((folder/'network-events.csv').open()):
        if e['event']=='rx':
            row=rows[int(e['index'])];delay=int(e['time_us'])-row['offset_us']
            if delay<0:raise RuntimeError('negative network delay')
            if row['network_drop'] or delay<row['network_delay_us']:row.update(network_drop=False,network_delay_us=delay)
    result={'schema':1,'messages':rows,'scope':'ns-3_3.44_IEEE802.11p_10MHz_6Mbps_broadcast_no_PC5',
            'seed':seed,'tx_power_dbm':tx_power,'log_distance_exponent':exponent,'reference_loss_db':47.86,
            'frequency_GHz':5.86,'wire_packet_bytes':351,'fcd_sha256':hashlib.sha256(Path(fcd).read_bytes()).hexdigest(),
            'simulator_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),
            'scheduled':len(rows),'received':sum(not r['network_drop'] for r in rows)}
    write_json(folder/'trace.json',result);manifest(folder);return result

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--out',required=True);p.add_argument('--fcd',default='examples/sumo/fcd.xml')
    p.add_argument('--seed',type=int,default=1);p.add_argument('--tx-power',type=float,default=16);p.add_argument('--exponent',type=float,default=2.7)
    a=vars(p.parse_args());r=run(a.pop('out'),**a);print({k:v for k,v in r.items() if k!='messages'})
