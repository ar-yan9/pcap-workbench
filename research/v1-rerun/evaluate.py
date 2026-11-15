#!/usr/bin/env python3
"""Strict one-to-one event matching. See README for metric denominators."""
import argparse, importlib.util, json, collections
from pathlib import Path

def load(path):
    spec=importlib.util.spec_from_file_location('wb', path)
    wb=importlib.util.module_from_spec(spec); spec.loader.exec_module(wb); return wb

def match(alerts, units, decoded, window, ports):
    assigned={}; unmatched=[]; details=[]
    for index,a in enumerate(alerts):
        nums=a['evidence_packets']; ev=[decoded.get(n) for n in nums]
        candidates=[]
        valid=bool(nums) and len(nums)==len(set(nums)) and all(ev)
        if valid:
            valid=(all(e['protocol']=='TCP' and e['syn'] and not e['ack'] for e in ev)
                   and len({(e['src'],e['dst']) for e in ev})==1
                   and len({e['dport'] for e in ev})>=ports
                   and max(e['time_ns'] for e in ev)-min(e['time_ns'] for e in ev)<=window*10**9)
        if valid:
            for u in units:
                if set(nums)<=set(u['packet_numbers']) and u['id'] not in assigned:
                    candidates.append(u)
        if len(candidates)==1:
            u=candidates[0]; assigned[u['id']]=index
            details.append(dict(alert=index,event=u['id'],attack=u['attack'],evidence_count=len(nums),
                                evidence_fraction=len(nums)/len(u['packet_numbers']),
                                latency_seconds=(max(e['time_ns'] for e in ev)-u['start_ns'])/1e9))
        else: unmatched.append(index)
    tp=sum(u['attack'] and u['id'] in assigned for u in units)
    fn=sum(u['attack'] and u['id'] not in assigned for u in units)
    fp=sum(not u['attack'] and u['id'] in assigned for u in units)
    tn=sum(not u['attack'] and u['id'] not in assigned for u in units)
    alert_fp=fp+len(unmatched)
    return dict(event_confusion=dict(tp=tp,fn=fn,fp=fp,tn=tn),
                alert_precision=tp/(tp+alert_fp) if tp+alert_fp else None,
                event_recall=tp/(tp+fn) if tp+fn else None,
                alert_false_positives=alert_fp,unmatched_alerts=unmatched,matches=details)

def evaluate(implementation,pcap,labels):
    wb=load(implementation); packets,notices=wb.read_capture(pcap)
    assert not notices
    decoded={p['number']:wb.decode_packet(p)[0] for p in packets}
    units=json.loads(Path(str(labels)+'.events.json').read_text())
    rows=[]
    for w,p in [(10,10),(60,10),(300,10),(60,5),(60,15),(60,20),(300,5),(300,20)]:
        report=wb.investigate(pcap,w,p)
        row=dict(window=w,ports=p,alerts=len(report['alerts']),**match(report['alerts'],units,decoded,w,p))
        rows.append(row)
    return dict(records=len(packets),units=len(units),implementation_sha256=__import__('hashlib').sha256(Path(implementation).read_bytes()).hexdigest(),results=rows)

if __name__=='__main__':
    ap=argparse.ArgumentParser(); ap.add_argument('implementation'); ap.add_argument('pcap');ap.add_argument('labels')
    a=ap.parse_args(); print(json.dumps(evaluate(a.implementation,a.pcap,a.labels),indent=2))
