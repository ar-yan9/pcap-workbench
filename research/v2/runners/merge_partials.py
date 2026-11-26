#!/usr/bin/env python3
"""Merge chunked heldout_scoring partial JSONs. Arithmetic only: sums,
list concatenation, dict union, boolean OR, min/max of run windows.
Recomputes recall from merged campaign sums. No scoring logic here."""
import json, sys

def merge(paths):
    parts = [json.load(open(p)) for p in paths]
    out = {k: v for k, v in parts[0].items()
           if k not in ('engines', 'run_manifests', 'trace_detail')}
    out['engines'] = {}
    out['run_manifests'] = []
    out['trace_detail'] = []
    for p in parts:
        out['trace_detail'] += p.get('trace_detail', [])
    eng_keys = list(parts[0]['engines'].keys())
    for ek in eng_keys:
        m = {'campaigns_total': 0, 'campaigns_matched': 0,
             'expected_alert_units': 0, 'expected_duplicate_burden': 0,
             'total_alerts': 0, 'zero_tolerance_violations': [],
             'failed_traces': [], 'per_family': {}, 'stress_alerts': {},
             'cap_exhausted': False}
        starts, ends = [], []
        for p in parts:
            e = p['engines'][ek]
            for f in ('campaigns_total', 'campaigns_matched', 'expected_alert_units',
                      'expected_duplicate_burden', 'total_alerts'):
                m[f] += e.get(f, 0)
            m['zero_tolerance_violations'] += e.get('zero_tolerance_violations', [])
            m['failed_traces'] += e.get('failed_traces', [])
            m['per_family'].update(e.get('per_family', {}))
            m['stress_alerts'].update(e.get('stress_alerts', {}))
            m['cap_exhausted'] = m['cap_exhausted'] or e.get('cap_exhausted', False)
            rw = e.get('run_window_utc', {})
            if rw.get('start'): starts.append(rw['start'])
            if rw.get('end'): ends.append(rw['end'])
        m['recall'] = (m['campaigns_matched'] / m['campaigns_total']
                       if m['campaigns_total'] else None)
        m['run_window_utc'] = {'start': min(starts), 'end': max(ends)}
        if not m['stress_alerts']:
            del m['stress_alerts']
        out['engines'][ek] = m
    for p in parts:
        out['run_manifests'] += p.get('run_manifests', [])
    return out

if __name__ == '__main__':
    dest = sys.argv[1]
    merged = merge(sys.argv[2:])
    with open(dest, 'w') as f:
        json.dump(merged, f, sort_keys=True, indent=1)
    print('wrote', dest)
