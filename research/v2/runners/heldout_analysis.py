#!/usr/bin/env python3
"""Amendment A4 section-4 predeclared analysis over the frozen held-out
scoring record. Cluster bootstrap 10,000 resamples, fixed analysis seed
20261113, stratified by family over independently generated traces, engines
paired on the same trace. Pure stdlib. Reads the scoring JSON, writes an
analysis JSON. No scoring or tuning logic here."""
import json, random, statistics, sys
from pathlib import Path

RESAMPLES = 10000
ANALYSIS_SEED = 20261113
ATTACK = ['fast-vertical-syn', 'threshold-edge-syn', 'slow-syn',
          'horizontal-syn', 'fin', 'null', 'xmas', 'repeated-vertical-bursts',
          'repeated-horizontal-bursts', 'mixed-families', 'distributed-syn',
          'udp']
SELECTION = None  # filled from trace rows: families with campaigns recorded
BENIGN = ['normal-sessions', 'few-port-retries', 'approved-admin-scan',
          'nat-shared-source', 'service-discovery', 'fin-ack-teardown']
BENIGN_TRACE_HOURS = 1.0  # spec v0.1 section 4: benign traces are 3600 s


def percentile(sorted_vals, q):
    if not sorted_vals:
        return None
    k = (len(sorted_vals) - 1) * q
    f = int(k)
    c = min(f + 1, len(sorted_vals) - 1)
    return sorted_vals[f] + (sorted_vals[c] - sorted_vals[f]) * (k - f)


def main(scoring_path, out_path):
    data = json.loads(Path(scoring_path).read_text())
    rows = data['trace_detail']

    # per-trace campaign outcomes per engine, keyed (family, capture_id)
    v2_rows = [r for r in rows if r['engine'] == 'v2']
    bl_rows = [r for r in rows if r['engine'] in ('zeek', 'snort')]

    # selection-scope attack families = families where v2 rows carry campaigns
    camp = {}   # engine -> family -> list of (total, matched) per trace
    for r in v2_rows:
        if r.get('campaigns'):
            t, m = len(r['campaigns']), sum(1 for c in r['campaigns'] if c['matched'])
            camp.setdefault('v2', {}).setdefault(r['family'], []).append((t, m))
    for r in bl_rows:
        if r.get('campaigns_total'):
            camp.setdefault(r['engine'], {}).setdefault(r['family'], []).append(
                (r['campaigns_total'], r['campaigns_matched']))

    sel_families = sorted(camp.get('v2', {}).keys())

    def recall(engine, fam_filter=None):
        t = m = 0
        for fam, traces in camp.get(engine, {}).items():
            if fam_filter and fam not in fam_filter:
                continue
            for tt, mm in traces:
                t += tt
                m += mm
        return (m / t) if t else None, m, t

    # --- per-family recall (all engines) ---
    per_family = {}
    for eng in camp:
        per_family[eng] = {}
        for fam in sel_families:
            r, m, t = recall(eng, {fam})
            per_family[eng][fam] = {'campaigns_total': t, 'campaigns_matched': m,
                                    'recall': r}

    # --- stratified cluster bootstrap, paired on the same trace ---
    rng = random.Random(ANALYSIS_SEED)
    # cluster unit: trace. outcome vector per trace: (total, matched) per engine
    trace_units = {}  # family -> list of capture-level units
    for fam in sel_families:
        units = []
        v2t = {cid: (t, m) for cid, (t, m) in zip(
            [r['capture_id'] for r in v2_rows if r['family'] == fam and r.get('campaigns')],
            camp['v2'][fam])}
        for eng in ('zeek', 'snort'):
            engt = {r['capture_id']: (r['campaigns_total'], r['campaigns_matched'])
                    for r in bl_rows if r['engine'] == eng and r['family'] == fam
                    and r.get('campaigns_total')}
            for cid, (t, m) in v2t.items():
                # pair engines on the same trace
                for i, u in enumerate(units):
                    if u['capture_id'] == cid:
                        u[eng] = engt.get(cid, (0, 0))
                        break
                else:
                    units.append({'capture_id': cid, 'v2': (t, m),
                                  eng: engt.get(cid, (0, 0))})
        # ensure every unit has all three engines
        for u in units:
            for eng in ('v2', 'zeek', 'snort'):
                u.setdefault(eng, (0, 0))
        trace_units[fam] = units

    boot = {'v2': [], 'zeek': [], 'snort': [], 'v2_minus_zeek': [],
            'v2_minus_snort': []}
    for _ in range(RESAMPLES):
        sums = {e: [0, 0] for e in ('v2', 'zeek', 'snort')}
        for fam in sel_families:
            units = trace_units[fam]
            for _ in range(len(units)):
                u = units[rng.randrange(len(units))]
                for e in sums:
                    sums[e][0] += u[e][1]
                    sums[e][1] += u[e][0]
        recs = {}
        for e in sums:
            m, t = sums[e]
            recs[e] = (m / t) if t else None
        for e in ('v2', 'zeek', 'snort'):
            boot[e].append(recs[e])
        if recs['v2'] is not None and recs['zeek'] is not None:
            boot['v2_minus_zeek'].append(recs['v2'] - recs['zeek'])
        if recs['v2'] is not None and recs['snort'] is not None:
            boot['v2_minus_snort'].append(recs['v2'] - recs['snort'])
    intervals = {}
    for k, vals in boot.items():
        vals = sorted(v for v in vals if v is not None)
        intervals[k] = {'n_resamples': len(vals),
                        'p2.5': percentile(vals, 0.025),
                        'p50': percentile(vals, 0.5),
                        'p97.5': percentile(vals, 0.975)}

    # --- benign alert rates (alerts per unit per trace-hour) ---
    benign_rates = {}
    for eng_label, eng in (('v2 detector (W=300, T=5) frozen', 'v2'),
                           ('zeek-8.0.11+bro-simple-scan(35cf19cf)+bro-is-darknet(7564a8f2) defaults', 'zeek'),
                           ('snort-3.13.2.0 port_scan inspector defaults', 'snort')):
        e = data['engines'][eng_label]
        benign_rates[eng] = {}
        for fam in BENIGN:
            alerts = e['per_family'].get(fam, 0)
            n_units = 20  # seeds 10..29
            benign_rates[eng][fam] = {
                'alerts': alerts,
                'units': n_units,
                'trace_hours': n_units * BENIGN_TRACE_HOURS,
                'alerts_per_unit': alerts / n_units,
                'alerts_per_trace_hour': alerts / (n_units * BENIGN_TRACE_HOURS)}

    # --- latency: matcher distance on v2 matched pairs (ns) ---
    dists = [p['distance_ns'] for r in v2_rows for p in (r.get('matched_pairs') or [])
             if p.get('distance_ns') is not None]
    latency = {'v2_matched_pair_distance_ns': {
        'n': len(dists),
        'median_s': (statistics.median(dists) / 1e9) if dists else None,
        'max_s': (max(dists) / 1e9) if dists else None,
        'note': 'baseline decision timestamps unavailable per contract; '
                'EOF/start timestamps are not decision times'}}

    # --- stress families (out of scope, reported separately) ---
    stress = data['engines']['v2 detector (W=300, T=5) frozen'].get('stress_alerts', {})

    out = {
        'analysis': 'A4 section 4 predeclared analysis',
        'source_scoring_sha256': __import__('hashlib').sha256(
            Path(scoring_path).read_bytes()).hexdigest(),
        'bootstrap': {'resamples': RESAMPLES, 'analysis_seed': ANALYSIS_SEED,
                      'unit': 'trace (cluster), stratified by family, engines paired on trace',
                      'selection_scope_families': sel_families,
                      'intervals': intervals},
        'overall': {eng: dict(zip(('recall', 'matched', 'total'), recall(eng)))
                    for eng in camp},
        'per_family': per_family,
        'benign_alert_rates': benign_rates,
        'zero_tolerance_violations': {eng: len(e['zero_tolerance_violations'])
                                      for eng, e in data['engines'].items()},
        'duplicate_burden': {eng: e['expected_duplicate_burden']
                             for eng, e in data['engines'].items()},
        'latency': latency,
        'stress_family_alert_counts_v2': stress,
        'ambiguous_excluded': {'mixed-families': 'excluded from primary recall/precision per contract s6'},
    }
    Path(out_path).write_text(json.dumps(out, sort_keys=True, indent=1))
    print('wrote', out_path)
    print(json.dumps(out['overall'], indent=1))
    print(json.dumps({k: v for k, v in intervals.items()}, indent=1))


if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2])
