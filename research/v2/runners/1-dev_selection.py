#!/usr/bin/env python3
"""Development operating-point selection runner (operating-point-selection.md v1.0).

Generates development traces (seeds 0..9) with the frozen generator, runs the
v2 selection detector over the 12-setting grid, applies the Amendment A2/A2.1
budget filter per key dimension, computes campaign-level development recall
with the frozen matcher, and selects (W, T). Writes a results JSON with full
per-setting tables. No held-out seeds are generated or inspected.
"""
import hashlib, importlib.util, json, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]

def _load(name, rel):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

GEN = _load('synthetic_corpus', 'research/v2/generators/synthetic_corpus.py')
DET = _load('v2_detector', 'research/v2/detectors/v2_detector.py')
COMPAT = _load('compatibility', 'research/v2/adapters/compatibility.py')
MATCH = _load('matching', 'research/v2/adapters/matching.py')

GRID_W = (10, 60, 300)
GRID_T = (5, 10, 15, 20)
DEV_SEEDS = range(10)

ATTACK_SELECTION = {'fast-vertical-syn', 'threshold-edge-syn', 'horizontal-syn',
                    'fin', 'null', 'xmas', 'repeated-vertical-bursts',
                    'repeated-horizontal-bursts', 'mixed-families'}
STRESS_OUT_OF_SCOPE = {'slow-syn', 'distributed-syn', 'udp'}
ZERO_TOLERANCE_BOTH = {'normal-sessions', 'few-port-retries', 'fin-ack-teardown'}
ZERO_TOLERANCE_VERTICAL = {'service-discovery'}
EXPECTED_VERTICAL = {'approved-admin-scan', 'nat-shared-source'}
EXPECTED_HORIZONTAL = {'service-discovery'}


def trace_paths(out_dir):
    for fam in GEN.FAMILIES:
        for seed in DEV_SEEDS:
            yield fam, seed, out_dir / ('%s-s%d.pcap' % (fam, seed)), out_dir / ('%s-s%d.labels.json' % (fam, seed))


def generate(out_dir):
    out_dir.mkdir(parents=True, exist_ok=True)
    for fam in GEN.FAMILIES:
        for seed in DEV_SEEDS:
            ev, labels = GEN.build(fam, seed)
            cid = labels['capture_id']
            GEN.write_pcap(out_dir / (cid + '.pcap'), ev)
            (out_dir / (cid + '.labels.json')).write_text(json.dumps(labels, sort_keys=True))


def predictions_from_alerts(alerts, capture_id):
    preds = []
    for a in alerts:
        key = '%s|%s|%s|%s|%s' % (a['direction'], a['family'], a['scanner'],
                                  a.get('target', a.get('target_port')), a['key_fire_index'])
        p = {'alert_id': '%s#v2det#%s' % (capture_id, key),
             'capture_id': capture_id, 'scanner': a['scanner'],
             'direction': a['direction'], 'family': a['family'],
             'event_time_ns': a['event_time_ns'], 'decision_time_ns': a['decision_time_ns']}
        if a['direction'] == 'vertical':
            p['target_host'] = a['target']
        else:
            p['target_port'] = a['target_port']
        preds.append(p)
    return preds


def episodes_from_labels(labels):
    eps = []
    for e in labels['episodes']:
        ep = dict(e)
        ep['capture_id'] = labels['capture_id']
        eps.append(ep)
    return eps


def benign_segments(path, scanner, target, W_s):
    """Label-derived contiguous probe segments for a (scanner, target) pair."""
    times = sorted(t for (t, n, s, d, sp, dp, fl, af) in DET.read_pcap(path)
                   if '.'.join(map(str, s)) == scanner and '.'.join(map(str, d)) == target)
    segs, last = 0, None
    for t in times:
        if last is None or t - last > int(W_s * 1e9):
            segs += 1
        last = t
    return max(segs, 1)


def evaluate(out_dir):
    """Return per-setting results: {(W,T): {...}}."""
    results = {}
    traces = []
    for fam, seed, pcap, lab in trace_paths(out_dir):
        labels = json.loads(lab.read_text())
        traces.append((fam, seed, pcap, labels))
    for W in GRID_W:
        for T in GRID_T:
            per = {'zero_tolerance_violations': [], 'expected_alert_units': 0,
                   'expected_duplicate_burden': 0, 'campaigns_total': 0,
                   'campaigns_matched': 0, 'stress_alerts': {},
                   'cap_exhausted': False, 'failed_traces': []}
            for fam, seed, pcap, labels in traces:
                alerts, summary = DET.run(str(pcap), W, T)
                if summary['caps_exhausted']:
                    per['cap_exhausted'] = True
                preds = predictions_from_alerts(alerts, labels['capture_id'])
                eps = episodes_from_labels(labels)
                famset = fam
                if famset in ZERO_TOLERANCE_BOTH:
                    if alerts:
                        per['zero_tolerance_violations'].append(labels['capture_id'])
                elif famset in ZERO_TOLERANCE_VERTICAL:
                    va = [a for a in alerts if a['direction'] == 'vertical']
                    if va:
                        per['zero_tolerance_violations'].append(labels['capture_id'])
                    ha = [a for a in alerts if a['direction'] == 'horizontal']
                    if ha:
                        per['expected_alert_units'] += 1
                elif famset in EXPECTED_VERTICAL:
                    va = [a for a in alerts if a['direction'] == 'vertical']
                    if va:
                        per['expected_alert_units'] += 1
                        for e in eps:
                            segs = benign_segments(pcap, e['scanner'], e.get('target'), W) if e.get('target') else 1
                            per['expected_duplicate_burden'] += max(0, len(va) - segs)
                # campaign-level recall over selection-scope attack campaigns
                if famset in ATTACK_SELECTION or famset in STRESS_OUT_OF_SCOPE:
                    built = COMPAT.build_candidates(eps, preds)
                    triples = [(c['episode_id'], c['alert_id'], c['distance_ns'])
                               for c in built['candidates']]
                    matched = MATCH.match_candidates(
                        [e['episode_id'] for e in eps],
                        [p['alert_id'] for p in preds],
                        triples)
                    matched_eps = {pair[0] for pair in matched['pairs']}
                    campaigns = {}
                    for e in eps:
                        campaigns.setdefault(e['campaign_id'], []).append(e)
                    for cid, members in campaigns.items():
                        intent = members[0]['intent']
                        if famset in ATTACK_SELECTION and intent == 'attack':
                            per['campaigns_total'] += 1
                            if any(m['episode_id'] in matched_eps for m in members):
                                per['campaigns_matched'] += 1
                    if famset in STRESS_OUT_OF_SCOPE:
                        per['stress_alerts'][labels['capture_id']] = len(alerts)
            results['%d,%d' % (W, T)] = per
    return results


def select(results):
    """Amendment A2 selection: budget filter, maximal recall, ordered tie-breaks."""
    rows = []
    for key, per in results.items():
        W, T = (int(x) for x in key.split(','))
        ok = not per['zero_tolerance_violations'] and not per['cap_exhausted'] \
            and per['expected_duplicate_burden'] == 0 and not per['failed_traces']
        recall = (per['campaigns_matched'] / per['campaigns_total']
                  if per['campaigns_total'] else None)
        rows.append({'W': W, 'T': T, 'budget_ok': ok, 'recall': recall,
                     'expected_alert_units': per['expected_alert_units'],
                     'zero_tolerance_violations': per['zero_tolerance_violations']})
    passing = [r for r in rows if r['budget_ok'] and r['recall'] is not None]
    if not passing:
        return None, rows
    best = max(r['recall'] for r in passing)
    tied = [r for r in passing if r['recall'] == best]
    tied.sort(key=lambda r: (r['expected_alert_units'], -r['W'], -r['T']))
    return tied[0], rows


def main(argv=None):
    out_dir = Path(argv[1] if argv and len(argv) > 1 else '/downloads/portscan-v2-execution/dev-corpus')
    generate(out_dir)
    results = evaluate(out_dir)
    selected, rows = select(results)
    report = {'rule': 'operating-point-selection.md v1.0', 'split': 'development',
              'seeds': '0..9', 'grid': {'W': GRID_W, 'T': GRID_T},
              'selected': selected, 'per_setting': rows,
              'details': results}
    dest = ROOT / 'research/v2/results/raw/dev-selection-2026-11-18.json'
    dest.write_text(json.dumps(report, sort_keys=True, indent=1))
    print(json.dumps({'selected': selected,
                      'passing': [r for r in rows if r['budget_ok']]}, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
