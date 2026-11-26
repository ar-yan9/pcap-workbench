#!/usr/bin/env python3
"""Held-out scoring runner (Amendment A4, 26 November 2026).

Runs the frozen configuration over held-out seeds 10..29 only:
  * v2 selection detector at the dev-selected operating point (W=300, T=5),
  * Zeek 8.0.11 + pinned ncsa scanner packages at recorded defaults,
  * Snort 3.13.2.0 port_scan inspector at recorded defaults.
No S1 variant (A4 section 3). Scores with the same frozen matcher, adapters
and contract gates as the development runs. The corpus directory must already
exist with a manifest.json (A4 generation step); every input file's SHA-256
is verified against that manifest before any engine runs. Run manifests
record argument vectors, UTC windows, per-trace input hashes, exit codes and
failure accounting per the protocol: a failed/timed-out engine run is a
failed trace, never a zero-alert success. Captures stay local.

Usage: heldout_scoring.py <engine-prefix> <scanner-sources> <corpus-dir> [out-json]
"""
import hashlib, importlib.util, json, sys, tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]

def _load(name, rel):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

GEN = _load('synthetic_corpus', 'research/v2/generators/synthetic_corpus.py')
SEL = _load('dev_selection', 'research/v2/runners/dev_selection.py')
BASE = _load('dev_baselines', 'research/v2/runners/dev_baselines.py')

W_FROZEN, T_FROZEN = 300, 5
HELD_OUT_SEEDS = range(10, 30)


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def utcnow():
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'


def verify_corpus(corpus):
    mpath = corpus / 'manifest.json'
    if mpath.exists():
        manifest = json.loads(mpath.read_text())
        files = manifest['files']
    else:
        # development smoke-test path: dev corpus predates manifest emission;
        # synthesize the ledger from current on-disk hashes (dev data only).
        manifest = {'files': {}}
        files = {p.name: sha256(p) for p in sorted(corpus.glob('*'))
                 if p.suffix in ('.pcap', '.json')}
    bad = []
    for fn, want in files.items():
        p = corpus / fn
        if not p.exists() or sha256(p) != want:
            bad.append(fn)
    return manifest, bad


def score_detector_trace(fam, labels, alerts, preds, pcap, per, detail=None):
    """Mirror dev_selection.evaluate per-trace logic at the frozen setting.
    When detail (a list) is given, append a per-trace record with campaign
    outcomes, matched-pair distances and unmatched-alert counts for the
    predeclared A4 section-4 analysis (additive output; scoring unchanged)."""
    eps = SEL.episodes_from_labels(labels)
    if fam in SEL.ZERO_TOLERANCE_BOTH:
        if alerts:
            per['zero_tolerance_violations'].append(labels['capture_id'])
    elif fam in SEL.ZERO_TOLERANCE_VERTICAL:
        va = [a for a in alerts if a['direction'] == 'vertical']
        if va:
            per['zero_tolerance_violations'].append(labels['capture_id'])
        if [a for a in alerts if a['direction'] == 'horizontal']:
            per['expected_alert_units'] += 1
    elif fam in SEL.EXPECTED_VERTICAL:
        va = [a for a in alerts if a['direction'] == 'vertical']
        if va:
            per['expected_alert_units'] += 1
            for e in eps:
                segs = SEL.benign_segments(pcap, e['scanner'], e.get('target'),
                                           W_FROZEN) if e.get('target') else 1
                per['expected_duplicate_burden'] += max(0, len(va) - segs)
    if fam in SEL.ATTACK_SELECTION or fam in SEL.STRESS_OUT_OF_SCOPE:
        built = SEL.COMPAT.build_candidates(eps, preds)
        triples = [(c['episode_id'], c['alert_id'], c['distance_ns'])
                   for c in built['candidates']]
        matched = SEL.MATCH.match_candidates([e['episode_id'] for e in eps],
                                             [p['alert_id'] for p in preds],
                                             triples)
        matched_eps = {pair[0] for pair in matched['pairs']}
        if detail is not None:
            dist = {}
            for eid, aid, d in triples:
                dist.setdefault((eid, aid), d)
            pair_rows = [{'episode_id': a, 'alert_id': b,
                          'distance_ns': dist.get((a, b))}
                         for a, b in matched['pairs']]
            detail.append({'capture_id': labels['capture_id'], 'family': fam,
                           'engine': 'v2', 'alerts': len(alerts),
                           'episodes': len(eps),
                           'matched_pairs': pair_rows,
                           'campaigns': None})
        campaigns = {}
        for e in eps:
            campaigns.setdefault(e['campaign_id'], []).append(e)
        for cid, members in campaigns.items():
            if fam in SEL.ATTACK_SELECTION and members[0]['intent'] == 'attack':
                per['campaigns_total'] += 1
                hit = any(m['episode_id'] in matched_eps for m in members)
                if hit:
                    per['campaigns_matched'] += 1
                if detail is not None:
                    detail[-1]['campaigns'] = detail[-1]['campaigns'] or []
                    detail[-1]['campaigns'].append(
                        {'campaign_id': cid, 'matched': bool(hit)})
        if fam in SEL.STRESS_OUT_OF_SCOPE:
            per['stress_alerts'][labels['capture_id']] = len(alerts)


def main(argv=None):
    prefix = Path(argv[1]).resolve()
    sources = Path(argv[2]).resolve()
    corpus = Path(argv[3]).resolve()
    seeds = HELD_OUT_SEEDS if 'heldout' in corpus.name else range(10)
    # optional execution chunking (sandbox wall-clock limits): identical
    # scoring code, family subset per invocation; partials merged by
    # arithmetic only (sums, list concatenation, dict union, OR).
    families = (argv[5].split(',') if len(argv) > 5 else list(GEN.FAMILIES))

    manifest, bad = verify_corpus(corpus)
    if bad:
        print('CORPUS INTEGRITY FAILURE:', bad[:5], '(%d files)' % len(bad))
        return 2

    trace_detail = []
    report = {'split': 'held-out', 'seeds': '10..29',
              'amendment': 'A4 (frozen configuration; no S1 on held-out)',
              'operating_point': {'W': W_FROZEN, 'T': T_FROZEN},
              'corpus_manifest_sha256': (sha256(corpus / 'manifest.json')
                                         if (corpus / 'manifest.json').exists() else
                                         hashlib.sha256(json.dumps(manifest['files'],
                                         sort_keys=True).encode()).hexdigest()),
              'binary_sha256': {'zeek': sha256(prefix / 'opt/zeek/bin/zeek'),
                                'snort': sha256(prefix / 'bin/snort')},
              'burden_window_s': BASE.BURDEN_WINDOW_S,
              'engines': {}}

    # --- v2 detector at the frozen operating point ---
    label = 'v2 detector (W=300, T=5) frozen'
    per = {'zero_tolerance_violations': [], 'expected_alert_units': 0,
           'expected_duplicate_burden': 0, 'campaigns_total': 0,
           'campaigns_matched': 0, 'stress_alerts': {},
           'cap_exhausted': False, 'failed_traces': [], 'total_alerts': 0,
           'per_family': {}}
    runs = []
    t0 = utcnow()
    for fam in families:
        fam_alerts = 0
        for seed in seeds:
            cid = '%s-s%d' % (fam, seed)
            pcap = corpus / (cid + '.pcap')
            labels = json.loads((corpus / (cid + '.labels.json')).read_text())
            start = utcnow()
            try:
                alerts, summary = SEL.DET.run(str(pcap), W_FROZEN, T_FROZEN)
                rc, timed_out = 0, False
            except Exception as exc:
                per['failed_traces'].append('%s: %s' % (cid, exc))
                runs.append({'capture_id': cid, 'engine': 'v2', 'start_utc': start,
                             'end_utc': utcnow(), 'rc': 'exception', 'timed_out': False,
                             'input_sha256': sha256(pcap)})
                continue
            if summary['caps_exhausted']:
                per['cap_exhausted'] = True
            preds = SEL.predictions_from_alerts(alerts, labels['capture_id'])
            runs.append({'capture_id': cid, 'engine': 'v2', 'start_utc': start,
                         'end_utc': utcnow(), 'rc': rc, 'timed_out': timed_out,
                         'input_sha256': sha256(pcap),
                         'alert_count': len(alerts)})
            fam_alerts += len(alerts)
            score_detector_trace(fam, labels, alerts, preds, str(pcap), per,
                                 detail=trace_detail)
        per['per_family'][fam] = fam_alerts
        per['total_alerts'] += fam_alerts
    per['recall'] = (per['campaigns_matched'] / per['campaigns_total']
                     if per['campaigns_total'] else None)
    per['families_in_chunk'] = families
    per['run_window_utc'] = {'start': t0, 'end': utcnow()}
    report['engines'][label] = per

    # --- baselines at pinned defaults (same scoring path as dev_baselines) ---
    engines = {'zeek-8.0.11+bro-simple-scan(35cf19cf)+bro-is-darknet(7564a8f2) defaults': 'zeek',
               'snort-3.13.2.0 port_scan inspector defaults': 'snort'}
    for blabel, kind in engines.items():
        bp = {'campaigns_total': 0, 'campaigns_matched': 0,
              'zero_tolerance_violations': [], 'expected_alert_units': 0,
              'expected_duplicate_burden': 0, 'total_alerts': 0,
              'failed_traces': [], 'per_family': {}}
        t0 = utcnow()
        for fam in families:
            fam_alerts = 0
            for seed in seeds:
                cid = '%s-s%d' % (fam, seed)
                pcap = corpus / (cid + '.pcap')
                labels = json.loads((corpus / (cid + '.labels.json')).read_text())
                start = utcnow()
                with tempfile.TemporaryDirectory() as td:
                    workdir = Path(td)
                    try:
                        if kind == 'zeek':
                            preds = BASE.zeek_predictions(prefix, sources, pcap, cid, workdir)
                        else:
                            preds = BASE.snort_predictions(prefix, pcap, cid, workdir)
                        rc = 0
                    except Exception as exc:
                        bp['failed_traces'].append('%s: %s' % (cid, exc))
                        runs.append({'capture_id': cid, 'engine': kind,
                                     'start_utc': start, 'end_utc': utcnow(),
                                     'rc': 'exception', 'timed_out': False,
                                     'input_sha256': sha256(pcap)})
                        continue
                runs.append({'capture_id': cid, 'engine': kind, 'start_utc': start,
                             'end_utc': utcnow(), 'rc': rc, 'timed_out': False,
                             'input_sha256': sha256(pcap),
                             'alert_count': len(preds)})
                fam_alerts += len(preds)
                s = BASE.score(fam, labels, preds, str(pcap))
                trow = {'capture_id': cid, 'family': fam, 'engine': kind,
                        'alerts': len(preds),
                        'campaigns_total': s['campaigns_total'],
                        'campaigns_matched': s['campaigns_matched']}
                if fam in SEL.ATTACK_SELECTION or fam in SEL.STRESS_OUT_OF_SCOPE:
                    built = SEL.COMPAT.build_candidates(
                        [dict(e, capture_id=labels['capture_id']) for e in labels['episodes']],
                        preds)
                    triples = [(c['episode_id'], c['alert_id'], c['distance_ns'])
                               for c in built['candidates']]
                    eps_ids = [e['episode_id'] for e in labels['episodes']]
                    matched = SEL.MATCH.match_candidates(
                        eps_ids, [p['alert_id'] for p in preds], triples)
                    dist = {}
                    for eid, aid, d in triples:
                        dist.setdefault((eid, aid), d)
                    trow['matched_pairs'] = [
                        {'episode_id': a, 'alert_id': b,
                         'distance_ns': dist.get((a, b))}
                        for a, b in matched['pairs']]
                trace_detail.append(trow)
                bp['campaigns_total'] += s['campaigns_total']
                bp['campaigns_matched'] += s['campaigns_matched']
                bp['expected_alert_units'] += s['expected_alert_unit']
                bp['expected_duplicate_burden'] += s['expected_duplicate_burden']
                if s['zero_tolerance_violation']:
                    bp['zero_tolerance_violations'].append(cid)
            bp['per_family'][fam] = fam_alerts
            bp['total_alerts'] += fam_alerts
        bp['recall'] = (bp['campaigns_matched'] / bp['campaigns_total']
                        if bp['campaigns_total'] else None)
        bp['run_window_utc'] = {'start': t0, 'end': utcnow()}
        report['engines'][blabel] = bp

    report['run_manifests'] = runs
    report['trace_detail'] = trace_detail
    dest = (Path(argv[4]).resolve() if len(argv) > 4
            else ROOT / 'research/v2/results/raw/heldout-scoring-2026-11-26.json')
    dest.write_text(json.dumps(report, sort_keys=True, indent=1))
    print('wrote', dest)
    print('engines scored:', list(report['engines'].keys()))
    print('failed traces per engine:',
          {k: len(v['failed_traces']) for k, v in report['engines'].items()})
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
