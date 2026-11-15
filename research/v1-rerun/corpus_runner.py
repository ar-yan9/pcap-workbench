#!/usr/bin/env python3
"""C1 corpus runner: multi-seed v1.1 evaluation with bootstrap CIs.

Regenerates one synthetic fixture per seed with the v1.1 generator (vary mode),
evaluates each with the frozen detector and the frozen eight-setting grid, and
writes per-seed rows plus aggregate statistics with bootstrap confidence
intervals. The legacy seed 20261027 fixture is evaluated as-is (no vary) and
reported separately as the published anchor run.

Everything here is deterministic: fixtures are seed-deterministic, the
bootstrap RNG is string-seeded, and output JSON is written with sorted keys.
Rerunning the runner on the same inputs must produce byte-identical outputs
(except the manifest's generated_at timestamp).

Usage:
    python3 corpus_runner.py                 # seeds 0..29 plus the anchor
    python3 corpus_runner.py --seeds 0 1 2   # subset

--data-dir / --results-dir / --manifest redirect outputs (used by tests so a
mini run never clobbers the canonical corpus artifacts). The legacy anchor
fixture is always read from this directory's data/seed-20261027/.
"""
import argparse
import hashlib
import tempfile
import zipfile
import json
import random
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
GENERATOR = HERE / 'generators' / 'gen_capture_v1_1.py'
EVALUATOR = HERE / 'evaluate.py'
IMPLEMENTATION = HERE / 'evaluated_workbench.py'
ANCHOR_SEED = 20261027
FROZEN_ZIP = HERE.parent.parent / '1-portscan-study-v3.zip'
ANCHOR_MEMBERS = ['eval.pcap', 'eval.labels', 'eval.labels.events.json']
SETTINGS = [(10, 10), (60, 10), (300, 10), (60, 5), (60, 15), (60, 20), (300, 5), (300, 20)]
BOOTSTRAP_DRAWS = 10000

sys.path.insert(0, str(HERE))
import importlib.util
_spec = importlib.util.spec_from_file_location('v1_evaluate', EVALUATOR)
ev = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ev)


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def generate(seed, data_dir):
    """Generate (or regenerate) the fixture for one seed; return its paths."""
    out_dir = Path(data_dir) / ('seed-%d' % seed)
    out_dir.mkdir(parents=True, exist_ok=True)
    pcap = out_dir / 'eval.pcap'
    labels = out_dir / 'eval.labels'
    if seed == ANCHOR_SEED:
        args = []  # legacy mode: no vary, must stay byte-identical to the anchor
    else:
        args = [str(seed), 'vary']
    subprocess.run([sys.executable, str(GENERATOR), str(pcap), str(labels), *args],
                   check=True, capture_output=True, text=True)
    return pcap, labels


def bootstrap_ci(values, rng):
    """95% percentile bootstrap CI of the mean over per-seed values."""
    n = len(values)
    if n == 0:
        return [None, None]
    if n == 1:
        return [values[0], values[0]]
    means = []
    for _ in range(BOOTSTRAP_DRAWS):
        means.append(sum(values[rng.randrange(n)] for _ in range(n)) / n)
    means.sort()
    lo = means[int(0.025 * BOOTSTRAP_DRAWS)]
    hi = means[min(int(0.975 * BOOTSTRAP_DRAWS), BOOTSTRAP_DRAWS - 1)]
    return [lo, hi]


def summarize(per_seed_rows):
    """Aggregate per-setting metrics across seeds.

    per_seed_rows: {seed: {f"{window},{ports}": row}}
    Metrics that are None for any seed (undefined denominator) are dropped for
    that setting and noted.
    """
    rng = random.Random('v1.1-corpus-bootstrap')
    summary = {}
    for window, ports in SETTINGS:
        key = '%d,%d' % (window, ports)
        rows = [per_seed_rows[s][key] for s in per_seed_rows]
        entry = {'window': window, 'ports': ports, 'seeds': len(rows)}
        for metric in ('alert_precision', 'event_recall'):
            vals = [r[metric] for r in rows]
            dropped = sum(v is None for v in vals)
            vals = [v for v in vals if v is not None]
            if not vals:
                entry[metric] = None
                continue
            entry[metric] = {
                'mean': sum(vals) / len(vals),
                'min': min(vals),
                'max': max(vals),
                'ci95': bootstrap_ci(vals, rng),
                'dropped_seeds': dropped,
            }
        entry['mean_alerts'] = sum(r['alerts'] for r in rows) / len(rows)
        entry['total_alert_false_positives'] = sum(r['alert_false_positives'] for r in rows)
        entry['total_unmatched_alerts'] = sum(len(r['unmatched_alerts']) for r in rows)
        summary[key] = entry
    return summary


def markdown_table(summary, anchor_row):
    lines = ['| window | ports | mean precision (95% CI) | mean recall (95% CI) | mean alerts |',
             '|---:|---:|---|---|---:|']
    for window, ports in SETTINGS:
        key = '%d,%d' % (window, ports)
        s = summary[key]
        def fmt(m):
            if s[m] is None:
                return 'n/a'
            return '%.3f [%.3f, %.3f]' % (s[m]['mean'], s[m]['ci95'][0], s[m]['ci95'][1])
        lines.append('| %d | %d | %s | %s | %.1f |' % (
            window, ports, fmt('alert_precision'), fmt('event_recall'), s['mean_alerts']))
    return '\n'.join(lines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--seeds', type=int, nargs='*', default=list(range(30)))
    ap.add_argument('--data-dir', default=str(HERE / 'data'))
    ap.add_argument('--results-dir', default=str(HERE / 'results'))
    ap.add_argument('--manifest', default=str(HERE / 'manifest.json'))
    args = ap.parse_args()

    data_dir = Path(args.data_dir)
    results_dir = Path(args.results_dir)

    per_seed_rows = {}
    raw = {}
    fixtures = {}
    for seed in args.seeds:
        pcap, labels = generate(seed, data_dir)
        out = ev.evaluate(str(IMPLEMENTATION), str(pcap), str(labels))
        raw[str(seed)] = out
        per_seed_rows[seed] = {'%d,%d' % (r['window'], r['ports']): r for r in out['results']}
        fixtures['seed-%d' % seed] = {
            'eval.pcap': sha256(pcap),
            'eval.labels': sha256(labels),
            'eval.labels.events.json': sha256(str(labels) + '.events.json'),
        }
        print('seed %d: %d settings evaluated' % (seed, len(out['results'])))

    # Anchor fixture ships inside the frozen revision-3 ZIP (repo root);
    # extract it to hash and evaluate the exact published bytes.
    anchor_hashes = {}
    with zipfile.ZipFile(FROZEN_ZIP) as z, tempfile.TemporaryDirectory() as anchor_dir:
        for member in ANCHOR_MEMBERS:
            data = z.read('portscan-study-v3/data/' + member)
            anchor_hashes[member] = hashlib.sha256(data).hexdigest()
            Path(anchor_dir, member).write_bytes(data)
        anchor = ev.evaluate(str(IMPLEMENTATION),
                             str(Path(anchor_dir, 'eval.pcap')),
                             str(Path(anchor_dir, 'eval.labels')))
    fixtures['seed-%d' % ANCHOR_SEED] = anchor_hashes

    summary = summarize(per_seed_rows)

    results_dir.mkdir(parents=True, exist_ok=True)
    (results_dir / 'corpus_runs.json').write_text(
        json.dumps({'seeds': args.seeds, 'runs': raw,
                    'anchor_seed_%d' % ANCHOR_SEED: anchor}, indent=2, sort_keys=True) + '\n')
    (results_dir / 'corpus_summary.json').write_text(
        json.dumps({'seeds': args.seeds, 'bootstrap_draws': BOOTSTRAP_DRAWS,
                    'settings': summary}, indent=2, sort_keys=True) + '\n')

    table = markdown_table(summary, None)
    md = ['# v1.1 corpus summary', '',
          'Seeds: %s (vary mode). Detector and evaluator frozen from revision 3.' % (
              ', '.join(map(str, args.seeds))),
          'Bootstrap: %d draws, percentile 95%% CI of the across-seed mean.' % BOOTSTRAP_DRAWS,
          '', table, '']
    (results_dir / 'corpus_summary.md').write_text('\n'.join(md))

    manifest = {
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'generator_sha256': sha256(GENERATOR),
        'evaluator_sha256': sha256(EVALUATOR),
        'implementation_sha256': sha256(IMPLEMENTATION),
        'seeds': args.seeds,
        'anchor_seed': ANCHOR_SEED,
        'settings': SETTINGS,
        'bootstrap_draws': BOOTSTRAP_DRAWS,
        'fixtures': fixtures,
    }
    Path(args.manifest).write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
    print(table)
    print('wrote results/corpus_runs.json, results/corpus_summary.{json,md}, manifest.json')


if __name__ == '__main__':
    main()
