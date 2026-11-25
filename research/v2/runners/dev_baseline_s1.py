#!/usr/bin/env python3
"""Amendment A3 sensitivity run S1: Zeek baseline with one flipped deployment knob.

Repeats the exact default Zeek-baseline dev-corpus run (dev_baselines.py)
with the single added policy line `redef Site::private_address_space_is_local
= F;`. All detection thresholds and suppression remain the pinned package
defaults. Development seeds 0..9 only; held-out seeds are never touched.
Results are separately labeled and never merged into the default headline
numbers. See protocol.md Amendment A3 (frozen before this run).
"""
import importlib.util, json, os, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('db', ROOT / 'research/v2/runners/dev_baselines.py')
db = importlib.util.module_from_spec(spec)
spec.loader.exec_module(db)

GEN = db.GEN
DEV_SEEDS = db.DEV_SEEDS


def zeek_predictions_s1(prefix, sources, pcap, capture_id, workdir):
    env = os.environ.copy()
    env['LD_LIBRARY_PATH'] = os.pathsep.join([str(prefix / 'usr/lib/x86_64-linux-gnu'),
                                              str(prefix / 'lib')])
    zeekroot = prefix / 'opt/zeek/share/zeek'
    env['ZEEKPATH'] = os.pathsep.join([str(zeekroot), str(zeekroot / 'policy'),
                                       str(zeekroot / 'site'), str(zeekroot / 'builtin-plugins')])
    env['TZ'] = 'UTC'
    env.pop('ZEEK_SCRIPT_PREFIXES', None)
    env.pop('ZEEK_PLUGIN_PATH', None)
    policy = workdir / 'scanner.zeek'
    policy.write_text('@load ' + str(sources / 'bro-is-darknet/scripts') + '\n@load ' +
                      str(sources / 'bro-simple-scan/scripts') + '\n'
                      'redef Site::private_address_space_is_local = F;\n')
    rc, timed_out = db.run_engine([prefix / 'opt/zeek/bin/zeek', '-r', pcap, policy], workdir, env)
    if timed_out or rc != 0:
        raise RuntimeError('zeek failed rc=%s timeout=%s' % (rc, timed_out))
    log = workdir / 'notice.log'
    if not log.exists():
        return []
    preds, _ignored = db.ZEEK_AD.parse_notice_log(log.read_text(), capture_id)
    return preds


def main(argv=None):
    prefix = Path(argv[1]).resolve()
    sources = Path(argv[2]).resolve()
    corpus = Path(argv[3] if len(argv) > 3 else '/downloads/portscan-v2-execution/dev-corpus')
    if not (corpus / ('approved-admin-scan-s0.labels.json')).exists():
        raise SystemExit('dev corpus missing; regenerate via dev_selection.py first')
    label = ('zeek-8.0.11+bro-simple-scan(35cf19cf)+bro-is-darknet(7564a8f2) '
             'A3-S1 sensitivity: only private_address_space_is_local=F, all detection '
             'thresholds at package defaults')
    report = {'split': 'development', 'seeds': '0..9',
              'purpose': 'Amendment A3 S1 sensitivity diagnostic; separately labeled; '
                         'never merged into default-configuration headline numbers; '
                         'not held-out or deployment performance',
              'amendment': 'A3 (protocol.md, frozen 22 November 2026 before this run)',
              'binary_sha256': {'zeek': db.sha256(prefix / 'opt/zeek/bin/zeek')},
              'burden_window_s': db.BURDEN_WINDOW_S, 'engines': {}}
    per_engine = {'campaigns_total': 0, 'campaigns_matched': 0,
                  'zero_tolerance_violations': [], 'expected_alert_units': 0,
                  'expected_duplicate_burden': 0, 'total_alerts': 0,
                  'failed_traces': [], 'per_family': {}}
    for fam in GEN.FAMILIES:
        fam_alerts = 0
        for seed in DEV_SEEDS:
            cid = '%s-s%d' % (fam, seed)
            pcap = corpus / (cid + '.pcap')
            labels = json.loads((corpus / (cid + '.labels.json')).read_text())
            with tempfile.TemporaryDirectory() as td:
                try:
                    preds = zeek_predictions_s1(prefix, sources, pcap, cid, Path(td))
                except Exception as exc:
                    per_engine['failed_traces'].append('%s: %s' % (cid, exc))
                    continue
            fam_alerts += len(preds)
            s = db.score(fam, labels, preds, str(pcap))
            per_engine['campaigns_total'] += s['campaigns_total']
            per_engine['campaigns_matched'] += s['campaigns_matched']
            per_engine['expected_alert_units'] += s['expected_alert_unit']
            per_engine['expected_duplicate_burden'] += s['expected_duplicate_burden']
            if s['zero_tolerance_violation']:
                per_engine['zero_tolerance_violations'].append(cid)
        per_engine['per_family'][fam] = fam_alerts
        per_engine['total_alerts'] += fam_alerts
    per_engine['recall'] = (per_engine['campaigns_matched'] / per_engine['campaigns_total']
                            if per_engine['campaigns_total'] else None)
    report['engines'][label] = per_engine
    print(label, json.dumps({'recall': per_engine['recall'],
                             'alerts': per_engine['total_alerts'],
                             'zt_violations': len(per_engine['zero_tolerance_violations']),
                             'failed': len(per_engine['failed_traces'])}))
    dest = ROOT / 'research/v2/results/raw/dev-baselines-sensitivity-2026-11-22.json'
    dest.write_text(json.dumps(report, sort_keys=True, indent=1))
    print('wrote', dest)
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
