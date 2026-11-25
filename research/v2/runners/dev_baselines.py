#!/usr/bin/env python3
"""Development-corpus baseline runner for pinned Zeek/Snort engines.

Runs the ACTUAL provisioned engines (Zeek 8.0.11 + pinned ncsa scanner
packages, Snort 3.13.2.0 port_scan inspector, frozen activation configs) over
the development corpus (seeds 0..9, same frozen generator as
dev_selection.py) and scores them with the same independent matcher and
contract gates as the v2 detector. Baselines run at their pinned defaults:
they are never tuned to W/T, and are separately labeled per protocol.md.
No held-out seeds are generated or inspected. Captures stay local.

Duplicate-burden accounting for baselines uses the same 300s benign segment
window as the selected v2 operating point (W=300, T=5 from
operating-point-selection.md v1.0), documented here as a fixed accounting
constant, not a baseline tuning knob.
"""
import hashlib, importlib.util, json, os, subprocess, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]

def _load(name, rel):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

GEN = _load('synthetic_corpus', 'research/v2/generators/synthetic_corpus.py')
ZEEK_AD = _load('zeek_notice', 'research/v2/adapters/zeek_notice.py')
SNORT_AD = _load('snort_alert', 'research/v2/adapters/snort_alert.py')
COMPAT = _load('compatibility', 'research/v2/adapters/compatibility.py')
MATCH = _load('matching', 'research/v2/adapters/matching.py')
SEL = _load('dev_selection', 'research/v2/runners/dev_selection.py')

DEV_SEEDS = range(10)
BURDEN_WINDOW_S = 300  # accounting constant from the frozen selection record

ATTACK_SELECTION = SEL.ATTACK_SELECTION
STRESS_OUT_OF_SCOPE = SEL.STRESS_OUT_OF_SCOPE
ZERO_TOLERANCE_BOTH = SEL.ZERO_TOLERANCE_BOTH
ZERO_TOLERANCE_VERTICAL = SEL.ZERO_TOLERANCE_VERTICAL
EXPECTED_VERTICAL = SEL.EXPECTED_VERTICAL


def sha256(path):
    h = hashlib.sha256()
    h.update(Path(path).read_bytes())
    return h.hexdigest()


def run_engine(argv, cwd, env, timeout=60):
    with subprocess.Popen([str(a) for a in argv], cwd=cwd, env=env,
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                          start_new_session=True) as p:
        try:
            rc = p.wait(timeout=timeout)
            return rc, False
        except subprocess.TimeoutExpired:
            import signal
            os.killpg(p.pid, signal.SIGKILL)
            p.wait()
            return -9, True


def zeek_predictions(prefix, sources, pcap, capture_id, workdir):
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
                      str(sources / 'bro-simple-scan/scripts') + '\n')
    rc, timed_out = run_engine([prefix / 'opt/zeek/bin/zeek', '-r', pcap, policy], workdir, env)
    if timed_out or rc != 0:
        raise RuntimeError('zeek failed rc=%s timeout=%s' % (rc, timed_out))
    log = workdir / 'notice.log'
    if not log.exists():
        return []
    preds, _ignored = ZEEK_AD.parse_notice_log(log.read_text(), capture_id)
    return preds


def snort_predictions(prefix, pcap, capture_id, workdir):
    env = os.environ.copy()
    env['LD_LIBRARY_PATH'] = os.pathsep.join([str(prefix / 'usr/lib/x86_64-linux-gnu'),
                                              str(prefix / 'lib')])
    config = workdir / 'snort.lua'
    config.write_text('include ' + json.dumps(str(prefix / 'etc/snort/snort.lua')) + '\n'
                      + 'ips.enable_builtin_rules = true\n'
                      + "alert_json = { file = true, fields = 'timestamp seconds pkt_num proto src_addr dst_addr src_port dst_port gid sid msg' }\n")
    rc, timed_out = run_engine([prefix / 'bin/snort', '--daq-dir', prefix / 'lib/daq',
                                '-c', config, '-r', pcap, '-l', workdir], workdir, env)
    if timed_out or rc != 0:
        raise RuntimeError('snort failed rc=%s timeout=%s' % (rc, timed_out))
    log = workdir / 'alert_json.txt'
    if not log.exists():
        return []
    preds, _ignored = SNORT_AD.parse_alert_json(log.read_text(), capture_id)
    return preds


def score(fam, labels, preds, pcap):
    """Mirror dev_selection.evaluate per-trace scoring for one engine."""
    out = {'alert_count': len(preds), 'zero_tolerance_violation': False,
           'expected_alert_unit': 0, 'expected_duplicate_burden': 0,
           'campaigns_total': 0, 'campaigns_matched': 0}
    eps = []
    for e in labels['episodes']:
        ep = dict(e)
        ep['capture_id'] = labels['capture_id']
        eps.append(ep)
    if fam in ZERO_TOLERANCE_BOTH:
        if preds:
            out['zero_tolerance_violation'] = True
    elif fam in ZERO_TOLERANCE_VERTICAL:
        va = [p for p in preds if p['direction'] == 'vertical']
        if va:
            out['zero_tolerance_violation'] = True
        if [p for p in preds if p['direction'] == 'horizontal']:
            out['expected_alert_unit'] = 1
    elif fam in EXPECTED_VERTICAL:
        va = [p for p in preds if p['direction'] == 'vertical']
        if va:
            out['expected_alert_unit'] = 1
            for e in eps:
                segs = SEL.benign_segments(pcap, e['scanner'], e.get('target'),
                                           BURDEN_WINDOW_S) if e.get('target') else 1
                out['expected_duplicate_burden'] += max(0, len(va) - segs)
    if fam in ATTACK_SELECTION or fam in STRESS_OUT_OF_SCOPE:
        built = COMPAT.build_candidates(eps, preds)
        triples = [(c['episode_id'], c['alert_id'], c['distance_ns'])
                   for c in built['candidates']]
        matched = MATCH.match_candidates([e['episode_id'] for e in eps],
                                         [p['alert_id'] for p in preds], triples)
        matched_eps = {pair[0] for pair in matched['pairs']}
        campaigns = {}
        for e in eps:
            campaigns.setdefault(e['campaign_id'], []).append(e)
        for cid, members in campaigns.items():
            if fam in ATTACK_SELECTION and members[0]['intent'] == 'attack':
                out['campaigns_total'] += 1
                if any(m['episode_id'] in matched_eps for m in members):
                    out['campaigns_matched'] += 1
    return out


def main(argv=None):
    prefix = Path(argv[1]).resolve()
    sources = Path(argv[2]).resolve()
    corpus = Path(argv[3] if len(argv) > 3 else '/downloads/portscan-v2-execution/dev-corpus')
    if not (corpus / 'manifest.json').exists():
        SEL.generate(corpus)
    engines = {'zeek-8.0.11+bro-simple-scan(35cf19cf)+bro-is-darknet(7564a8f2) defaults': 'zeek',
               'snort-3.13.2.0 port_scan inspector defaults': 'snort'}
    report = {'split': 'development', 'seeds': '0..9',
              'purpose': 'baseline comparison at pinned default configs; never tuned to W/T',
              'binary_sha256': {'zeek': sha256(prefix / 'opt/zeek/bin/zeek'),
                                'snort': sha256(prefix / 'bin/snort')},
              'burden_window_s': BURDEN_WINDOW_S, 'engines': {}}
    for label, kind in engines.items():
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
                    workdir = Path(td)
                    try:
                        if kind == 'zeek':
                            preds = zeek_predictions(prefix, sources, pcap, cid, workdir)
                        else:
                            preds = snort_predictions(prefix, pcap, cid, workdir)
                    except Exception as exc:
                        per_engine['failed_traces'].append('%s: %s' % (cid, exc))
                        continue
                fam_alerts += len(preds)
                s = score(fam, labels, preds, str(pcap))
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
    dest = ROOT / 'research/v2/results/raw/dev-baselines-2026-11-22.json'
    dest.write_text(json.dumps(report, sort_keys=True, indent=1))
    print('wrote', dest)
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
