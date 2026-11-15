#!/usr/bin/env python3
"""C3 scale-up: RSS measurement + 100k-record scan-heavy workload + epoch-scale
window-edge rerun. Real runs only; results -> results/c3_scale_rss.json.

- RSS/wall per grid setting for the published 10,600-record workload and a new
  102,600-record workload (500 scanners x 200 ports + background), 5 reps each,
  each rep in a child process so peak RSS is per-run.
- The W-edge boundary pair (60.000000 s vs 60.000001 s) rebuilt at an epoch
  base of 1.8e9 s to answer the float-resolution question. (The detector's
  eviction arithmetic is integer nanoseconds; this run verifies behavior at
  epoch scale rather than assuming it.)
"""
import importlib.util, json, subprocess, sys, time
from pathlib import Path

HERE = Path(__file__).resolve().parent

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

C3 = load('c3', HERE / 'c3_workloads.py')
C2 = load('c2', HERE / 'c2_boundary.py')
GRID = [(10, 10), (60, 10), (300, 10), (60, 5), (60, 15), (60, 20), (300, 5), (300, 20)]

CHILD = r'''
import importlib.util, json, resource, sys, time
spec = importlib.util.spec_from_file_location('det', sys.argv[1])
d = importlib.util.module_from_spec(spec); spec.loader.exec_module(d)
t0 = time.perf_counter()
rep = d.investigate(sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), max_packets=int(sys.argv[5]))
dt = time.perf_counter() - t0
print(json.dumps({'wall': dt, 'alerts': len(rep['alerts']),
                  'maxrss_kib': resource.getrusage(resource.RUSAGE_SELF).ru_maxrss}))
'''

def timed_runs(pcap, w, p, max_packets, reps=5):
    walls, rss, alerts = [], [], None
    for _ in range(reps):
        out = subprocess.run([sys.executable, '-c', CHILD,
                              str(HERE / 'evaluated_workbench.py'), str(pcap), str(w), str(p), str(max_packets)],
                             check=True, capture_output=True, text=True).stdout
        r = json.loads(out)
        walls.append(r['wall']); rss.append(r['maxrss_kib']); alerts = r['alerts']
    walls.sort(); rss.sort()
    return dict(window=w, ports=p, alerts=alerts,
                wall_median_s=round(walls[len(walls)//2], 3),
                wall_min_s=round(walls[0], 3), wall_max_s=round(walls[-1], 3),
                peak_rss_median_mib=round(rss[len(rss)//2] / 1024, 1),
                peak_rss_max_mib=round(rss[-1] / 1024, 1))

def build_100k(outdir):
    frames = []
    nets = [192, 198, 203]
    for i in range(500):
        net = nets[min(i // 240, 2)]
        host = 11 + (i % 240)
        if net == 203: host = 21 + (i % 20)  # avoid 203.0.113.20 == CLIENT
        src = bytes([net, 0, 2, host]) if net == 192 else (bytes([198, 51, 100, host]) if net == 198 else bytes([203, 0, 113, host]))
        base = (i * 137) % 60000
        for j in range(200):
            dport = 1 + (base + j) % 64000
            t = 2.0 + i * 0.5 + j * 0.6
            frames.append((t, C3.frame_v4(src, C3.TARGET, 6, C3.tcp(41000 + j, dport, syn=True, ack=False)), 'SCANNER_%03d' % i))
    for k in range(800):
        t = 1.0 + k * 0.15
        sport = 50000 + (k % 10000)
        dport = 80 if k % 2 == 0 else 443
        frames.append((t, C3.frame_v4(C3.CLIENT, C3.TARGET, 6, C3.tcp(sport, dport, syn=True, ack=False)), 'NORMAL'))
        frames.append((t + 0.02, C3.frame_v4(C3.TARGET, C3.CLIENT, 6, C3.tcp(dport, sport, syn=True, ack=True)), 'NORMAL'))
        frames.append((t + 0.04, C3.frame_v4(C3.CLIENT, C3.TARGET, 6, C3.tcp(sport, dport, syn=False, ack=True)), 'NORMAL'))
    for k in range(200):
        t = 1.5 + k * 0.6
        frames.append((t, C3.frame_v4(C3.CLIENT, C3.TARGET, 17, C3.udp(53000 + k, 53, C3.dns_query('host%d.example' % k))), 'NORMAL'))
    frames.sort(key=lambda x: x[0])
    pcap = outdir / 'scan_heavy_100k.pcap'
    C3.write_pcap(pcap, frames)
    C3.write_labels(pcap, frames)
    units = []
    by_scanner = {}
    normal_nums = []
    for n, (t, _fr, label) in enumerate(frames, 1):
        ns = C3.BASE_NS + int(round(t * 1e9))
        (by_scanner.setdefault(label, []).append((n, ns)) if label.startswith('SCANNER_') else normal_nums.append((n, ns)))
    for sid, rows in sorted(by_scanner.items()):
        units.append(dict(id=sid, attack=True, packet_numbers=[n for n, _ in rows],
                          start_ns=min(t for _, t in rows), end_ns=max(t for _, t in rows)))
    units.append(dict(id='NORMAL', attack=False, packet_numbers=[n for n, _ in normal_nums],
                      start_ns=min(t for _, t in normal_nums), end_ns=max(t for _, t in normal_nums)))
    C3.write_events(pcap, units)
    return pcap, units, frames

def epoch_edge_pair():
    C2.BASE_NS = 1_800_000_000_000_000_000  # 1.8e9 s: binary64 ~0.24 us resolution if floats were used
    out = {}
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        for name, frames, want_alerts, want_distinct, note in C2.UNITS:
            if not name.startswith('w_edge'): continue
            pcap = Path(td) / (name + '.pcap')
            C2.write_pcap(pcap, frames)
            rep = C2.DETECTOR.investigate(str(pcap), C2.W, C2.T)
            got = len(rep['alerts'])
            out[name] = dict(expected_alerts=want_alerts, actual_alerts=got,
                             verdict='PASS' if got == want_alerts else 'FAIL',
                             base_seconds=1_800_000_000)
    return out

def main():
    outdir = HERE / 'data' / 'c3-workloads'
    pcap100, units100, frames100 = build_100k(outdir)
    print('100k workload records:', len(frames100), flush=True)
    result = dict(
        probe='C3 scale-up: RSS, 102,600-record workload, epoch-scale window edge',
        detector='frozen revision-3 063ad1d (research/v1-rerun/evaluated_workbench.py)',
        note='eviction arithmetic in evaluated_workbench.py is integer nanoseconds; the epoch pair verifies behavior, not assumptions',
        epoch_edge_pair=epoch_edge_pair(),
        workloads={})
    for tag, pcap, units, maxpk in (('scan_heavy_10k', HERE / 'data' / 'c3-workloads' / 'scan_heavy_workload.pcap', None, 100000),
                                    ('scan_heavy_100k', pcap100, units100, 200000)):
        rows = [timed_runs(pcap, w, p, maxpk) for w, p in GRID]
        result['workloads'][tag] = dict(records=102600 if tag.endswith('100k') else 10600,
                                        max_packets=maxpk, grid=rows)
        print(tag, 'done', flush=True)
    # precision/recall for the 100k workload via the frozen evaluator
    EVAL = load('ev', HERE / 'evaluate.py')
    DET = C2.DETECTOR
    packets, notices = DET.read_capture(str(pcap100))
    decoded = {p['number']: DET.decode_packet(p)[0] for p in packets}
    matchrows = []
    for w, p in GRID:
        rep = DET.investigate(str(pcap100), w, p, max_packets=200000)
        m = EVAL.match(rep['alerts'], units100, decoded, w, p)
        matchrows.append(dict(window=w, ports=p, alerts=len(rep['alerts']),
                              precision=m['alert_precision'], recall=m['event_recall'],
                              unmatched_alerts=len(m['unmatched_alerts'])))
    result['workloads']['scan_heavy_100k']['evaluator_grid'] = matchrows
    dest = HERE / 'results' / 'c3_scale_rss.json'
    dest.write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    print(json.dumps(result['epoch_edge_pair'], indent=1))

if __name__ == '__main__':
    sys.exit(main())
