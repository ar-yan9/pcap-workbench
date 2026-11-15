#!/usr/bin/env python3
"""C2 boundary-condition units for the frozen v1 detector (revision-3, 063ad1d).

Micro-captures built with the v1.1 generator's exact frame helpers, run through
the frozen detector's investigate() at (window=60, ports=10). Each unit probes
a boundary of the detection rule:

  queue eviction: while queue and now - oldest > window*1e9  (strictly greater)
  alert:          distinct dports in queue >= ports, once per (src,dst) pair

Expectations are stated per unit and checked against real detector output.
Results (with PASS/FAIL) go to results/c2_boundary.json.
"""
import importlib.util, json, struct, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

DETECTOR = load('frozen_detector', HERE / 'evaluated_workbench.py')

# --- frame helpers: verbatim copies from generators/gen_capture_v1_1.py -------
def csum(data):
    if len(data) % 2: data += b'\x00'
    s = sum(struct.unpack('!%dH' % (len(data)//2), data))
    s = (s >> 16) + (s & 0xffff); s += s >> 16
    return (~s) & 0xffff

def ipv4(src, dst, proto, payload):
    hdr = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20+len(payload), 0, 0, 64, proto, 0, src, dst)
    return struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20+len(payload), 0, 0, 64, proto, csum(hdr), src, dst) + payload

def tcp(sport, dport, syn=True, ack=False):
    flags = (0x02 if syn else 0) | (0x10 if ack else 0)
    return struct.pack('!HHLLBBHHH', sport, dport, 0, 0, 0x50, flags, 65535, 0, 0)

def eth(payload, kind=0x0800):
    return b'\xaa\xbb\xcc\xdd\xee\xff' + b'\x11\x22\x33\x44\x55\x66' + struct.pack('!H', kind) + payload

def transport_checksum(src, dst, proto, payload):
    payload = payload[:16] + b'\0\0' + payload[18:]
    pseudo = src + dst + struct.pack('!BBH', 0, proto, len(payload))
    check = csum(pseudo + payload) or 0xffff
    return payload[:16] + struct.pack('!H', check) + payload[18:]

BASE_NS = 1_774_300_000_000_000_000
SCANNER = bytes([192, 0, 2, 77])     # RFC 5737 TEST-NET-1
TARGET  = bytes([198, 51, 100, 9])   # RFC 5737 TEST-NET-2
TARGET2 = bytes([198, 51, 100, 10])

def syn_frame(src, dst, dport, sport=40000):
    payload = transport_checksum(src, dst, 6, tcp(sport, dport, syn=True, ack=False))
    return eth(ipv4(src, dst, 6, payload))

def write_pcap(path, timed_frames):
    """timed_frames: list of (t_sec_float, frame). Microsecond-resolution pcap,
    same format as the v1/v1.1 fixtures."""
    timed_frames = sorted(timed_frames, key=lambda x: x[0])
    out = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    for tsec, frame in timed_frames:
        ns = BASE_NS + int(round(tsec * 1e9))
        sec, usec = ns // 1_000_000_000, (ns % 1_000_000_000) // 1000
        out += struct.pack('<IIII', sec, usec, len(frame), len(frame)) + frame
    Path(path).write_bytes(out)

# --- units --------------------------------------------------------------------
# Each unit: (name, frames, expected_alerts, expect_distinct_or_None, note)
UNITS = []
W, T = 60, 10

# 1: T-1 distinct ports inside window -> no alert
UNITS.append(('t_minus1_no_alert',
    [(float(i), syn_frame(SCANNER, TARGET, 10000+i)) for i in range(1, 10)],
    0, None, '9 distinct ports in 9 s < threshold 10'))

# 2: exactly T distinct ports -> one alert, 10 distinct
UNITS.append(('t_exact_alert',
    [(float(i), syn_frame(SCANNER, TARGET, 10000+i)) for i in range(1, 11)],
    1, 10, '10 distinct ports in 10 s == threshold 10'))

# 3: T+1 distinct ports -> still one alert (fires at the 10th, once per pair)
UNITS.append(('t_plus1_single_alert',
    [(float(i), syn_frame(SCANNER, TARGET, 10000+i)) for i in range(1, 12)],
    1, 10, '11 distinct ports; alert at the 10th; emitted-once semantics'))

# 4: W edge inclusive: span exactly 60.000000 s -> oldest stays, alert
UNITS.append(('w_edge_inclusive_alert',
    [(0.0, syn_frame(SCANNER, TARGET, 10000))]
    + [(float(i), syn_frame(SCANNER, TARGET, 10000+i)) for i in range(1, 9)]
    + [(60.0, syn_frame(SCANNER, TARGET, 10009))],
    1, 10, 'span exactly window=60 s: now-oldest == W is NOT evicted (rule is > W)'))

# 5: W edge exclusive: span 60.000001 s -> oldest evicted, no alert
UNITS.append(('w_edge_exclusive_no_alert',
    [(0.0, syn_frame(SCANNER, TARGET, 10000))]
    + [(float(i), syn_frame(SCANNER, TARGET, 10000+i)) for i in range(1, 9)]
    + [(60.000001, syn_frame(SCANNER, TARGET, 10009))],
    0, None, 'span 60 s + 1 us: now-oldest > W evicts the oldest -> 9 distinct'))

# 6: window slide, boundary stays: 9 ports at t=1..9, 10th at t=60.5 (oldest 59.5 s old)
UNITS.append(('w_slide_stay_alert',
    [(float(i), syn_frame(SCANNER, TARGET, 10000+i)) for i in range(1, 10)]
    + [(60.5, syn_frame(SCANNER, TARGET, 10099))],
    1, 10, 'oldest 59.5 s old at decision time -> still inside window'))

# 7: window slide, boundary evicts: 10th at t=61.5 (oldest 60.5 s old)
UNITS.append(('w_slide_evict_no_alert',
    [(float(i), syn_frame(SCANNER, TARGET, 10000+i)) for i in range(1, 10)]
    + [(61.5, syn_frame(SCANNER, TARGET, 10099))],
    0, None, 'oldest 60.5 s old at decision time -> evicted -> 9 distinct'))

# 8: same-port repetition never reaches distinct threshold
UNITS.append(('same_port_repeat_no_alert',
    [(float(i), syn_frame(SCANNER, TARGET, 22)) for i in range(1, 26)],
    0, None, '25 SYNs to one port in 25 s: distinct ports = 1'))

# 9: per-pair isolation: 10 ports on target A, 9 on target B -> one alert (A only)
UNITS.append(('per_pair_isolation',
    [(float(i), syn_frame(SCANNER, TARGET, 10000+i)) for i in range(1, 11)]
    + [(float(i), syn_frame(SCANNER, TARGET2, 20000+i)) for i in range(1, 10)],
    1, 10, '(src,dst) queues are independent; 9-port pair stays silent'))

# 10: after one alert, a second 10-port sweep on the same pair raises nothing new
UNITS.append(('emitted_once_no_realert',
    [(float(i), syn_frame(SCANNER, TARGET, 10000+i)) for i in range(1, 11)]
    + [(20.0+i, syn_frame(SCANNER, TARGET, 30000+i)) for i in range(1, 11)],
    1, 10, 'two full sweeps in one window; alert emitted once per pair'))

def main():
    outdir = HERE / 'data' / 'c2-boundary'
    outdir.mkdir(parents=True, exist_ok=True)
    results = []
    failures = 0
    for name, frames, want_alerts, want_distinct, note in UNITS:
        pcap = outdir / (name + '.pcap')
        write_pcap(pcap, frames)
        report = DETECTOR.investigate(str(pcap), W, T)
        got_alerts = len(report['alerts'])
        got_distinct = report['alerts'][0]['distinct_destination_ports'] if report['alerts'] else None
        ok = got_alerts == want_alerts and (want_distinct is None or got_distinct == want_distinct)
        if not ok:
            failures += 1
        results.append(dict(
            unit=name, records=len(frames), window=W, ports=T, note=note,
            expected_alerts=want_alerts, actual_alerts=got_alerts,
            expected_distinct=want_distinct, actual_distinct=got_distinct,
            detected_at=[a['detected_at'] for a in report['alerts']],
            skipped=dict(report['stats']['skipped_by_reason']),
            verdict='PASS' if ok else 'FAIL'))
    payload = dict(
        probe='C2 boundary units (T-1/T/T+1 threshold edge, W/W+1us window edge, slide, distinctness, per-pair, emitted-once)',
        detector='frozen revision-3 063ad1d (research/v1-rerun/evaluated_workbench.py)',
        units=len(results), passed=sum(1 for r in results if r['verdict'] == 'PASS'),
        failed=failures, results=results)
    dest = HERE / 'results' / 'c2_boundary.json'
    dest.write_text(json.dumps(payload, indent=2, sort_keys=True) + '\n')
    print(json.dumps({k: payload[k] for k in ('units', 'passed', 'failed')}))
    for r in results:
        print('%(verdict)s %(unit)s alerts=%(actual_alerts)d distinct=%(actual_distinct)s' % r)
    return 1 if failures else 0

if __name__ == '__main__':
    sys.exit(main())
