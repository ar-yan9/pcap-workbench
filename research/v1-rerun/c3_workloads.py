#!/usr/bin/env python3
"""C3: ACK-only replication and one scan-heavy workload, frozen detector + evaluator.

Part 1 (ack_only_replication): the FAST-scan shape (1 source -> 50 distinct
ports in ~20 s) rendered three ways: SYN+ACK set, ACK only, and plain SYN
(control). The frozen rule keys on (syn and not ack), so the first two must
produce zero alerts and the control exactly one.

Part 2 (scan_heavy_workload): 40 distinct scanners x 200 ports each over 120 s,
interleaved with 800 benign web handshakes and 200 DNS queries (10,600
records). Ground-truth labels + events.json built alongside; the frozen
evaluator's 8-setting grid runs with per-setting wall time recorded.

Results -> results/c3_workloads.json. Honest numbers only.
"""
import importlib.util, json, struct, sys, time
from pathlib import Path

HERE = Path(__file__).resolve().parent

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

DETECTOR = load('frozen_detector', HERE / 'evaluated_workbench.py')
EVALUATOR = load('frozen_evaluator', HERE / 'evaluate.py')

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

def udp(sport, dport, payload=b'x'):
    return struct.pack('!HHHH', sport, dport, 8+len(payload), 0) + payload

def dns_query(name):
    q = struct.pack('!HHHHHH', 0x1234, 0x0100, 1, 0, 0, 0)
    for part in name.split('.'):
        q += bytes([len(part)]) + part.encode()
    return q + b'\x00' + struct.pack('!HH', 1, 1)

def eth(payload, kind=0x0800):
    return b'\xaa\xbb\xcc\xdd\xee\xff' + b'\x11\x22\x33\x44\x55\x66' + struct.pack('!H', kind) + payload

def transport_checksum(src, dst, proto, payload):
    offset = 16 if proto == 6 else 6
    payload = payload[:offset] + b'\0\0' + payload[offset+2:]
    pseudo = src + dst + struct.pack('!BBH', 0, proto, len(payload))
    check = csum(pseudo + payload) or 0xffff
    return payload[:offset] + struct.pack('!H', check) + payload[offset+2:]

BASE_NS = 1_774_300_000_000_000_000

def frame_v4(src, dst, proto, payload):
    return eth(ipv4(src, dst, proto, transport_checksum(src, dst, proto, payload)))

def write_pcap(path, timed_frames):
    timed_frames = sorted(timed_frames, key=lambda x: x[0])
    out = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    for tsec, frame, _label in timed_frames:
        ns = BASE_NS + int(round(tsec * 1e9))
        sec, usec = ns // 1_000_000_000, (ns % 1_000_000_000) // 1000
        out += struct.pack('<IIII', sec, usec, len(frame), len(frame)) + frame
    Path(path).write_bytes(out)
    return timed_frames

def labels_path(pcap_path):
    return str(pcap_path)[:-5] + '.labels'

def write_labels(pcap_path, timed_frames):
    with open(labels_path(pcap_path), 'w', newline='') as f:
        for n, (_t, _fr, label) in enumerate(timed_frames, 1):
            f.write('%d\t%s\n' % (n, label))

def write_events(pcap_path, units):
    Path(labels_path(pcap_path) + '.events.json').write_bytes(
        (json.dumps(units, indent=2) + '\n').encode())

TARGET = bytes([198, 51, 100, 9])
CLIENT = bytes([203, 0, 113, 20])

def fast_scan_frames(flags_syn, flags_ack, ports=50, span=20.0):
    src = bytes([192, 0, 2, 77])
    frames = []
    for i in range(ports):
        t = 1.0 + i * (span / ports)
        frames.append((t, frame_v4(src, TARGET, 6, tcp(40000+i, 1000+i, syn=flags_syn, ack=flags_ack)), 'FAST'))
    return frames

def detector_alert_count(pcap, w=60, p=10):
    return len(DETECTOR.investigate(str(pcap), w, p)['alerts'])

def part1(outdir):
    cases = [
        ('ack_syn_scan_shape', dict(syn=True, ack=True), 0,
         'SYN+ACK set on every probe: rule requires syn and not ack'),
        ('ack_only_scan_shape', dict(syn=False, ack=True), 0,
         'pure ACK probes: never enter the SYN queue'),
        ('syn_control_scan_shape', dict(syn=True, ack=False), 1,
         'plain SYN control: identical shape must alert once'),
    ]
    rows = []
    for name, flags, want, note in cases:
        pcap = outdir / (name + '.pcap')
        frames = fast_scan_frames(flags['syn'], flags['ack'])
        write_pcap(pcap, frames)
        got = detector_alert_count(pcap)
        rows.append(dict(unit=name, records=len(frames), note=note,
                         expected_alerts=want, actual_alerts=got,
                         verdict='PASS' if got == want else 'FAIL'))
    return rows

def part2(outdir):
    frames = []
    # 40 scanners x 200 distinct ports over 120 s
    scanner_packets = {}
    for i in range(40):
        src = bytes([192, 0, 2, 11 + i])
        base = (i * 137) % 60000
        my = []
        for j in range(200):
            dport = 1 + (base + j) % 64000
            t = 2.0 + i * 0.5 + j * 0.6
            fr = frame_v4(src, TARGET, 6, tcp(41000 + j, dport, syn=True, ack=False))
            frames.append((t, fr, 'SCANNER_%02d' % i))
        my.append(None)  # placeholder; packet numbers assigned after sort
    # 800 benign handshakes (SYN, SYN+ACK, ACK) to 80/443
    for k in range(800):
        t = 1.0 + k * 0.15
        sport = 50000 + (k % 10000)
        dport = 80 if k % 2 == 0 else 443
        frames.append((t, frame_v4(CLIENT, TARGET, 6, tcp(sport, dport, syn=True, ack=False)), 'NORMAL'))
        frames.append((t + 0.02, frame_v4(TARGET, CLIENT, 6, tcp(dport, sport, syn=True, ack=True)), 'NORMAL'))
        frames.append((t + 0.04, frame_v4(CLIENT, TARGET, 6, tcp(sport, dport, syn=False, ack=True)), 'NORMAL'))
    # 200 DNS queries
    for k in range(200):
        t = 1.5 + k * 0.6
        frames.append((t, frame_v4(CLIENT, TARGET, 17, udp(53000 + k, 53, dns_query('host%d.example' % k))), 'NORMAL'))

    frames.sort(key=lambda x: x[0])
    pcap = outdir / 'scan_heavy_workload.pcap'
    write_pcap(pcap, frames)
    write_labels(pcap, frames)

    # ground truth units with real packet numbers (post-sort)
    units = []
    by_scanner = {}
    normal_nums = []
    for n, (t, _fr, label) in enumerate(frames, 1):
        ns = BASE_NS + int(round(t * 1e9))
        if label.startswith('SCANNER_'):
            by_scanner.setdefault(label, []).append((n, ns))
        else:
            normal_nums.append((n, ns))
    for sid, rows in sorted(by_scanner.items()):
        units.append(dict(id=sid, attack=True,
                          packet_numbers=[n for n, _ in rows],
                          start_ns=min(t for _, t in rows), end_ns=max(t for _, t in rows)))
    units.append(dict(id='NORMAL', attack=False,
                      packet_numbers=[n for n, _ in normal_nums],
                      start_ns=min(t for _, t in normal_nums), end_ns=max(t for _, t in normal_nums)))
    write_events(pcap, units)

    # evaluator grid with per-setting wall time (same 8 settings as frozen study)
    packets, notices = DETECTOR.read_capture(str(pcap))
    assert not notices, notices
    decoded = {p['number']: DETECTOR.decode_packet(p)[0] for p in packets}
    grid = [(10, 10), (60, 10), (300, 10), (60, 5), (60, 15), (60, 20), (300, 5), (300, 20)]
    rows = []
    for w, p in grid:
        t0 = time.perf_counter()
        report = DETECTOR.investigate(str(pcap), w, p)
        dt = time.perf_counter() - t0
        m = EVALUATOR.match(report['alerts'], units, decoded, w, p)
        rows.append(dict(window=w, ports=p, alerts=len(report['alerts']),
                         wall_seconds=round(dt, 3),
                         precision=m['alert_precision'], recall=m['event_recall'],
                         unmatched_alerts=len(m['unmatched_alerts'])))
    return dict(records=len(frames), attack_units=40, benign_units=1,
                pcap_bytes=Path(pcap).stat().st_size, grid=rows)

def main():
    outdir = HERE / 'data' / 'c3-workloads'
    outdir.mkdir(parents=True, exist_ok=True)
    p1 = part1(outdir)
    p2 = part2(outdir)
    payload = dict(
        probe='C3 ACK-only replication + scan-heavy workload',
        detector='frozen revision-3 063ad1d (research/v1-rerun/evaluated_workbench.py)',
        evaluator='frozen 8-setting grid (research/v1-rerun/evaluate.py match())',
        ack_only_replication=p1,
        ack_only_passed=sum(1 for r in p1 if r['verdict'] == 'PASS'),
        scan_heavy_workload=p2)
    dest = HERE / 'results' / 'c3_workloads.json'
    dest.write_text(json.dumps(payload, indent=2, sort_keys=True) + '\n')
    print(json.dumps(p1, indent=1))
    print(json.dumps(p2, indent=1))
    fails = [r for r in p1 if r['verdict'] == 'FAIL']
    return 1 if fails else 0

if __name__ == '__main__':
    sys.exit(main())
