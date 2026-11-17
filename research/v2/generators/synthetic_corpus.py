#!/usr/bin/env python3
"""v2 synthetic corpus generator, implementing synthetic-corpus-spec-v0.1.md.

Deterministic: every draw comes from random.Random(sub) with
sub = int.from_bytes(sha256(b"v2-synth-corpus-v0.1|<family>|<seed>").digest()[:8], "big").
Regenerating a trace from the same spec version and seed reproduces identical
pcap bytes and identical label JSON. No wall clock, no os.urandom.

Uniform draws are integer nanoseconds / integer counts over the spec ranges.
This file generates traces; it is not a result and contains no measurements.
"""
import argparse, hashlib, json, random, struct, sys
from pathlib import Path

GENERATOR_VERSION = "v2-synth-corpus-v0.1"
SPEC_VERSION = "synthetic-corpus-spec-v0.1"
SUBSEED_PREFIX = b"v2-synth-corpus-v0.1"

FAMILIES = [
    'fast-vertical-syn', 'threshold-edge-syn', 'slow-syn', 'horizontal-syn',
    'fin', 'null', 'xmas', 'repeated-vertical-bursts',
    'repeated-horizontal-bursts', 'mixed-families', 'distributed-syn', 'udp',
    'normal-sessions', 'few-port-retries', 'approved-admin-scan',
    'nat-shared-source', 'service-discovery', 'fin-ack-teardown',
]
ATTACK = set(FAMILIES[:12])
BENIGN = set(FAMILIES[12:])
STRESS = {'slow-syn', 'distributed-syn', 'udp'}

PORT_POOL = list(range(1, 1025)) + [1433, 1521, 2049, 2375, 3000, 3306, 3389,
    4444, 5432, 5900, 6379, 8000, 8080, 8443, 9000, 9200, 27017]

def ipb(s):
    return bytes(int(x) for x in s.split('.'))

SCANNER_NET = [ipb('192.0.2.%d' % i) for i in range(2, 62)]
TARGET_NET  = [ipb('198.51.100.%d' % i) for i in range(2, 62)]
BG_NET      = [ipb('203.0.113.%d' % i) for i in range(2, 62)]
ADMIN_SRC   = ipb('192.0.2.10')
NAT_SRC     = ipb('192.0.2.20')
NAT_TARGET  = ipb('198.51.100.20')

def csum(data):
    if len(data) % 2: data += b'\x00'
    s = sum(struct.unpack('!%dH' % (len(data)//2), data))
    s = (s >> 16) + (s & 0xffff); s += s >> 16
    return (~s) & 0xffff

def ipv4(src, dst, proto, payload):
    hdr = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20+len(payload), 0, 0, 64, proto, 0, src, dst)
    return struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20+len(payload), 0, 0, 64, proto, csum(hdr), src, dst) + payload

def tcp_seg(sport, dport, flags, seq=0, ackno=0, payload=b''):
    hdr = struct.pack('!HHLLBBHHH', sport, dport, seq, ackno, 0x50, flags, 65535, 0, 0)
    return hdr + payload

def udp_seg(sport, dport, payload=b''):
    return struct.pack('!HHHH', sport, dport, 8+len(payload), 0) + payload

def eth(payload, kind=0x0800):
    return b'\xaa\xbb\xcc\xdd\xee\xff' + b'\x11\x22\x33\x44\x55\x66' + struct.pack('!H', kind) + payload

def _fixsum(src, dst, proto, payload):
    if proto == 6:
        payload = payload[:16] + b'\0\0' + payload[18:]
    elif proto == 17:
        payload = payload[:6] + b'\0\0' + payload[8:]
    pseudo = src + dst + struct.pack('!BBH', 0, proto, len(payload))
    check = csum(pseudo + payload) or 0xffff
    if proto == 6:
        return payload[:16] + struct.pack('!H', check) + payload[18:]
    return payload[:6] + struct.pack('!H', check) + payload[8:]

def tcp_frame(src, dst, sport, dport, flags, seq=0, ackno=0, payload=b''):
    return eth(ipv4(src, dst, 6, _fixsum(src, dst, 6, tcp_seg(sport, dport, flags, seq, ackno, payload))))

def udp_frame(src, dst, sport, dport, payload=b''):
    return eth(ipv4(src, dst, 17, _fixsum(src, dst, 17, udp_seg(sport, dport, payload))))

SYN, SYNACK, ACK, FINACK, RSTACK = 0x02, 0x12, 0x10, 0x11, 0x14
FIN_ONLY, NULL_F, XMAS = 0x01, 0x00, 0x29

def write_pcap(path, timed_frames_ns):
    """timed_frames_ns: list of (t_ns_absolute, frame). Microsecond pcap, linktype 1."""
    timed_frames_ns = sorted(timed_frames_ns, key=lambda x: x[0])
    out = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    for tns, frame in timed_frames_ns:
        sec, usec = tns // 1_000_000_000, (tns % 1_000_000_000) // 1000
        out += struct.pack('<IIII', sec, usec, len(frame), len(frame)) + frame
    Path(path).write_bytes(out)

# --- session / probe builders -------------------------------------------------
def session(t0, src, dst, sport, dport, rng, fin_teardown=True):
    """Complete connection: handshake, 0..8 data segments each way, teardown."""
    ev = [(t0, tcp_frame(src, dst, sport, dport, SYN, 100, 0))]
    t = t0 + rng.randint(1_000_000, 5_000_000)
    ev.append((t, tcp_frame(dst, src, dport, sport, SYNACK, 200, 101)))
    t += rng.randint(1_000_000, 5_000_000)
    ev.append((t, tcp_frame(src, dst, sport, dport, ACK, 101, 201)))
    sseq, dseq = 101, 201
    for _ in range(rng.randint(0, 8)):
        for (a, b, ap, bp, s, o) in ((src, dst, sport, dport, 's', 0), (dst, src, dport, sport, 'd', 0)):
            t += rng.randint(1_000_000, 20_000_000)
            pay = bytes(rng.randint(0, 255) for _ in range(rng.randint(1, 64)))
            if s == 's':
                ev.append((t, tcp_frame(a, b, ap, bp, 0x18, sseq, dseq, pay))); sseq += len(pay)
            else:
                ev.append((t, tcp_frame(a, b, ap, bp, 0x18, dseq, sseq, pay))); dseq += len(pay)
    t += rng.randint(1_000_000, 10_000_000)
    if fin_teardown:
        ev.append((t, tcp_frame(src, dst, sport, dport, FINACK, sseq, dseq)))
        t += rng.randint(1_000_000, 5_000_000)
        ev.append((t, tcp_frame(dst, src, dport, sport, FINACK, dseq, sseq + 1)))
        t += rng.randint(1_000_000, 5_000_000)
        ev.append((t, tcp_frame(src, dst, sport, dport, ACK, sseq + 1, dseq + 1)))
    else:
        ev.append((t, tcp_frame(src, dst, sport, dport, RSTACK, sseq, dseq)))
    return ev

def closed_probe(t, src, dst, sport, dport):
    """Unanswered SYN to a closed port: SYN (ACK clear) + RST/ACK reply."""
    return [(t, tcp_frame(src, dst, sport, dport, SYN, 0, 0)),
            (t + 1_000_000, tcp_frame(dst, src, dport, sport, RSTACK, 0, 1))]

def raw_probe(t, src, dst, sport, dport, flags):
    return [(t, tcp_frame(src, dst, sport, dport, flags, 0, 0))]

def jitter(rng):
    return rng.randint(-2_000_000, 2_000_000)

def background(rng, base_ns, dur_ns, forbidden):
    """B in 5..20 complete sessions from TEST-NET-3, never touching forbidden addrs."""
    ev = []
    for _ in range(rng.randint(5, 20)):
        while True:
            h1, h2 = rng.choice(BG_NET), rng.choice(BG_NET)
            if h1 != h2 and h1 not in forbidden and h2 not in forbidden:
                break
        t0 = base_ns + rng.randint(0, max(1, int(dur_ns) - 60_000_000_000))
        ev += session(t0, h1, h2, rng.randint(20000, 60000), rng.choice([80, 443, 22, 8080]), rng)
    return ev

# --- family builders: return (events, episodes, extras) -----------------------
def build(fam, seed):
    idx = FAMILIES.index(fam)
    sub = int.from_bytes(hashlib.sha256(SUBSEED_PREFIX + b'|' + fam.encode() + b'|' + str(seed).encode()).digest()[:8], 'big')
    rng = random.Random(sub)
    base_s = 1700000000 + (seed * 18 + idx) * 86400
    base_ns = base_s * 1_000_000_000
    cid = '%s-s%d' % (fam, seed)
    ev, episodes = [], []

    def ep(eid, intent, technique, scanner, first, last, target=None, tport=None, targets=None,
           scope=None, qualifier=None, campaign=None):
        e = {'episode_id': eid, 'campaign_id': campaign or eid, 'intent': intent,
             'family': fam, 'scanner': '.'.join(map(str, scanner)),
             'first_probe_ns': first, 'last_probe_ns': last,
             'technique': technique,
             'provenance': {'generator': GENERATOR_VERSION, 'spec': SPEC_VERSION,
                            'seed': seed, 'sub_seed_hex': '%016x' % sub}}
        if target is not None: e['target'] = '.'.join(map(str, target))
        if tport is not None: e['target_port'] = tport
        if targets is not None: e['targets'] = ['.'.join(map(str, t)) for t in targets]
        if scope: e['scope'] = scope
        if qualifier: e['qualifier'] = qualifier
        episodes.append(e)

    scan, tgt = SCANNER_NET[2 + (seed % 20)], TARGET_NET[2 + (seed % 20)]

    if fam in ('fast-vertical-syn', 'fin', 'null', 'xmas', 'threshold-edge-syn', 'slow-syn'):
        flags = {'fast-vertical-syn': SYN, 'fin': FIN_ONLY, 'null': NULL_F,
                 'xmas': XMAS, 'threshold-edge-syn': SYN, 'slow-syn': SYN}[fam]
        if fam == 'threshold-edge-syn':
            variant = seed % 4
            n_ports, gap = {0: (20, 500_000_000), 1: (20, 550_000_000),
                            2: (5, 70_000_000_000), 3: (5, 80_000_000_000)}[variant]
        elif fam == 'slow-syn':
            n_ports = rng.randint(15, 25); gap = None
        else:
            n_ports = rng.randint(60, 120); gap = None
        ports = rng.sample(PORT_POOL, n_ports)
        t = base_ns + 1_000_000_000
        first = last = None
        for p in ports:
            ev += raw_probe(t + (jitter(rng) if fam not in ('slow-syn',) else 0), scan, tgt, rng.randint(20000, 60000), p, flags)
            if first is None: first = t
            last = t
            if fam == 'fast-vertical-syn' or fam in ('fin', 'null', 'xmas'):
                t += rng.randint(10_000_000, 50_000_000)
            elif fam == 'slow-syn':
                t += rng.randint(120_000_000_000, 240_000_000_000)
            else:
                t += gap
        scope = 'out-of-scope-stress' if fam in STRESS else None
        ep(cid + '-e0', 'attack', {'fast-vertical-syn': 'syn', 'fin': 'fin', 'null': 'null',
           'xmas': 'xmas', 'threshold-edge-syn': 'syn', 'slow-syn': 'syn'}[fam],
           scan, first, last, target=tgt, scope=scope)
        span = last - base_ns
    elif fam == 'horizontal-syn':
        H = rng.choice([8, 16, 24])
        hosts = rng.sample(TARGET_NET, H)
        port = rng.choice(PORT_POOL)
        t = base_ns + 1_000_000_000; first = last = None
        for h in hosts:
            ev += raw_probe(t + jitter(rng), scan, h, rng.randint(20000, 60000), port, SYN)
            if first is None: first = t
            last = t
            t += rng.randint(20_000_000, 100_000_000)
        ep(cid + '-e0', 'attack', 'syn-horizontal', scan, first, last, tport=port, targets=hosts)
        span = last - base_ns
    elif fam in ('repeated-vertical-bursts', 'repeated-horizontal-bursts'):
        vertical = fam == 'repeated-vertical-bursts'
        n_bursts = rng.randint(3, 5)
        port = rng.choice(PORT_POOL)
        t = base_ns + 1_000_000_000
        for b in range(n_bursts):
            n = rng.randint(25, 40) if vertical else rng.randint(8, 16)
            first = last = None
            if vertical:
                ports = rng.sample(PORT_POOL, n)
                for p in ports:
                    ev += raw_probe(t + jitter(rng), scan, tgt, rng.randint(20000, 60000), p, SYN)
                    if first is None: first = t
                    last = t
                    t += rng.randint(20_000_000, 100_000_000)
                ep('%s-e%d' % (cid, b), 'attack', 'syn', scan, first, last, target=tgt, campaign=cid + '-c0')
            else:
                hosts = rng.sample(TARGET_NET, n)
                for h in hosts:
                    ev += raw_probe(t + jitter(rng), scan, h, rng.randint(20000, 60000), port, SYN)
                    if first is None: first = t
                    last = t
                    t += rng.randint(20_000_000, 100_000_000)
                ep('%s-e%d' % (cid, b), 'attack', 'syn-horizontal', scan, first, last, tport=port,
                   targets=hosts, campaign=cid + '-c0')
            t += rng.randint(400_000_000_000, 500_000_000_000)
        span = last - base_ns
    elif fam == 'mixed-families':
        n = rng.randint(30, 50)
        ports = rng.sample(PORT_POOL, n)
        kinds = [SYN] * (n // 2) + [FIN_ONLY] * (n - n // 2)
        rng.shuffle(kinds)
        t = base_ns + 1_000_000_000; first = last = None
        for k, p in zip(kinds, ports):
            ev += raw_probe(t + jitter(rng), scan, tgt, rng.randint(20000, 60000), p, k)
            if first is None: first = t
            last = t
            t += rng.randint(10_000_000, 50_000_000)
        ep(cid + '-e0', 'ambiguous', 'mixed-syn-fin', scan, first, last, target=tgt)
        span = last - base_ns
    elif fam == 'distributed-syn':
        K = rng.randint(8, 16)
        scanners = rng.sample(SCANNER_NET, K)
        target = TARGET_NET[30]
        span = 0
        for k, sc in enumerate(scanners):
            ports = rng.sample(PORT_POOL, rng.randint(3, 4))
            t = base_ns + 1_000_000_000 + rng.randint(0, 5_000_000_000)
            first = last = None
            for p in ports:
                ev += raw_probe(t + jitter(rng), sc, target, rng.randint(20000, 60000), p, SYN)
                if first is None: first = t
                last = t
                t += rng.randint(500_000_000, 2_000_000_000)
            ep('%s-e%d' % (cid, k), 'attack', 'syn', sc, first, last, target=target,
               scope='out-of-scope-stress', campaign=cid + '-c0')
            span = max(span, last - base_ns)
    elif fam == 'udp':
        n = rng.randint(40, 80)
        ports = rng.sample(PORT_POOL, n)
        t = base_ns + 1_000_000_000; first = last = None
        for p in ports:
            ev.append((t + jitter(rng), udp_frame(scan, tgt, rng.randint(20000, 60000), p)))
            if first is None: first = t
            last = t
            t += rng.randint(10_000_000, 50_000_000)
        ep(cid + '-e0', 'attack', 'udp', scan, first, last, target=tgt, scope='out-of-scope-stress')
        span = last - base_ns
    elif fam == 'normal-sessions':
        dur_ns = 3600 * 1_000_000_000
        n = rng.randint(40, 120)
        starts = sorted(rng.randint(0, dur_ns - 60_000_000_000) for _ in range(n))
        for st in starts:
            h1, h2 = rng.choice(BG_NET), rng.choice(BG_NET)
            while h1 == h2: h2 = rng.choice(BG_NET)
            ev += session(base_ns + st, h1, h2, rng.randint(20000, 60000), rng.choice([80, 443, 22, 25, 8080]), rng)
    elif fam == 'few-port-retries':
        dur_ns = 3600 * 1_000_000_000
        ports = rng.sample(PORT_POOL, rng.randint(2, 3))
        t = base_ns + rng.randint(1_000_000_000, 600_000_000_000)
        for p in ports:
            for _ in range(rng.randint(2, 4)):
                ev += closed_probe(t, scan, tgt, rng.randint(20000, 60000), p)
                t += rng.randint(1_000_000_000, 10_000_000_000)
        ev += background(rng, base_ns, dur_ns, {scan, tgt})
    elif fam == 'approved-admin-scan':
        dur_ns = 3600 * 1_000_000_000
        ports = rng.sample(PORT_POOL, rng.randint(30, 60))
        t = base_ns + rng.randint(1_000_000_000, 600_000_000_000)
        first = last = None
        for p in ports:
            ev += closed_probe(t, ADMIN_SRC, tgt, rng.randint(20000, 60000), p)
            if first is None: first = t
            last = t
            t += rng.randint(50_000_000, 200_000_000)
        ep(cid + '-e0', 'benign', 'syn', ADMIN_SRC, first, last, target=tgt,
           qualifier='operational-control')
        ev += background(rng, base_ns, dur_ns, {ADMIN_SRC, tgt})
    elif fam == 'nat-shared-source':
        dur_ns = 3600 * 1_000_000_000
        clients = rng.randint(8, 20)
        for _ in range(clients):
            for _ in range(rng.randint(1, 4)):
                h = rng.choice(BG_NET)
                t0 = base_ns + rng.randint(0, dur_ns - 60_000_000_000)
                ev += session(t0, NAT_SRC, h, rng.randint(20000, 60000), rng.choice([80, 443, 25, 110, 993]), rng)
        shared = rng.randint(4, 8)
        first = last = None
        for _ in range(shared):
            for p in rng.sample(PORT_POOL, rng.randint(2, 5)):
                t = base_ns + rng.randint(0, dur_ns - 10_000_000_000)
                ev += closed_probe(t, NAT_SRC, NAT_TARGET, rng.randint(20000, 60000), p)
                if first is None: first = t
                last = t
        ep(cid + '-e0', 'benign', 'syn', NAT_SRC, first, last, target=NAT_TARGET,
           qualifier='shared-source')
    elif fam == 'service-discovery':
        dur_ns = 3600 * 1_000_000_000
        block = [ipb('203.0.113.%d' % (33 + i)) for i in range(30)]
        hosts = rng.sample(block, rng.randint(6, 12))
        plan = [(h, p) for h in hosts for p in (22, 80, 443, 8080)]
        rng.shuffle(plan)
        t = base_ns + rng.randint(1_000_000_000, 60_000_000_000)
        first = last = None
        for h, p in plan:
            ev += closed_probe(t, scan, h, rng.randint(20000, 60000), p)
            if first is None: first = t
            last = t
            t += rng.randint(30_000_000_000, 90_000_000_000)
    elif fam == 'fin-ack-teardown':
        dur_ns = 3600 * 1_000_000_000
        n = rng.randint(20, 40)
        starts = sorted(rng.randint(0, dur_ns - 60_000_000_000) for _ in range(n))
        for st in starts:
            h1, h2 = rng.choice(BG_NET), rng.choice(BG_NET)
            while h1 == h2: h2 = rng.choice(BG_NET)
            ev += session(base_ns + st, h1, h2, rng.randint(20000, 60000), rng.choice([80, 443, 5432]), rng,
                          fin_teardown=rng.random() < 0.7)
        for _ in range(rng.randint(2, 5)):
            t = base_ns + rng.randint(0, dur_ns - 1_000_000_000)
            h1, h2 = rng.choice(BG_NET), rng.choice(BG_NET)
            ev.append((t, tcp_frame(h1, h2, rng.randint(20000, 60000), 443, FINACK, 500, 700)))
    else:
        raise ValueError(fam)

    if fam in ATTACK:
        dur_ns = span + 600 * 1_000_000_000
        ev += background(rng, base_ns, dur_ns, {scan, tgt})
        dur_s = dur_ns // 1_000_000_000
    else:
        dur_s = 3600

    labels = {'capture_id': cid, 'generator': GENERATOR_VERSION, 'spec_version': SPEC_VERSION,
              'seed': seed, 'family': fam, 'family_index': idx, 'epoch_base_s': base_s,
              'duration_s': dur_s, 'episodes': episodes,
              'split': 'development' if seed <= 9 else 'held-out'}
    if fam in BENIGN:
        labels['benign_units'] = [{'unit': fam, 'intent': 'benign', 'duration_s': 3600}]
    return ev, labels

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--out', required=True, help='output directory (must exist)')
    ap.add_argument('--family', choices=FAMILIES + ['all'], default='all')
    ap.add_argument('--seeds', default='0-29', help='e.g. 0-9 or 0,3,5')
    args = ap.parse_args()
    out = Path(args.out)
    if not out.is_dir():
        ap.error('--out directory must already exist')
    if '-' in args.seeds:
        a, b = args.seeds.split('-'); seeds = list(range(int(a), int(b) + 1))
    else:
        seeds = [int(x) for x in args.seeds.split(',')]
    fams = FAMILIES if args.family == 'all' else [args.family]
    manifest = {'generator': GENERATOR_VERSION, 'spec_version': SPEC_VERSION, 'files': {}}
    for fam in fams:
        for seed in seeds:
            ev, labels = build(fam, seed)
            cid = labels['capture_id']
            pcap_path = out / (cid + '.pcap')
            label_path = out / (cid + '.labels.json')
            for p in (pcap_path, label_path):
                if p.exists():
                    ap.error('refusing to overwrite existing file: %s' % p)
            write_pcap(pcap_path, ev)
            label_path.write_text(json.dumps(labels, indent=2, sort_keys=True) + '\n')
            for p in (pcap_path, label_path):
                manifest['files'][p.name] = hashlib.sha256(p.read_bytes()).hexdigest()
            print('%s: %d frames' % (cid, len(ev)), file=sys.stderr)
    mpath = out / 'manifest.json'
    if mpath.exists():
        ap.error('refusing to overwrite existing file: %s' % mpath)
    mpath.write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')

if __name__ == '__main__':
    main()
