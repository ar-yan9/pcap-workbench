#!/usr/bin/env python3
"""Seeded classic-PCAP generator v1.1 with labeled ground truth for evaluation.

Lineage: verbatim copy of the frozen revision-3 generator (seed 20261027) with
exactly two marked changes:

1. [v1.1] The master seed comes from argv[3] (default 20261027). With no extra
   arguments this script reproduces the frozen fixture byte-exact; the v1-rerun
   regression test proves it against data/seed-20261027/.
2. [v1.1] An optional 'vary' mode (argv[4] == 'vary') perturbs the ATTACK and
   benign-lookalike scenarios, which the frozen generator builds
   deterministically: destination-port order and base offset, per-probe timing
   jitter (bounded fraction of nominal spacing), DIST source permutation, and
   the RETRY single port. Variation draws from an independent Random instance
   keyed ('v1.1-vary', seed), so the legacy random stream is untouched and
   legacy output is unchanged. Scenario families, packet counts, approximate
   spans, address ranges and label semantics are preserved.

Scenarios:
  NORMAL   office web traffic (80/443 handshakes, DNS queries)
  FAST     fast SYN scan: 1 source -> 50 distinct ports on 1 target in ~20 s
  SLOW     slow SYN scan: 12 distinct ports, one every 10 s (110 s span)
  DIST     distributed scan: 10 sources x 5 ports each on 1 target
  UDPSCAN  UDP probes to 20 distinct ports (no SYN flag at all)
  V6FAST   fast SYN scan over IPv6: 1 source -> 25 distinct ports in ~10 s
  ADMIN    benign admin health-check: 12 distinct ports in 30 s (not an attack)
  RETRY    benign retransmissions: 25 SYN retries to the SAME port
Everything is synthetic; documentation addresses only (RFC 5737 / RFC 3849).
"""
import struct, random, sys
from pathlib import Path

# [v1.1] seed and variation mode; defaults reproduce the frozen generator.
SEED = int(sys.argv[3]) if len(sys.argv) > 3 else 20261027
VARY = len(sys.argv) > 4 and sys.argv[4] == 'vary'

random.seed(SEED)
BASE_NS = 1_774_300_000_000_000_000  # fixed epoch-ish, reproducible
pkts = []   # (time_ns, ethernet_frame_bytes, label)

def csum(data):
    if len(data) % 2: data += b'\x00'
    s = sum(struct.unpack('!%dH' % (len(data)//2), data))
    s = (s >> 16) + (s & 0xffff); s += s >> 16
    return (~s) & 0xffff

def ipv4(src, dst, proto, payload):
    hdr = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20+len(payload), 0, 0, 64, proto, 0, src, dst)
    chk = csum(hdr)
    return struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20+len(payload), 0, 0, 64, proto, chk, src, dst) + payload

def ipv6(src, dst, nxt, payload):
    return struct.pack('!IHBB16s16s', 0x60000000, len(payload), nxt, 64, src, dst) + payload

def tcp(sport, dport, syn=True, ack=False, seq=0, payload=b''):
    flags = (0x02 if syn else 0) | (0x10 if ack else 0)
    hdr = struct.pack('!HHLLBBHHH', sport, dport, seq, 0, 0x50, flags, 65535, 0, 0)
    return hdr + payload

def udp(sport, dport, payload=b'x'):
    return struct.pack('!HHHH', sport, dport, 8+len(payload), 0) + payload

def dns_query(name):
    tid = 0x1234; flags = 0x0100
    q = struct.pack('!HHHHHH', tid, flags, 1, 0, 0, 0)
    for part in name.split('.'):
        q += bytes([len(part)]) + part.encode()
    return q + b'\x00' + struct.pack('!HH', 1, 1)

def eth(payload, kind):
    return b'\xaa\xbb\xcc\xdd\xee\xff' + b'\x11\x22\x33\x44\x55\x66' + struct.pack('!H', kind) + payload

def transport_checksum(src, dst, proto, payload, v6):
    offset = 16 if proto == 6 else 6
    payload = payload[:offset] + b'\0\0' + payload[offset+2:]
    pseudo = src + dst + (struct.pack('!I3xB', len(payload), proto) if v6 else struct.pack('!BBH', 0, proto, len(payload)))
    check = csum(pseudo + payload) or 0xffff
    return payload[:offset] + struct.pack('!H', check) + payload[offset+2:]

def add_v4(t_ns, src, dst, proto, payload, label):
    payload = transport_checksum(src, dst, proto, payload, False)
    frame = eth(ipv4(src, dst, proto, payload), 0x0800)
    pkts.append((t_ns, frame, label))

def add_v6(t_ns, src, dst, nxt, payload, label):
    payload = transport_checksum(src, dst, nxt, payload, True)
    frame = eth(ipv6(src, dst, nxt, payload), 0x86dd)
    pkts.append((t_ns, frame, label))

def ip4(a,b,c,d): return bytes([a,b,c,d])

T = 0
def t(sec): return BASE_NS + int(sec*1e9)

# [v1.1] Variation helpers. With VARY=False every helper returns the original
# deterministic value and consumes no randomness, so legacy output is
# byte-identical to the frozen generator. With VARY=True an independent stream
# perturbs port order/base and probe timing within family-preserving bounds.
# String seed: tuple/other types hash-seed nondeterministically across processes.
vrng = random.Random('v1.1-vary:%d' % SEED) if VARY else None
JITTER_FRAC = 0.2

def vary_ports(base, count):
    if not VARY:
        return [base + i for i in range(count)]
    offset = vrng.randint(0, 4000)
    order = list(range(count))
    vrng.shuffle(order)
    return [base + offset + j for j in order]

def vary_single_port(port):
    if not VARY:
        return port
    return vrng.randint(1, 10000)

def vary_gap(sec, nominal):
    if not VARY:
        return sec
    return sec + vrng.uniform(-JITTER_FRAC * nominal, JITTER_FRAC * nominal)

def vary_sources(start, count):
    if not VARY:
        return [start + i for i in range(count)]
    return vrng.sample(range(100, 200), count)

# ---- NORMAL: 40 clients, web browsing + DNS over a day slice (~2 hours) ----
clients = [ip4(203,0,113,random.randint(10,60)) for _ in range(40)]
websites = ['example%d.test' % i for i in range(15)]
for sec in range(0, 7200, 37):
    c = random.choice(clients)
    srv = ip4(198,51,100,random.choice([80,90,100]))
    add_v4(t(sec), c, srv, 17, udp(random.randint(40000,60000), 53, dns_query(random.choice(websites))), 'NORMAL')
    sp = random.randint(40000,60000)
    dp = random.choice([80,443])
    add_v4(t(sec+0.1), c, srv, 6, tcp(sp, dp), 'NORMAL')
    add_v4(t(sec+0.2), srv, c, 6, tcp(dp, sp, syn=True, ack=True), 'NORMAL')
    add_v4(t(sec+0.3), c, srv, 6, tcp(sp, dp, syn=False, ack=True, seq=1), 'NORMAL')

# ---- FAST scan: 192.0.2.66 -> 198.51.100.20, 50 ports in ~20 s ----
t0 = 8000
fast_ports = vary_ports(20, 50)
for i in range(50):
    add_v4(t(vary_gap(t0 + i*0.4, 0.4)), ip4(192,0,2,66), ip4(198,51,100,20), 6, tcp(44444, fast_ports[i]), 'FAST')

# ---- SLOW scan: 192.0.2.77 -> 198.51.100.20, 12 ports, 10 s apart ----
t0 = 9000
slow_ports = vary_ports(300, 12)
for i in range(12):
    add_v4(t(vary_gap(t0 + i*10, 10)), ip4(192,0,2,77), ip4(198,51,100,20), 6, tcp(55555, slow_ports[i]), 'SLOW')

# ---- DIST scan: 10 sources x 5 ports on 198.51.100.30 ----
t0 = 10000
dist_ports = vary_ports(500, 5)
dist_sources = vary_sources(100, 10)
for s in range(10):
    for p in range(5):
        add_v4(t(vary_gap(t0 + s*2 + p*0.3, 0.3)), ip4(192,0,2,dist_sources[s]), ip4(198,51,100,30), 6, tcp(40000+s, dist_ports[p]), 'DIST')

# ---- UDP scan: 192.0.2.88 -> 20 distinct UDP ports ----
t0 = 11000
udp_ports = vary_ports(1000, 20)
for i in range(20):
    add_v4(t(vary_gap(t0 + i*0.5, 0.5)), ip4(192,0,2,88), ip4(198,51,100,40), 17, udp(45678, udp_ports[i]), 'UDPSCAN')

# ---- V6FAST scan over IPv6: 25 ports in ~10 s ----
v6src = bytes.fromhex('20010db8000000000000000000000001')
v6dst = bytes.fromhex('20010db8000000000000000000000002')
t0 = 12000
v6_ports = vary_ports(2000, 25)
for i in range(25):
    add_v6(t(vary_gap(t0 + i*0.4, 0.4)), v6src, v6dst, 6, tcp(46666, v6_ports[i]), 'V6FAST')

# ---- ADMIN benign: monitoring host checks 12 ports in 30 s ----
t0 = 13000
admin_ports = vary_ports(7000, 12)
for i in range(12):
    add_v4(t(vary_gap(t0 + i*2.5, 2.5)), ip4(203,0,113,5), ip4(198,51,100,50), 6, tcp(38000, admin_ports[i]), 'ADMIN')
    add_v4(t(vary_gap(t0 + i*2.5 + 0.1, 2.5), ), ip4(198,51,100,50), ip4(203,0,113,5), 6, tcp(admin_ports[i], 38000, syn=True, ack=True), 'ADMIN')

# ---- RETRY benign: 25 SYN retransmissions to the SAME port 22 ----
t0 = 14000
retry_port = vary_single_port(22)
for i in range(25):
    add_v4(t(vary_gap(t0 + i*2, 2)), ip4(203,0,113,9), ip4(198,51,100,60), 6, tcp(39000, retry_port), 'RETRY')

pkts.sort(key=lambda x: x[0])
out, lab = sys.argv[1], sys.argv[2]
with open(out, 'wb') as f:
    f.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    n = 0
    with open(lab, 'w') as g:
        for tns, frame, label in pkts:
            n += 1
            sec = tns // 1_000_000_000
            usec = (tns % 1_000_000_000) // 1000
            f.write(struct.pack('<IIII', sec, usec, len(frame), len(frame)))
            f.write(frame)
            g.write(f'{n}\t{label}\n')
# Explicit finite evaluation episodes. NORMAL is one background control unit,
# not an estimate of the number of real-world negative opportunities.
import json
units = []
for name in ['NORMAL','FAST','SLOW','DIST','UDPSCAN','V6FAST','ADMIN','RETRY']:
    rows = [(i+1, x) for i,x in enumerate(pkts) if x[2] == name]
    units.append(dict(id=name, attack=name in {'FAST','SLOW','DIST','UDPSCAN','V6FAST'},
                      packet_numbers=[i for i,_ in rows],
                      start_ns=min(x[0] for _,x in rows), end_ns=max(x[0] for _,x in rows)))
Path(lab + '.events.json').write_text(json.dumps(units, indent=2) + '\n')
print(f'packets={n}')
