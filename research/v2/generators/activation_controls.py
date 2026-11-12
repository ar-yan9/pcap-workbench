#!/usr/bin/env python3
"""Write local Ethernet/IP/TCP activation controls. Sends no network traffic.

These deterministic fixtures are smoke controls, not research evaluation data.
The packet checksum is computed independently of any detector under test.
"""
import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import struct


def checksum(data):
    if len(data) % 2:
        data += b'\0'
    value = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    while value >> 16:
        value = (value & 65535) + (value >> 16)
    return (~value) & 65535


def packet(src, dst, sport, dport, seq, ack, flags, ident):
    sa, da = ipaddress.ip_address(src).packed, ipaddress.ip_address(dst).packed
    tcp = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, 0x50, flags, 64240, 0, 0)
    pseudo = sa + da + struct.pack('!BBH', 0, 6, len(tcp))
    tcp = tcp[:16] + struct.pack('!H', checksum(pseudo + tcp)) + tcp[18:]
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 40, ident & 65535, 0x4000, 64, 6, 0, sa, da)
    ip = ip[:10] + struct.pack('!H', checksum(ip)) + ip[12:]
    assert checksum(ip) == 0 and checksum(pseudo + tcp) == 0
    mac_a, mac_b = bytes.fromhex('020000000001'), bytes.fromhex('020000000002')
    if src == '192.0.2.1':
        return mac_b + mac_a + b'\x08\x00' + ip + tcp
    return mac_a + mac_b + b'\x08\x00' + ip + tcp


def write_pcap(path, records):
    # Refuse overwrites, including symlinks.
    with path.open('xb') as f:
        f.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for offset_us, raw in records:
            sec, usec = divmod(1700000000000000 + offset_us, 1000000)
            f.write(struct.pack('<IIII', sec, usec, len(raw), len(raw)))
            f.write(raw)
    return {'filename': path.name, 'packets': len(records), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}


def generate(out):
    out.mkdir(parents=True, exist_ok=True)
    a, b = '192.0.2.1', '198.51.100.2'
    positive = []
    for i in range(300):
        port, sport, seq, t = 1000 + i, 40000 + i, 10000 + i * 100, i * 100000
        positive.append((t, packet(a, b, sport, port, seq, 0, 0x02, 2*i)))
        positive.append((t+10000, packet(b, a, port, sport, 0, seq+1, 0x14, 2*i+1)))
    negative = []
    for i in range(10):
        sport, seq, srv, t = 50000+i, 20000+i*100, 90000+i*100, i*100000
        exchanges = [(a,b,sport,443,seq,0,0x02),
                     (b,a,443,sport,srv,seq+1,0x12),
                     (a,b,sport,443,seq+1,srv+1,0x10),
                     (a,b,sport,443,seq+1,srv+1,0x11),
                     (b,a,443,sport,srv+1,seq+2,0x11),
                     (a,b,sport,443,seq+2,srv+2,0x10)]
        for j,args in enumerate(exchanges):
            negative.append((t+j*1000,packet(*args,ident=i*6+j)))
    # Two refused connections, both to the same port, remain below scan thresholds.
    for i in range(2):
        t, sport, seq = 2000000+i*100000, 51000+i, 30000+i*100
        negative.extend([(t,packet(a,b,sport,22,seq,0,2,100+i*2)),
                         (t+10000,packet(b,a,22,sport,0,seq+1,0x14,101+i*2))])
    result = {'purpose': 'baseline activation only; not held-out research data',
              'linktype': 1, 'checksums': 'IPv4 and TCP independently asserted valid',
              'positive': write_pcap(out/'positive.pcap', positive),
              'negative': write_pcap(out/'negative.pcap', negative)}
    with (out/'manifest.json').open('x') as f:
        json.dump(result,f,indent=2); f.write('\n')
    return result


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output',type=Path)
    print(json.dumps(generate(parser.parse_args().output),indent=2))
