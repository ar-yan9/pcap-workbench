#!/usr/bin/env python3
"""Offline classic-PCAP/PCAPNG investigation. No sniffing, network calls or payload export."""
import argparse
from collections import Counter, defaultdict, deque
from datetime import datetime, timezone
import hashlib
import hmac
import ipaddress
import json
from pathlib import Path
import secrets
import struct
import sys

MAGIC = {b'\xd4\xc3\xb2\xa1': ('<', 1000000), b'\xa1\xb2\xc3\xd4': ('>', 1000000),
         b'\x4d\x3c\xb2\xa1': ('<', 1000000000), b'\xa1\xb2\x3c\x4d': ('>', 1000000000)}
PCAPNG_MAGIC = b'\x0a\x0d\x0d\x0a'
PCAPNG_ORDERS = {b'\x4d\x3c\x2b\x1a': '<', b'\x1a\x2b\x3c\x4d': '>'}
PCAPNG_MAX_BLOCK = 16*1024*1024 + 4096


def read_capture(path, max_packets=100000, max_bytes=64*1024*1024):
    """Bounded classic PCAP / first-section PCAPNG reader; record numbers are the evidence references."""
    with Path(path).open('rb') as stream:
        magic = stream.read(4)
        if magic in MAGIC:
            return _read_classic(stream, magic, max_packets, max_bytes)
        if magic == PCAPNG_MAGIC:
            return _read_pcapng(stream, max_packets, max_bytes)
    raise ValueError('Expected classic PCAP or PCAPNG, not another format')


def _read_classic(stream, magic, max_packets, max_bytes):
    packets, notices = [], []
    header = stream.read(20)
    if len(header) != 20:
        raise ValueError('Expected classic PCAP or PCAPNG, not another format')
    order, resolution = MAGIC[magic]
    major, minor, _, _, snaplen, linktype = struct.unpack(order+'HHIIII', header)
    if (major, minor) != (2, 4) or linktype != 1 or not 0 < snaplen <= 16*1024*1024:
        raise ValueError('Requires PCAP 2.4, Ethernet link type 1 and a bounded snap length')
    consumed = 24
    while True:
        record = stream.read(16)
        if not record:
            break
        number = len(packets) + 1
        if number > max_packets:
            notices.append('Packet limit reached; remaining records not analyzed')
            break
        if len(record) != 16:
            notices.append('Truncated record header at packet %d' % number)
            break
        sec, fraction, captured, original = struct.unpack(order+'IIII', record)
        if fraction >= resolution or captured > snaplen or captured > original:
            notices.append('Invalid record metadata at packet %d' % number)
            break
        consumed += 16 + captured
        if consumed > max_bytes:
            notices.append('Byte limit reached; remaining records not analyzed')
            break
        data = stream.read(captured)
        if len(data) != captured:
            notices.append('Truncated record data at packet %d' % number)
            break
        packets.append({'number': number, 'time_ns': sec*1000000000 + fraction*(1000000000//resolution),
                        'data': data, 'captured': captured, 'original': original})
    return packets, notices, 'pcap'


def _pcapng_options(order, data):
    """Bounded option reader; yields (code, value) pairs."""
    cursor = 0
    while cursor + 4 <= len(data):
        code, length = struct.unpack(order+'HH', data[cursor:cursor+4])
        cursor += 4
        if code == 0:
            break
        if cursor + length > len(data):
            break
        yield code, data[cursor:cursor+length]
        cursor += length + (-length % 4)


def _read_pcapng(stream, max_packets, max_bytes):
    """First section only: Ethernet interfaces, Enhanced Packet Blocks, micro/nanosecond time."""
    packets, notices = [], []
    prologue = stream.read(8)
    if len(prologue) != 8 or prologue[4:] not in PCAPNG_ORDERS:
        raise ValueError('Expected classic PCAP or PCAPNG, not another format')
    order = PCAPNG_ORDERS[prologue[4:]]
    total = struct.unpack(order+'I', prologue[:4])[0]
    if total < 28 or total > PCAPNG_MAX_BLOCK:
        raise ValueError('Malformed PCAPNG section header')
    rest = stream.read(total-12)
    if len(rest) != total-12 or struct.unpack(order+'I', rest[-4:])[0] != total:
        raise ValueError('Malformed PCAPNG section header')
    if struct.unpack(order+'H', rest[0:2])[0] != 1:
        raise ValueError('Requires PCAPNG major version 1')
    consumed = total
    interfaces, skipped = [], Counter()
    while True:
        head = stream.read(8)
        if not head:
            break
        if len(head) != 8:
            notices.append('Truncated PCAPNG block header')
            break
        block_type, total = struct.unpack(order+'II', head)
        if block_type == 0x0A0D0D0A:
            notices.append('Additional PCAPNG section not analyzed; only the first section is processed')
            break
        if total < 12 or total > PCAPNG_MAX_BLOCK:
            notices.append('Malformed PCAPNG block length')
            break
        body = stream.read(total-8)
        if len(body) != total-8:
            notices.append('Truncated PCAPNG block data')
            break
        if struct.unpack(order+'I', body[-4:])[0] != total:
            notices.append('Malformed PCAPNG block length')
            break
        consumed += total
        if consumed > max_bytes:
            notices.append('Byte limit reached; remaining blocks not analyzed')
            break
        body = body[:-4]
        if block_type == 1:
            if len(body) < 8:
                notices.append('Malformed PCAPNG interface description')
                break
            linktype, _, snaplen = struct.unpack(order+'HHI', body[:8])
            if linktype != 1:
                interfaces.append(('skip', 'non-ethernet-interface'))
                continue
            if snaplen > 16*1024*1024:
                interfaces.append(('skip', 'unbounded-snap-length'))
                continue
            resolution, state = 1000000, 'ok'
            for code, value in _pcapng_options(order, body[8:]):
                if code == 9 and len(value) >= 1:
                    if value[0] in (6, 9):
                        resolution = 10**value[0]
                    else:
                        state = 'skip'
            if state == 'ok':
                interfaces.append(('ok', snaplen, resolution))
            else:
                interfaces.append(('skip', 'unsupported-timestamp-resolution'))
        elif block_type == 6:
            number = len(packets) + 1
            if number > max_packets:
                notices.append('Packet limit reached; remaining records not analyzed')
                break
            if len(body) < 20:
                notices.append('Malformed PCAPNG packet block at packet %d' % number)
                break
            interface, high, low, captured, original = struct.unpack(order+'IIIII', body[:20])
            if interface >= len(interfaces):
                skipped['unknown-interface'] += 1
                continue
            entry = interfaces[interface]
            if entry[0] == 'skip':
                skipped[entry[1]] += 1
                continue
            _, snaplen, resolution = entry
            if captured > original or (snaplen and captured > snaplen) or 20+captured > len(body):
                notices.append('Invalid record metadata at packet %d' % number)
                break
            timestamp = (high << 32) | low
            packets.append({'number': number, 'time_ns': timestamp*(1000000000//resolution),
                            'data': body[20:20+captured], 'captured': captured, 'original': original})
        elif block_type == 3:
            skipped['simple-packet-blocks'] += 1
        else:
            skipped['other-blocks'] += 1
    labels = {'non-ethernet-interface': 'Skipped %d enhanced packet block(s) on non-Ethernet interface(s)',
              'unbounded-snap-length': 'Skipped %d enhanced packet block(s) on interface(s) with an unbounded snap length',
              'unsupported-timestamp-resolution': 'Skipped %d enhanced packet block(s) with an unsupported timestamp resolution (only micro/nanosecond supported)',
              'unknown-interface': 'Skipped %d enhanced packet block(s) referencing an unknown interface',
              'simple-packet-blocks': 'Skipped %d simple packet block(s); they carry no timestamps',
              'other-blocks': 'Skipped %d other PCAPNG block(s) (name resolution, statistics or unknown types)'}
    for reason, count in skipped.items():
        if count:
            notices.append(labels[reason] % count)
    return packets, notices, 'pcapng'


def dns_question(data):
    """First uncompressed DNS question only. Never expose its text in a report."""
    if len(data) < 12:
        return None
    _, flags, questions, _, _, _ = struct.unpack('!6H', data[:12])
    if flags & 0x8000 or questions == 0:
        return None
    labels, cursor = [], 12
    while cursor < len(data):
        size = data[cursor]
        cursor += 1
        if size == 0:
            if not labels or cursor+4 > len(data):
                return None
            name = b'.'.join(labels)
            if len(name) > 253:
                return None
            return name.lower(), struct.unpack('!H', data[cursor:cursor+2])[0]
        # Compressed names, extended labels and oversized labels unsupported.
        if size > 63 or cursor+size > len(data):
            return None
        labels.append(data[cursor:cursor+size])
        cursor += size
    return None


def decode_packet(packet):
    data = packet['data']
    if len(data) < 14:
        return None, 'malformed-ethernet'
    kind = struct.unpack('!H', data[12:14])[0]
    offset = 14
    # Up to two VLAN tags; deeper nesting is intentionally unsupported.
    for _ in range(2):
        if kind not in (0x8100, 0x88a8):
            break
        if offset+4 > len(data):
            return None, 'malformed-vlan'
        kind = struct.unpack('!H', data[offset+2:offset+4])[0]
        offset += 4
    ip = data[offset:]
    if kind == 0x0800:
        if len(ip) < 20 or ip[0] >> 4 != 4:
            return None, 'malformed-ipv4'
        length = (ip[0] & 15)*4
        total = struct.unpack('!H', ip[2:4])[0]
        if length < 20 or total < length or len(ip) < total:
            return None, 'malformed-or-truncated-ipv4'
        fragment = struct.unpack('!H', ip[6:8])[0]
        if fragment & 0x3fff:
            return None, 'fragmented-ipv4'
        protocol = ip[9]
        src, dst = ip[12:16], ip[16:20]
        payload = ip[length:total]
    elif kind == 0x86dd:
        if len(ip) < 40 or ip[0] >> 4 != 6:
            return None, 'malformed-ipv6'
        payload_length = struct.unpack('!H', ip[4:6])[0]
        total = 40 + payload_length
        if len(ip) < total:
            return None, 'malformed-or-truncated-ipv6'
        protocol = ip[6]
        if protocol == 44:
            return None, 'fragmented-ipv6'
        if protocol not in (6, 17):
            return None, 'unsupported-ipv6-next-header'
        src, dst = ip[8:24], ip[24:40]
        payload = ip[40:total]
    else:
        return None, 'unsupported-network-type'
    event = {'number': packet['number'], 'time_ns': packet['time_ns'],
             'src': str(ipaddress.ip_address(src)), 'dst': str(ipaddress.ip_address(dst)),
             'bytes': total, 'protocol': 'TCP' if protocol == 6 else 'UDP' if protocol == 17 else str(protocol)}
    if protocol == 6:
        if len(payload) < 20:
            return None, 'malformed-tcp'
        tcp_length = (payload[12] >> 4)*4
        if tcp_length < 20 or tcp_length > len(payload):
            return None, 'malformed-tcp'
        event.update(sport=struct.unpack('!H',payload[:2])[0], dport=struct.unpack('!H',payload[2:4])[0],
                     syn=bool(payload[13] & 2), ack=bool(payload[13] & 16))
    elif protocol == 17:
        if len(payload) < 8:
            return None, 'malformed-udp'
        udp_length = struct.unpack('!H',payload[4:6])[0]
        if udp_length < 8 or udp_length > len(payload):
            return None, 'malformed-udp'
        event.update(sport=struct.unpack('!H',payload[:2])[0], dport=struct.unpack('!H',payload[2:4])[0])
        if event['dport'] == 53:
            query = dns_question(payload[8:udp_length])
            if query:
                event.update(dns_name=query[0], dns_type=query[1])
    else:
        return None, 'unsupported-transport'
    return event, None


def iso(time_ns):
    return datetime.fromtimestamp(time_ns/1000000000, timezone.utc).isoformat()


def investigate(path, window=60, ports=10, max_packets=100000, max_bytes=64*1024*1024):
    if window <= 0 or ports < 2 or max_packets <= 0 or max_bytes < 24:
        raise ValueError('Invalid analysis limits')
    packets, notices, capture_format = read_capture(path, max_packets, max_bytes)
    skipped, protocols = Counter(), Counter()
    events = []
    for packet in packets:
        event, reason = decode_packet(packet)
        if reason:
            skipped[reason] += 1
        else:
            events.append(event)
            protocols[event['protocol']] += 1
    key = secrets.token_bytes(32)
    def pseudonym(kind, value):
        raw = value if isinstance(value, bytes) else value.encode()
        return kind+'-'+hmac.new(key, kind.encode()+b'\0'+raw, hashlib.sha256).hexdigest()[:16]
    flows, queries = {}, Counter()
    queues, emitted, alerts = defaultdict(deque), set(), []
    for event in sorted(events, key=lambda e:(e['time_ns'], e['number'])):
        identity = (event['src'],event['dst'],event['sport'],event['dport'],event['protocol'])
        if identity not in flows:
            flows[identity] = {'packets':0, 'ip_bytes':0, 'first':event['time_ns'], 'last':event['time_ns']}
        flow = flows[identity]
        flow['packets'] += 1
        flow['ip_bytes'] += event['bytes']
        flow['last'] = event['time_ns']
        if 'dns_name' in event:
            queries[(event['dns_name'],event['dns_type'])] += 1
        if event['protocol'] == 'TCP' and event['syn'] and not event['ack']:
            pair=(event['src'],event['dst'])
            queue=queues[pair]
            while queue and event['time_ns']-queue[0]['time_ns'] > window*1000000000:
                queue.popleft()
            queue.append(event)
            unique={e['dport'] for e in queue}
            if len(unique) >= ports and pair not in emitted:
                emitted.add(pair)
                alerts.append({'rule':'possible-port-scan', 'severity':'medium',
                               'source':pseudonym('ip',pair[0]), 'target':pseudonym('ip',pair[1]),
                               'distinct_destination_ports':len(unique), 'detected_at':iso(event['time_ns']),
                               'evidence_packets':[e['number'] for e in queue]})
    ranked = sorted(flows.items(),key=lambda item:(-item[1]['ip_bytes'],item[0]))[:20]
    flow_rows=[{'source':pseudonym('ip',a),'target':pseudonym('ip',b), 'source_port':sp,'target_port':dp,
                'protocol':protocol,'packets':f['packets'],'ip_bytes':f['ip_bytes'],
                'first':iso(f['first']),'last':iso(f['last'])} for (a,b,sp,dp,protocol),f in ranked]
    dns_rows=[{'name':pseudonym('dns',name),'query_type':qt,'queries':count}
              for (name,qt),count in queries.most_common(20)]
    return {'stats':{'capture_records':len(packets),'capture_format':capture_format,'decoded_packets':len(events),
                     'protocol_packets':dict(protocols), 'skipped_by_reason':dict(skipped),
                     'total_directional_flows':len(flows),'dns_questions':sum(queries.values()),
                     'snaplen_truncated_records':sum(p['captured']<p['original'] for p in packets)},
            'top_flows':flow_rows, 'dns_queries':dns_rows, 'alerts':alerts,'notices':notices,
            'settings':{'window_seconds':window,'port_threshold':ports},
            'scope':'Classic PCAP and PCAPNG (first section) Ethernet IPv4/IPv6 TCP/UDP only. Per-report pseudonyms; no payload export. Heuristics, not confirmed attacks.'}


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture')
    parser.add_argument('--window',type=int,default=60)
    parser.add_argument('--ports',type=int,default=10)
    parser.add_argument('--max-packets',type=int,default=100000)
    parser.add_argument('--max-bytes',type=int,default=64*1024*1024)
    parser.add_argument('--format',choices=['text','json'],default='text')
    args=parser.parse_args(argv)
    try:
        report=investigate(args.capture,args.window,args.ports,args.max_packets,args.max_bytes)
    except (OSError,ValueError,OverflowError):
        print('Error: input unavailable, unsupported PCAP header or invalid limits',file=sys.stderr)
        return 2
    if args.format == 'json':
        print(json.dumps(report,indent=2))
    else:
        print('PCAP Workbench: %d decoded packet(s), %d review alert(s)' % (report['stats']['decoded_packets'],len(report['alerts'])))
        print('Stats:',report['stats'])
        for alert in report['alerts']:
            print('{rule} [{severity}] {source} -> {target}; ports={distinct_destination_ports}; packets={evidence_packets}'.format(**alert))
        for notice in report['notices']:
            print('NOTICE:',notice)
        print(report['scope'])
    return 2 if report['notices'] else (1 if report['alerts'] else 0)


if __name__ == '__main__':
    sys.exit(main())
