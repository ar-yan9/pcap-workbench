#!/usr/bin/env python3
"""Offline classic-PCAP investigation. No sniffing, network calls or payload export."""
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


def read_capture(path, max_packets=100000, max_bytes=64*1024*1024):
    """Bounded classic PCAP reader; record numbers are the evidence references."""
    packets, notices = [], []
    with Path(path).open('rb') as stream:
        header = stream.read(24)
        if len(header) != 24 or header[:4] not in MAGIC:
            raise ValueError('Expected classic PCAP, not PCAPNG or another format')
        order, resolution = MAGIC[header[:4]]
        major, minor, _, _, snaplen, linktype = struct.unpack(order+'HHIIII', header[4:])
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
    return packets, notices


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
    if kind != 0x0800:
        return None, 'unsupported-network-type'
    ip = data[offset:]
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
    event = {'number': packet['number'], 'time_ns': packet['time_ns'],
             'src': str(ipaddress.ip_address(ip[12:16])), 'dst': str(ipaddress.ip_address(ip[16:20])),
             'bytes': total, 'protocol': 'TCP' if protocol == 6 else 'UDP' if protocol == 17 else str(protocol)}
    payload = ip[length:total]
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
    packets, notices = read_capture(path, max_packets, max_bytes)
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
    return {'stats':{'capture_records':len(packets),'decoded_packets':len(events),
                     'protocol_packets':dict(protocols), 'skipped_by_reason':dict(skipped),
                     'total_directional_flows':len(flows),'dns_questions':sum(queries.values()),
                     'snaplen_truncated_records':sum(p['captured']<p['original'] for p in packets)},
            'top_flows':flow_rows, 'dns_queries':dns_rows, 'alerts':alerts,'notices':notices,
            'settings':{'window_seconds':window,'port_threshold':ports},
            'scope':'Classic PCAP Ethernet IPv4 TCP/UDP only. Per-report pseudonyms; no payload export. Heuristics, not confirmed attacks.'}


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
