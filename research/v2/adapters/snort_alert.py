"""Parse Snort 3 alert_json output into evaluator prediction records.

Baseline: Snort 3.13.2.0 (fe29cbe7403acc0dd428065a69d8f29cc311c18e) with the
port_scan inspector. The gid/sid/message table below is frozen from the pinned
build's own port_scan module help (saved during provisioning), not from memory:
sid classes portscan (one host, many ports: vertical), portsweep (many hosts:
horizontal), plus decoy/distributed/filtered qualifiers across tcp/udp/ip/icmp.

An alert references the triggering packet (pkt_num, src/dst of that packet).
For sweeps the scanned group is therefore NOT enumerable from one alert; this
adapter records only the triggering packet's destination and never invents a
group. With alert_all=false (recorded default) Snort emits the first alert per
scanner/window; duplicate accounting is the contract's job, not this parser's.
Unknown port_scan sids, gid/sid/message contradictions and malformed lines
raise SnortAlertError; alerts from other gids are ignored with a count.
"""

import json
import re

PORT_SCAN_GID = 122

# sid -> (proto, direction, qualifiers, documented message)
_PORT_SCAN_SIDS = {
    1: ('tcp', 'vertical', (), 'TCP portscan'),
    2: ('tcp', 'vertical', ('decoy',), 'TCP decoy portscan'),
    3: ('tcp', 'horizontal', (), 'TCP portsweep'),
    4: ('tcp', 'distributed', ('distributed',), 'TCP distributed portscan'),
    5: ('tcp', 'vertical', ('filtered',), 'TCP filtered portscan'),
    6: ('tcp', 'vertical', ('filtered', 'decoy'), 'TCP filtered decoy portscan'),
    7: ('tcp', 'horizontal', ('filtered',), 'TCP filtered portsweep'),
    8: ('tcp', 'distributed', ('filtered', 'distributed'), 'TCP filtered distributed portscan'),
    9: ('ip', 'protocol', (), 'IP protocol scan'),
    10: ('ip', 'protocol', ('decoy',), 'IP decoy protocol scan'),
    11: ('ip', 'protocol-sweep', (), 'IP protocol sweep'),
    12: ('ip', 'distributed', ('distributed',), 'IP distributed protocol scan'),
    13: ('ip', 'protocol', ('filtered',), 'IP filtered protocol scan'),
    14: ('ip', 'protocol', ('filtered', 'decoy'), 'IP filtered decoy protocol scan'),
    15: ('ip', 'protocol-sweep', ('filtered',), 'IP filtered protocol sweep'),
    16: ('ip', 'distributed', ('filtered', 'distributed'), 'IP filtered distributed protocol scan'),
    17: ('udp', 'vertical', (), 'UDP portscan'),
    18: ('udp', 'vertical', ('decoy',), 'UDP decoy portscan'),
    19: ('udp', 'horizontal', (), 'UDP portsweep'),
    20: ('udp', 'distributed', ('distributed',), 'UDP distributed portscan'),
    21: ('udp', 'vertical', ('filtered',), 'UDP filtered portscan'),
    22: ('udp', 'vertical', ('filtered', 'decoy'), 'UDP filtered decoy portscan'),
    23: ('udp', 'horizontal', ('filtered',), 'UDP filtered portsweep'),
    24: ('udp', 'distributed', ('filtered', 'distributed'), 'UDP filtered distributed portscan'),
    25: ('icmp', 'horizontal', (), 'ICMP sweep'),
    26: ('icmp', 'horizontal', ('filtered',), 'ICMP filtered sweep'),
    27: ('tcp', 'open-port', (), 'open port'),
}

_TS_FRACTION = re.compile(r'\.(\d+)$')

_REQUIRED = ('timestamp', 'seconds', 'pkt_num', 'proto', 'src_addr', 'dst_addr',
             'dst_port', 'gid', 'sid', 'msg')


class SnortAlertError(ValueError):
    """Raised on malformed lines or alerts outside documented gid/sid formats."""


def _event_time_ns(record, where):
    seconds = record['seconds']
    if type(seconds) is not int or seconds < 0:
        raise SnortAlertError('%s: bad seconds %r' % (where, record.get('seconds')))
    timestamp = record['timestamp']
    if not isinstance(timestamp, str):
        raise SnortAlertError('%s: bad timestamp %r' % (where, timestamp))
    fraction = _TS_FRACTION.search(timestamp)
    nanos = 0
    if fraction:
        digits = fraction.group(1)
        if len(digits) > 9:
            raise SnortAlertError('%s: timestamp fraction beyond ns: %r' % (where, timestamp))
        nanos = int(digits.ljust(9, '0'))
    return seconds * 10 ** 9 + nanos


def parse_alert_json(text, capture_id, source='alert_json.txt'):
    """Parse alert_json lines into (predictions, ignored_other_gid_count).

    Strict: every nonblank line must be one JSON object with the documented
    alert_json keys; gid 122 rows must use a documented sid whose message text
    matches the pinned inspector help; proto must agree with the sid class.
    """
    predictions = []
    ignored = 0
    for lineno, raw in enumerate(text.splitlines(), start=1):
        if not raw.strip():
            continue
        where = '%s:%d' % (source, lineno)
        try:
            record = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise SnortAlertError('%s: invalid JSON: %s' % (where, exc))
        if not isinstance(record, dict):
            raise SnortAlertError('%s: alert is not a JSON object' % where)
        missing = [key for key in _REQUIRED if key not in record]
        if missing:
            raise SnortAlertError('%s: missing keys %s' % (where, ','.join(missing)))
        gid = record['gid']
        sid = record['sid']
        if gid != PORT_SCAN_GID:
            ignored += 1
            continue
        if sid not in _PORT_SCAN_SIDS:
            raise SnortAlertError('%s: undocumented port_scan sid %r' % (where, sid))
        proto, direction, qualifiers, message = _PORT_SCAN_SIDS[sid]
        msg = record['msg']
        if not isinstance(msg, str) or not msg.endswith(message):
            raise SnortAlertError('%s: msg %r contradicts documented sid %d message %r'
                                  % (where, msg, sid, message))
        if not isinstance(record['proto'], str) or record['proto'].lower() != proto:
            raise SnortAlertError('%s: proto %r contradicts sid %d proto %s'
                                  % (where, record['proto'], sid, proto))
        pkt_num = record['pkt_num']
        if type(pkt_num) is not int or pkt_num < 1:
            raise SnortAlertError('%s: bad pkt_num %r' % (where, pkt_num))
        dst_port = record['dst_port']
        if type(dst_port) is not int or not 0 <= dst_port <= 65535:
            raise SnortAlertError('%s: bad dst_port %r' % (where, dst_port))
        src_port = record.get('src_port')
        if proto in ('tcp', 'udp') and (type(src_port) is not int or not 0 <= src_port <= 65535):
            raise SnortAlertError('%s: bad src_port %r' % (where, src_port))

        target_host = None
        target_port = None
        if direction == 'vertical':
            target_host = record['dst_addr']
        elif direction == 'horizontal':
            target_port = dst_port
        qualifiers_out = {
            'sid': sid,
            'sid_message': message,
            'qualifiers': list(qualifiers),
            'trigger_pkt_num': pkt_num,
            'trigger_dst_addr': record['dst_addr'],
            'trigger_dst_port': dst_port,
        }
        predictions.append({
            'engine': 'snort',
            'capture_id': capture_id,
            'alert_id': 'snort:%s:%s:L%d:pkt%d' % (capture_id, source, lineno, pkt_num),
            'family': 'generic-scan',
            'direction': direction,
            'scanner': record['src_addr'],
            'target_host': target_host,
            'target_hosts': None,
            'target_port': target_port,
            'target_ports': None,
            'event_time_ns': _event_time_ns(record, where),
            'decision_time_ns': None,
            'qualifiers': qualifiers_out,
            'evidence_reference': 'gid %d sid %d (%s) at %s' % (gid, sid, message, where),
            'raw_record_reference': where,
        })
    return predictions, ignored
