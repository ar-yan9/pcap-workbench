"""Parse Zeek notice.log scan notices into evaluator prediction records.

Baseline: Zeek 8.0.11 + pinned bro-simple-scan 35cf19cf64ba9f9989022a56dce0c8ad6ae2f3f2
+ bro-is-darknet 7564a8f2035aa62359199b64086ff14749f35f73 (protocol amendment A1).
Message formats below are anchored to the pinned package source scripts/scan.zeek
(analyze_unique_hostports / generate_notice), not inferred from one sample. The
duration suffix uses the installed base/utils/time duration_to_mins_secs "%dm%ds".

This adapter extracts and cross-checks engine evidence only. It never invents
family, technique, target or decision-time evidence: unknown scan-notice content
raises ZeekNoticeError, and non-scan notices are ignored with a count. Zeek
notice ts is an emission timestamp that offline EOF flushing can delay
(documented development diagnostic); it is not a decision-delay measurement.
"""

import re
from decimal import Decimal

SCAN_NOTES = frozenset({'Scan::Address_Scan', 'Scan::Port_Scan', 'Scan::Random_Scan'})

_NOTE_DIRECTION = {
    'Scan::Address_Scan': 'horizontal',
    'Scan::Port_Scan': 'vertical',
    'Scan::Random_Scan': 'random',
}

# generate_notice: fmt("%s scanned at least %s in %s", scanner, inner, dur),
# with optional "kk: " prefix for knockknock notices.
_MSG = re.compile(
    r'^(?P<kk>kk: )?(?P<scanner>\S+) scanned at least (?P<inner>.+) in '
    r'(?P<dur>(?P<dur_m>\d+)m(?P<dur_s>\d+)s)$')

# analyze_unique_hostports inner formats, exact literals from the pinned source.
_INNERS = (
    ('horizontal', 'single_port',
     re.compile(r'^(?P<count>\d+) unique hosts on port (?P<port>\S+)$')),
    ('vertical', 'single_host',
     re.compile(r'^(?P<count>\d+) unique ports on host (?P<host>\S+)$')),
    ('horizontal', 'multi_port',
     re.compile(r'^(?P<count>\d+) unique hosts on ports (?P<ports>.+)$')),
    ('vertical', 'multi_host',
     re.compile(r'^(?P<count>\d+) unique ports on hosts (?P<hosts>.+)$')),
    ('random', 'random',
     re.compile(r'^(?P<count_hosts>\d+) hosts on (?P<count_ports>\d+) ports$')),
)

_PORT = re.compile(r'^(?P<number>\d+)/(?P<proto>tcp|udp|icmp)$')


class ZeekNoticeError(ValueError):
    """Raised on malformed logs or scan notices outside documented formats."""


def _decode_separator(text):
    def repl(match):
        return chr(int(match.group(1), 16))
    return re.sub(r'\\x([0-9a-fA-F]{2})', repl, text)


def parse_port(text):
    """Parse a Zeek '80/tcp' port string into (number, proto)."""
    match = _PORT.match(text)
    if not match:
        raise ZeekNoticeError('unrecognized Zeek port format: %r' % (text,))
    return int(match.group('number')), match.group('proto')


def parse_notice_log(text, capture_id, source='notice.log'):
    """Parse one notice.log into (predictions, ignored_non_scan_count).

    capture_id scopes deterministic alert IDs. source names the raw file in
    references. Strict: header directives #separator/#fields/#types/#empty_field/
    #unset_field are required before data; every data row must match the field
    count; every scan notice must match a documented pinned-package format.
    """
    separator = None
    fields = None
    types = None
    empty_field = None
    unset_field = None
    predictions = []
    ignored = 0
    for lineno, raw in enumerate(text.splitlines(), start=1):
        if not raw:
            continue
        if raw.startswith('#'):
            parts = raw[1:].split(None, 1)
            name = parts[0]
            value = parts[1] if len(parts) > 1 else ''
            if name == 'separator':
                separator = _decode_separator(value)
            elif name == 'fields' and separator is not None:
                fields = value.split(separator)
            elif name == 'types' and separator is not None:
                types = value.split(separator)
            elif name == 'empty_field':
                empty_field = value
            elif name == 'unset_field':
                unset_field = value
            continue
        if separator is None or fields is None or types is None:
            raise ZeekNoticeError('%s:%d: data row before complete header' % (source, lineno))
        columns = raw.split(separator)
        if len(columns) != len(fields) or len(types) != len(fields):
            raise ZeekNoticeError('%s:%d: column/field/type count mismatch' % (source, lineno))
        row = {}
        for name, value in zip(fields, columns):
            if unset_field is not None and value == unset_field:
                row[name] = None
            elif empty_field is not None and value == empty_field:
                row[name] = ''
            else:
                row[name] = value
        note = row.get('note')
        if note not in SCAN_NOTES:
            ignored += 1
            continue
        predictions.append(_scan_prediction(row, note, capture_id, source, lineno))
    return predictions, ignored


def _scan_prediction(row, note, capture_id, source, lineno):
    where = '%s:%d' % (source, lineno)
    msg = row.get('msg')
    if not msg:
        raise ZeekNoticeError('%s: scan notice without msg' % where)
    match = _MSG.match(msg)
    if not match:
        raise ZeekNoticeError('%s: scan notice msg outside documented formats: %r' % (where, msg))
    inner = match.group('inner')
    parsed = None
    for direction, shape, pattern in _INNERS:
        inner_match = pattern.match(inner)
        if inner_match:
            parsed = (direction, shape, inner_match)
            break
    if parsed is None:
        raise ZeekNoticeError('%s: scan notice inner msg outside documented formats: %r' % (where, inner))
    direction, shape, inner_match = parsed
    if direction != _NOTE_DIRECTION[note]:
        raise ZeekNoticeError('%s: note %s contradicts msg direction %s' % (where, note, direction))
    src = row.get('src')
    if not src:
        raise ZeekNoticeError('%s: scan notice without src scanner' % where)
    if src != match.group('scanner'):
        raise ZeekNoticeError('%s: src field %r contradicts msg scanner %r' % (where, src, match.group('scanner')))
    ts = row.get('ts')
    if ts is None:
        raise ZeekNoticeError('%s: scan notice with unset ts' % where)
    try:
        event_time_ns = int(Decimal(ts) * Decimal(10) ** 9)
    except ArithmeticError:
        raise ZeekNoticeError('%s: unparseable ts %r' % (where, ts))

    target_host = None
    target_hosts = None
    target_port = None
    target_ports = None
    count = None
    if shape == 'single_host':
        target_host = inner_match.group('host')
        count = int(inner_match.group('count'))
    elif shape == 'multi_host':
        target_hosts = inner_match.group('hosts').split(', ')
        count = int(inner_match.group('count'))
    elif shape == 'single_port':
        number, proto = parse_port(inner_match.group('port'))
        target_port = number
        count = int(inner_match.group('count'))
    elif shape == 'multi_port':
        target_ports = [parse_port(p)[0] for p in inner_match.group('ports').split(', ')]
        count = int(inner_match.group('count'))
    else:
        count = int(inner_match.group('count_hosts'))

    suppress_for = row.get('suppress_for')
    qualifiers = {
        'note': note,
        'side': row.get('sub') or None,
        'knockknock': match.group('kk') is not None,
        'engine_count': count,
        'engine_duration_s': int(match.group('dur_m')) * 60 + int(match.group('dur_s')),
        'suppress_for_s': None if suppress_for is None else int(Decimal(suppress_for)),
        'msg_shape': shape,
    }
    return {
        'engine': 'zeek',
        'capture_id': capture_id,
        'alert_id': 'zeek:%s:%s:L%d' % (capture_id, source, lineno),
        'family': 'generic-scan',
        'direction': direction,
        'scanner': src,
        'target_host': target_host,
        'target_hosts': target_hosts,
        'target_port': target_port,
        'target_ports': target_ports,
        'event_time_ns': event_time_ns,
        'decision_time_ns': None,
        'qualifiers': qualifiers,
        'evidence_reference': '%s %s at %s' % (note, shape, where),
        'raw_record_reference': where,
    }
