#!/usr/bin/env python3
"""v2 selection detector, implementing the frozen "Detector contract to
implement before test runs" in research/v2/protocol.md (v0.2 + A1 + A2/A2.1).

Contract points implemented:
- Events retain original packet number, integer ns timestamp, address family,
  source/destination, ports and full TCP flags.
- Sorted detection-only input streams; non-monotonic timestamps are rejected.
- Grid W in {10,60,300}s x T in {5,10,15,20}; H = T (declared convention).
- Thresholds count distinct values in the inclusive window [t-W, t].
- Vertical keys (source, target, family); horizontal keys
  (source, target_port, family).
- Family masks on the low six TCP control bits: SYN = SYN set and ACK clear;
  FIN-only = 0x01; NULL = 0x00; Xmas = 0x29. ECE/CWR are ignored for
  classification and retained in evidence. FIN+ACK is negative.
- Emit at most once per active key/family episode; re-arm only when the gap
  since the key's last qualifying probe is strictly greater than W.
- Distinct values keep reference counts under retransmission; idle keys are
  expired globally once their window must be empty (last probe older than W,
  which coincides with the re-arm condition, so expiry is semantics-neutral).
- Development safety budgets: 100,000 active keys and 1,000,000 retained
  probe events. Exceeding either raises StateCapExhausted: visible, never a
  silent eviction scored as complete.

This module is offline research tooling for synthetic labeled traces. It is
not a result; no measurements live here.
"""
import argparse, json, struct, sys
from collections import deque

# Development-only safety budgets (protocol: proposed, not verified capacity).
MAX_ACTIVE_KEYS = 100_000
MAX_RETAINED_PROBES = 1_000_000

MASKS = {'syn': 0x02, 'fin': 0x01, 'null': 0x00, 'xmas': 0x29}


def classify(flags):
    """Family from full TCP flags; None when the packet qualifies for none.

    Low six control bits only (ECE/CWR ignored). SYN = SYN set and ACK clear;
    FIN/NULL/Xmas require exact equality so FIN+ACK is negative.
    """
    low = flags & 0x3f
    if low & 0x02 and not low & 0x10:
        return 'syn'
    if low == 0x01:
        return 'fin'
    if low == 0x00:
        return 'null'
    if low == 0x29:
        return 'xmas'
    return None


class StateCapExhausted(RuntimeError):
    def __init__(self, which, cap):
        super().__init__('state cap exhausted: %s > %d' % (which, cap))
        self.which = which
        self.cap = cap


class KeyState:
    __slots__ = ('entries', 'refcounts', 'last_probe_ns', 'fired', 'fire_count')

    def __init__(self):
        self.entries = deque()          # (t_ns, value) in arrival order
        self.refcounts = {}             # value -> count inside window
        self.last_probe_ns = None
        self.fired = False
        self.fire_count = 0


class V2Detector:
    """Streaming detector over sorted probe events."""

    def __init__(self, window_s, threshold):
        if window_s <= 0 or threshold < 2:
            raise ValueError('invalid window/threshold')
        self.window_ns = int(window_s * 1_000_000_000)
        self.threshold = threshold
        self.states = {}                # key -> KeyState
        self.retained = 0
        self.probes_seen = 0
        self.alerts = []
        self._expiry_cursor = deque()   # (last_probe_ns, key) lazy expiry queue

    def _expire_globally(self, now_ns):
        while self._expiry_cursor:
            last, key = self._expiry_cursor[0]
            if last > now_ns - self.window_ns:
                break
            self._expiry_cursor.popleft()
            st = self.states.get(key)
            if st is not None and st.last_probe_ns == last and not st.entries:
                del self.states[key]

    def _evict_window(self, st, now_ns):
        cutoff = now_ns - self.window_ns  # inclusive [t-W, t]: keep ts >= cutoff
        while st.entries and st.entries[0][0] < cutoff:
            _, value = st.entries.popleft()
            self.retained -= 1
            st.refcounts[value] -= 1
            if st.refcounts[value] == 0:
                del st.refcounts[value]

    def process(self, t_ns, number, src, dst, sport, dport, flags, af='ipv4'):
        fam = classify(flags)
        if fam is None:
            return
        self.probes_seen += 1
        self._expire_globally(t_ns)
        for key in ((src, dst, fam, 'vertical'),
                    (src, dport, fam, 'horizontal')):
            value = dport if key[3] == 'vertical' else dst
            st = self.states.get(key)
            if st is None:
                if len(self.states) >= MAX_ACTIVE_KEYS:
                    raise StateCapExhausted('active_keys', MAX_ACTIVE_KEYS)
                st = self.states[key] = KeyState()
            if st.last_probe_ns is not None and t_ns < st.last_probe_ns:
                raise ValueError('unsorted input: timestamps must be non-decreasing per stream order')
            # Re-arm only after a gap strictly greater than W.
            if st.fired and st.last_probe_ns is not None and t_ns - st.last_probe_ns > self.window_ns:
                st.fired = False
            self._evict_window(st, t_ns)
            if self.retained >= MAX_RETAINED_PROBES:
                raise StateCapExhausted('retained_probes', MAX_RETAINED_PROBES)
            st.entries.append((t_ns, value))
            st.refcounts[value] = st.refcounts.get(value, 0) + 1
            self.retained += 1
            self._expiry_cursor.append((t_ns, key))
            if (not st.fired) and len(st.refcounts) >= self.threshold:
                st.fired = True
                st.fire_count += 1
                first_ns = st.entries[0][0]
                alert = {
                    'engine': 'v2-detector',
                    'family': fam,
                    'direction': key[3],
                    'scanner': src if isinstance(src, str) else _ip(src),
                    'event_time_ns': first_ns,
                    'decision_time_ns': t_ns,
                    'distinct_count': len(st.refcounts),
                    'window_s': self.window_ns // 1_000_000_000,
                    'threshold': self.threshold,
                    'evidence_packet': number,
                    'key_fire_index': st.fire_count,
                }
                if key[3] == 'vertical':
                    alert['target'] = _ip(key[1]) if not isinstance(key[1], str) else key[1]
                else:
                    alert['target_port'] = key[1]
                self.alerts.append(alert)
            st.last_probe_ns = t_ns

    def summary(self):
        return {'engine': 'v2-detector', 'window_s': self.window_ns // 1_000_000_000,
                'threshold': self.threshold, 'probes_seen': self.probes_seen,
                'alerts': len(self.alerts), 'active_keys': len(self.states),
                'retained_probes': self.retained,
                'caps': {'max_active_keys': MAX_ACTIVE_KEYS,
                         'max_retained_probes': MAX_RETAINED_PROBES},
                'caps_exhausted': False}


def _ip(b):
    if isinstance(b, str):
        return b
    if len(b) == 4:
        return '.'.join(str(x) for x in b)
    return ':'.join('%x' % struct.unpack('!H', b[i:i+2])[0] for i in range(0, 16, 2))


def read_pcap(path):
    """Yield (t_ns, number, src, dst, sport, dport, flags, af) from a pcap.

    Rejects non-monotonic timestamps. Supports Ethernet + IPv4/IPv6 TCP.
    """
    data = open(path, 'rb').read()
    if data[:4] == struct.pack('<I', 0xa1b2c3d4):
        endian, nano = '<', False
    elif data[:4] == struct.pack('>I', 0xa1b2c3d4):
        endian, nano = '>', False
    elif data[:4] == b'\x4d\x3c\xb2\xa1':
        endian, nano = '<', True
    elif data[:4] == b'\xa1\xb2\x3c\x4d':
        endian, nano = '>', True
    else:
        raise ValueError('not a pcap file')
    off, number, last_t = 24, 0, None
    while off + 16 <= len(data):
        sec, frac, incl, _ = struct.unpack(endian + 'IIII', data[off:off+16])
        off += 16
        frame = data[off:off+incl]
        off += incl
        number += 1
        t_ns = sec * 1_000_000_000 + (frac if nano else frac * 1000)
        if last_t is not None and t_ns < last_t:
            raise ValueError('unsorted capture: packet %d out of order' % number)
        last_t = t_ns
        if len(frame) < 14:
            continue
        kind = struct.unpack('!H', frame[12:14])[0]
        base = 14
        for _ in range(2):
            if kind not in (0x8100, 0x88a8):
                break
            kind = struct.unpack('!H', frame[base+2:base+4])[0]
            base += 4
        if kind == 0x0800 and len(frame) >= base + 20:
            ip = frame[base:]
            ihl = (ip[0] & 0x0f) * 4
            if ip[9] != 6 or len(ip) < ihl + 14:
                continue
            frag = struct.unpack('!H', ip[6:8])[0]
            if frag & 0x3fff:
                continue  # non-first fragments carry no flags
            sport, dport = struct.unpack('!HH', ip[ihl:ihl+4])
            flags = ip[ihl+13]
            yield (t_ns, number, ip[12:16], ip[16:20], sport, dport, flags, 'ipv4')
        elif kind == 0x86dd and len(frame) >= base + 40:
            ip = frame[base:]
            if ip[6] != 6:
                continue
            sport, dport = struct.unpack('!HH', ip[40:44])
            flags = ip[40+13]
            yield (t_ns, number, ip[8:24], ip[24:40], sport, dport, flags, 'ipv6')


def run(capture, window_s, threshold):
    det = V2Detector(window_s, threshold)
    try:
        for ev in read_pcap(capture):
            det.process(*ev)
    except StateCapExhausted as exc:
        s = det.summary()
        s['caps_exhausted'] = True
        s['exhausted_on'] = exc.which
        return det.alerts, s
    return det.alerts, det.summary()


def main(argv=None):
    ap = argparse.ArgumentParser(description='v2 selection detector (frozen contract)')
    ap.add_argument('--capture', required=True)
    ap.add_argument('--window', type=int, required=True, help='W seconds (grid: 10, 60, 300)')
    ap.add_argument('--threshold', type=int, required=True, help='T (grid: 5, 10, 15, 20); H = T')
    ap.add_argument('--out', help='write alerts JSONL here')
    args = ap.parse_args(argv)
    alerts, summary = run(args.capture, args.window, args.threshold)
    if args.out:
        with open(args.out, 'w') as fh:
            for a in alerts:
                fh.write(json.dumps(a, sort_keys=True) + '\n')
    print(json.dumps(summary, sort_keys=True))
    return 1 if alerts else 0


if __name__ == '__main__':
    sys.exit(main())
