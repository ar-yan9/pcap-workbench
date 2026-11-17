"""Structural and determinism tests for the v2 synthetic corpus generator.

These test the generator against synthetic-corpus-spec-v0.1.md: byte
determinism, seed separation, pcap checksums, family structure, label schema.
They are format/specification tests, not detector performance results.
"""
import hashlib, json, struct, tempfile, unittest
from pathlib import Path

import importlib.util
_spec = importlib.util.spec_from_file_location(
    'synthetic_corpus', Path(__file__).resolve().parent / 'research' / 'v2' / 'generators' / 'synthetic_corpus.py')
GEN = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(GEN)


def read_pcap(path):
    """Return list of (ts_ns, src, dst, proto, sport, dport, flags, frame_bytes)."""
    data = Path(path).read_bytes()
    assert data[:4] == struct.pack('<I', 0xa1b2c3d4) and struct.unpack('<I', data[20:24])[0] == 1
    off, out = 24, []
    while off < len(data):
        sec, usec, incl, _ = struct.unpack('<IIII', data[off:off+16])
        frame = data[off+16:off+16+incl]
        off += 16 + incl
        ip = frame[14:]
        proto = ip[9]
        src, dst = ip[12:16], ip[16:20]
        frag = struct.unpack('!H', ip[6:8])[0]
        sport = dport = flags = None
        if proto == 6 and frag == 0:
            sport, dport = struct.unpack('!HH', ip[20:24])
            flags = ip[33]
        elif proto == 17 and frag == 0:
            sport, dport = struct.unpack('!HH', ip[20:24])
        out.append((sec*1_000_000_000 + usec*1000, src, dst, proto, sport, dport, flags, frame))
    return out


def verify_checksums(frame):
    ip = frame[14:]
    ihl = (ip[0] & 0x0f) * 4
    hdr = ip[:ihl]
    assert GEN.csum(hdr) == 0, 'bad IPv4 header checksum'
    proto, src, dst = ip[9], ip[12:16], ip[16:20]
    payload = ip[ihl:]
    pseudo = src + dst + struct.pack('!BBH', 0, proto, len(payload))
    assert GEN.csum(pseudo + payload) == 0, 'bad transport checksum'


def gen_to_tmp(fam, seeds):
    tmp = tempfile.TemporaryDirectory()
    for seed in seeds:
        ev, labels = GEN.build(fam, seed)
        cid = labels['capture_id']
        GEN.write_pcap(Path(tmp.name) / (cid + '.pcap'), ev)
        (Path(tmp.name) / (cid + '.labels.json')).write_text(json.dumps(labels, sort_keys=True))
    return tmp


class DeterminismTests(unittest.TestCase):
    def test_all_families_byte_deterministic(self):
        for fam in GEN.FAMILIES:
            h = []
            for _ in range(2):
                ev, labels = GEN.build(fam, 0)
                buf = tempfile.NamedTemporaryFile(delete=False)
                GEN.write_pcap(buf.name, ev)
                h.append((hashlib.sha256(Path(buf.name).read_bytes()).hexdigest(),
                          hashlib.sha256(json.dumps(labels, sort_keys=True).encode()).hexdigest()))
            self.assertEqual(h[0], h[1], fam)

    def test_seed_separation(self):
        e0, _ = GEN.build('fast-vertical-syn', 0)
        e1, _ = GEN.build('fast-vertical-syn', 1)
        self.assertNotEqual([f for _, f in e0], [f for _, f in e1])

    def test_subseed_scheme_matches_spec(self):
        sub = int.from_bytes(hashlib.sha256(
            b"v2-synth-corpus-v0.1|fast-vertical-syn|0").digest()[:8], 'big')
        _, labels = GEN.build('fast-vertical-syn', 0)
        self.assertEqual(labels['episodes'][0]['provenance']['sub_seed_hex'], '%016x' % sub)


class StructureTests(unittest.TestCase):
    def test_epoch_base_formula(self):
        for fam, seed in (('udp', 3), ('normal-sessions', 7)):
            ev, labels = GEN.build(fam, seed)
            idx = GEN.FAMILIES.index(fam)
            self.assertEqual(labels['epoch_base_s'], 1700000000 + (seed * 18 + idx) * 86400)
            self.assertEqual(labels['split'], 'development' if seed <= 9 else 'held-out')

    def test_fast_vertical_structure(self):
        tmp = gen_to_tmp('fast-vertical-syn', [0])
        with tmp:
            rows = read_pcap(Path(tmp.name) / 'fast-vertical-syn-s0.pcap')
            labels = json.loads((Path(tmp.name) / 'fast-vertical-syn-s0.labels.json').read_text())
            scan = GEN.ipb(labels['episodes'][0]['scanner'])
            tgt = GEN.ipb(labels['episodes'][0]['target'])
            probes = [r for r in rows if r[1] == scan and r[2] == tgt and r[6] == 0x02]
            dports = {r[5] for r in probes}
            self.assertTrue(60 <= len(dports) <= 120)
            self.assertEqual(len(probes), len(dports))
            gaps = [probes[i+1][0] - probes[i][0] for i in range(len(probes)-1)]
            self.assertTrue(all(6_000_000 <= g <= 55_000_000 for g in gaps))

    def test_threshold_edge_variants(self):
        for seed, (n_ports, corner, inside) in enumerate([(20, 10, True), (20, 10, False),
                                                          (5, 300, True), (5, 300, False)]):
            ev, labels = GEN.build('threshold-edge-syn', seed)
            ep = labels['episodes'][0]
            span_s = (ep['last_probe_ns'] - ep['first_probe_ns']) / 1e9
            self.assertEqual(len(ev) // 1 >= n_ports, True)
            scan = GEN.ipb(ep['scanner']); tgt = GEN.ipb(ep['target'])
            probes = [f for t, f in ev]
            probe_rows = [r for r in read_pcap_frames(ev) if r[1] == scan and r[2] == tgt and r[6] == 0x02]
            self.assertEqual(len({r[5] for r in probe_rows}), n_ports)
            if inside:
                self.assertLessEqual(span_s, corner + 0.05, (seed, span_s))
            else:
                self.assertGreater(span_s, corner, (seed, span_s))

    def test_flag_families(self):
        for fam, fl in (('fin', 0x01), ('null', 0x00), ('xmas', 0x29)):
            ev, labels = GEN.build(fam, 0)
            ep = labels['episodes'][0]
            scan, tgt = GEN.ipb(ep['scanner']), GEN.ipb(ep['target'])
            rows = [r for r in read_pcap_frames(ev) if r[1] == scan and r[2] == tgt]
            self.assertTrue(rows)
            self.assertTrue(all(r[6] == fl for r in rows))

    def test_mixed_family_ambiguous(self):
        ev, labels = GEN.build('mixed-families', 0)
        self.assertEqual(labels['episodes'][0]['intent'], 'ambiguous')
        ep = labels['episodes'][0]
        scan, tgt = GEN.ipb(ep['scanner']), GEN.ipb(ep['target'])
        fls = {r[6] for r in read_pcap_frames(ev) if r[1] == scan and r[2] == tgt}
        self.assertEqual(fls, {0x02, 0x01})

    def test_distributed_structure(self):
        ev, labels = GEN.build('distributed-syn', 0)
        eps = labels['episodes']
        self.assertTrue(8 <= len(eps) <= 16)
        self.assertEqual(len({e['campaign_id'] for e in eps}), 1)
        self.assertTrue(all(e['scope'] == 'out-of-scope-stress' for e in eps))
        for e in eps:
            scan, tgt = GEN.ipb(e['scanner']), GEN.ipb(e['target'])
            dports = {r[5] for r in read_pcap_frames(ev) if r[1] == scan and r[2] == tgt and r[6] == 0x02}
            self.assertTrue(3 <= len(dports) <= 4)

    def test_udp_family_has_no_tcp(self):
        ev, labels = GEN.build('udp', 0)
        rows = read_pcap_frames(ev)
        self.assertTrue(all(r[3] == 17 for r in rows if r[1] == GEN.ipb(labels['episodes'][0]['scanner'])))
        self.assertEqual(labels['episodes'][0]['technique'], 'udp')

    def test_repeated_bursts_rearm_gap(self):
        ev, labels = GEN.build('repeated-vertical-bursts', 0)
        eps = labels['episodes']
        self.assertTrue(3 <= len(eps) <= 5)
        self.assertEqual(len({e['campaign_id'] for e in eps}), 1)
        for a, b in zip(eps, eps[1:]):
            self.assertGreater(b['first_probe_ns'] - a['last_probe_ns'], 400 * 1_000_000_000 - 1)

    def test_normal_sessions_all_answered(self):
        ev, labels = GEN.build('normal-sessions', 0)
        rows = read_pcap_frames(ev)
        syns = [(r[0], r[1], r[2], r[4], r[5]) for r in rows if r[6] == 0x02]
        synacks = {(r[1], r[2], r[4], r[5]) for r in rows if r[6] == 0x12}
        unanswered = [s for s in syns if (s[2], s[1], s[4], s[3]) not in synacks]
        self.assertEqual(unanswered, [])
        self.assertEqual(labels['benign_units'][0]['duration_s'], 3600)

    def test_fin_ack_teardown_negative(self):
        ev, _ = GEN.build('fin-ack-teardown', 0)
        fls = {r[6] for r in read_pcap_frames(ev)}
        self.assertNotIn(0x01, fls)
        self.assertNotIn(0x00, fls)
        self.assertIn(0x11, fls)

    def test_service_discovery_below_threshold(self):
        ev, labels = GEN.build('service-discovery', 0)
        rows = read_pcap_frames(ev)
        scan = GEN.ipb('192.0.2.0')  # scanner drawn from SCANNER_NET
        ports_per_host = {}
        for r in rows:
            if r[6] == 0x02 and r[3] == 6:
                ports_per_host.setdefault((r[1], r[2]), set()).add(r[5])
        self.assertTrue(5 <= len(ports_per_host) <= 12)
        self.assertTrue(all(2 <= len(v) <= 4 for v in ports_per_host.values()))


def read_pcap_frames(ev):
    """Parse frames built in-memory: (ts, frame) -> rows like read_pcap."""
    rows = []
    for tns, frame in ev:
        ip = frame[14:]
        proto = ip[9]
        sport = dport = flags = None
        if proto == 6:
            sport, dport = struct.unpack('!HH', ip[20:24])
            flags = ip[33]
        elif proto == 17:
            sport, dport = struct.unpack('!HH', ip[20:24])
        rows.append((tns, ip[12:16], ip[16:20], proto, sport, dport, flags, frame))
    return rows


class BenignFanoutInvariantTests(unittest.TestCase):
    """Erratum E1: benign session traffic never aggregates >= 5 distinct
    ports on one ordered (src, dst) pair, so the vertical SYN detector cannot
    alert on it at any grid threshold T >= 5."""

    def max_distinct_ports_per_pair(self, fam):
        worst = 0
        for seed in range(6):
            ev, _ = GEN.build(fam, seed)
            pair_ports = {}
            for r in read_pcap_frames(ev):
                if r[6] == 0x02:  # SYN without ACK
                    pair_ports.setdefault((r[1], r[2]), set()).add(r[5])
            # only benign sources: exclude declared attack episode scanners
            _, labels = GEN.build(fam, seed)
            attack_pairs = set()
            for e in labels['episodes']:
                if e['intent'] == 'attack' and e.get('target'):
                    attack_pairs.add((GEN.ipb(e['scanner']), GEN.ipb(e['target'])))
            for pair, ports in pair_ports.items():
                if pair not in attack_pairs:
                    worst = max(worst, len(ports))
        return worst

    def test_normal_sessions_fanout_capped(self):
        self.assertLessEqual(self.max_distinct_ports_per_pair('normal-sessions'), 4)

    def test_nat_nonshared_fanout_capped(self):
        ev, labels = GEN.build('nat-shared-source', 0)
        nat = GEN.ipb('192.0.2.20'); tgt = GEN.ipb('198.51.100.20')
        pair_ports = {}
        for r in read_pcap_frames(ev):
            if r[6] == 0x02 and (r[1], r[2]) != (nat, tgt):
                pair_ports.setdefault((r[1], r[2]), set()).add(r[5])
        self.assertTrue(pair_ports)
        self.assertLessEqual(max(len(v) for v in pair_ports.values()), 4)
        # shared target retains its designed FP pressure: union >= 8 distinct
        shared = {r[5] for r in read_pcap_frames(ev) if r[6] == 0x02 and (r[1], r[2]) == (nat, tgt)}
        self.assertGreaterEqual(len(shared), 8)

    def test_attack_background_fanout_capped(self):
        for fam in ('fast-vertical-syn', 'slow-syn', 'horizontal-syn', 'xmas'):
            self.assertLessEqual(self.max_distinct_ports_per_pair(fam), 4)


class ChecksumTests(unittest.TestCase):
    def test_all_frames_valid_checksums(self):
        for fam in GEN.FAMILIES:
            ev, _ = GEN.build(fam, 0)
            for _, frame in ev:
                verify_checksums(frame)


class SchemaTests(unittest.TestCase):
    def test_label_schema_fields(self):
        for fam in GEN.FAMILIES:
            _, labels = GEN.build(fam, 1)
            for k in ('capture_id', 'generator', 'spec_version', 'seed', 'family',
                      'family_index', 'epoch_base_s', 'duration_s', 'episodes', 'split'):
                self.assertIn(k, labels, (fam, k))
            self.assertEqual(labels['capture_id'], '%s-s1' % fam)
            for e in labels['episodes']:
                for k in ('episode_id', 'campaign_id', 'intent', 'family', 'scanner',
                          'first_probe_ns', 'last_probe_ns', 'technique', 'provenance'):
                    self.assertIn(k, e, (fam, k))
            if fam in GEN.BENIGN:
                self.assertIn('benign_units', labels)

    def test_attack_duration_margin(self):
        _, labels = GEN.build('slow-syn', 0)
        ep = labels['episodes'][0]
        span_s = (ep['last_probe_ns'] - labels['epoch_base_s'] * 1_000_000_000) / 1e9
        self.assertEqual(labels['duration_s'], int(span_s) + 600)


if __name__ == '__main__':
    unittest.main()
