"""Contract tests for the v2 selection detector (protocol "Detector contract").

These are classifier/state-semantics tests against the frozen contract and
the frozen synthetic corpus; they contain no performance claims.
"""
import importlib.util, tempfile, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent
def _load(name, rel):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

DET = _load('v2_detector', 'research/v2/detectors/v2_detector.py')
GEN = _load('synthetic_corpus', 'research/v2/generators/synthetic_corpus.py')


def gen_pcap(fam, seed):
    ev, labels = GEN.build(fam, seed)
    tmp = tempfile.NamedTemporaryFile(suffix='.pcap', delete=False)
    GEN.write_pcap(tmp.name, ev)
    return tmp.name, labels


def run_trace(fam, seed, W, T):
    path, labels = gen_pcap(fam, seed)
    alerts, summary = DET.run(path, W, T)
    return alerts, summary, labels


class ClassifierTests(unittest.TestCase):
    def test_syn_mask(self):
        self.assertEqual(DET.classify(0x02), 'syn')
        self.assertEqual(DET.classify(0x0a), 'syn')   # SYN+PSH: SYN set, ACK clear
        self.assertEqual(DET.classify(0x42), 'syn')   # ECE ignored
        self.assertEqual(DET.classify(0xc2), 'syn')   # CWR+ECE ignored
        self.assertIsNone(DET.classify(0x12))         # SYN+ACK negative
        self.assertIsNone(DET.classify(0x10))         # bare ACK

    def test_flag_family_masks(self):
        self.assertEqual(DET.classify(0x01), 'fin')
        self.assertEqual(DET.classify(0x00), 'null')
        self.assertEqual(DET.classify(0x29), 'xmas')
        self.assertIsNone(DET.classify(0x11))         # FIN+ACK is negative
        self.assertIsNone(DET.classify(0x19))         # FIN+PSH+ACK
        self.assertEqual(DET.classify(0x41), 'fin')   # ECE ignored
        self.assertIsNone(DET.classify(0x04))         # RST


class WindowAndThresholdTests(unittest.TestCase):
    def det(self, W=60, T=3):
        return DET.V2Detector(W, T)

    def feed(self, det, rows):
        for r in rows:
            det.process(*r)

    def test_inclusive_window_boundary(self):
        s, t = b'\x01\x01\x01\x01', b'\x02\x02\x02\x02'
        base = 1_000_000_000_000
        # probes at base, base+5s, base+10s: at the third, the first sits
        # exactly at t-W and must still count (inclusive [t-W, t]) -> fires
        d = self.det(W=10, T=3)
        self.feed(d, [(base, 1, s, t, 40000, 1000, 0x02, 'ipv4'),
                      (base + 5_000_000_000, 2, s, t, 40001, 1001, 0x02, 'ipv4'),
                      (base + 10_000_000_000, 3, s, t, 40002, 1002, 0x02, 'ipv4')])
        self.assertEqual(len(d.alerts), 1)
        # third probe 1 ns later: the first is now outside -> 2 distinct, no fire
        d2 = self.det(W=10, T=3)
        self.feed(d2, [(base, 1, s, t, 40000, 1000, 0x02, 'ipv4'),
                       (base + 5_000_000_000, 2, s, t, 40001, 1001, 0x02, 'ipv4'),
                       (base + 10_000_000_001, 3, s, t, 40002, 1002, 0x02, 'ipv4')])
        self.assertEqual(len(d2.alerts), 0)

    def test_retransmission_reference_counts(self):
        d = self.det(W=10, T=2)
        s, t = b'\x01\x01\x01\x01', b'\x02\x02\x02\x02'
        base = 1_000_000_000_000
        # retransmitted identical probe twice: distinct count stays 1
        self.feed(d, [(base, 1, s, t, 40000, 80, 0x02, 'ipv4'),
                      (base + 1_000_000, 2, s, t, 40000, 80, 0x02, 'ipv4')])
        self.assertEqual(len(d.alerts), 0)
        # add a second distinct port: fires once
        self.feed(d, [(base + 2_000_000, 3, s, t, 40000, 81, 0x02, 'ipv4')])
        self.assertEqual(len(d.alerts), 1)
        # after the window slides past the first port (both copies), the
        # refcount hits zero: a fresh pair with a new port does not fire (2 needed)
        self.feed(d, [(base + 11_000_000_000, 4, s, t, 40000, 82, 0x02, 'ipv4')])
        self.assertEqual(len(d.alerts), 1)

    def test_rearm_requires_gap_strictly_greater_than_w(self):
        d = self.det(W=10, T=2)
        s, t = b'\x01\x01\x01\x01', b'\x02\x02\x02\x02'
        base = 1_000_000_000_000
        def two_probes(t0, n):
            return [(t0, n, s, t, 40000, 80, 0x02, 'ipv4'),
                    (t0 + 1_000_000, n + 1, s, t, 40000, 81, 0x02, 'ipv4')]
        self.feed(d, two_probes(base, 1))
        self.assertEqual(len(d.alerts), 1)
        # gap exactly W: NOT strictly greater -> no re-arm -> no new alert
        self.feed(d, two_probes(base + 10_000_000_000, 3))
        self.assertEqual(len(d.alerts), 1)
        # gap strictly > W: re-arm -> second alert on the same key
        self.feed(d, two_probes(base + 20_000_000_001 + 1_000_000, 5))
        self.assertEqual(len(d.alerts), 2)
        self.assertEqual(d.alerts[1]['key_fire_index'], 2)

    def test_unsorted_input_rejected(self):
        d = self.det()
        s, t = b'\x01\x01\x01\x01', b'\x02\x02\x02\x02'
        d.process(2_000_000_000, 1, s, t, 40000, 80, 0x02)
        with self.assertRaises(ValueError):
            d.process(1_000_000_000, 2, s, t, 40000, 81, 0x02)

    def test_state_cap_exhaustion_visible(self):
        d = self.det(W=60, T=2)
        DET_mod_cap = DET.MAX_ACTIVE_KEYS
        try:
            DET.MAX_ACTIVE_KEYS = 3
            s = b'\x01\x01\x01\x01'
            with self.assertRaises(DET.StateCapExhausted):
                for i in range(10):
                    d.process(1_000_000_000 + i, i + 1, s,
                              bytes([2, 2, 2, i]), 40000, 80, 0x02)
        finally:
            DET.MAX_ACTIVE_KEYS = DET_mod_cap


class CorpusDetectionTests(unittest.TestCase):
    def test_fast_vertical_alert_identity(self):
        alerts, summary, labels = run_trace('fast-vertical-syn', 0, 60, 10)
        ep = labels['episodes'][0]
        va = [a for a in alerts if a['direction'] == 'vertical' and a['family'] == 'syn']
        self.assertEqual(len(va), 1)
        self.assertEqual(va[0]['scanner'], ep['scanner'])
        self.assertEqual(va[0]['target'], ep['target'])
        self.assertGreaterEqual(va[0]['distinct_count'], 10)  # count recorded at crossing = T
        self.assertFalse(summary['caps_exhausted'])

    def test_threshold_edge_corners(self):
        # seed 0: span <= 10s, 20 ports -> alerts at (10,20); seed 1: span > 10s -> not
        a0, _, _ = run_trace('threshold-edge-syn', 0, 10, 20)
        a1, _, _ = run_trace('threshold-edge-syn', 1, 10, 20)
        self.assertTrue(any(a['direction'] == 'vertical' for a in a0))
        self.assertFalse(any(a['direction'] == 'vertical' for a in a1))
        # seed 2: 5 ports within 300s -> alerts at (300,5); seed 3: span > 300s -> not
        a2, _, _ = run_trace('threshold-edge-syn', 2, 300, 5)
        a3, _, _ = run_trace('threshold-edge-syn', 3, 300, 5)
        self.assertTrue(any(a['direction'] == 'vertical' for a in a2))
        self.assertFalse(any(a['direction'] == 'vertical' for a in a3))

    def test_horizontal_family_alert(self):
        alerts, _, labels = run_trace('horizontal-syn', 0, 60, 10)
        ep = labels['episodes'][0]
        ha = [a for a in alerts if a['direction'] == 'horizontal' and a['family'] == 'syn']
        self.assertTrue(ha)
        self.assertEqual(ha[0]['target_port'], int(ep['target_port']))
        self.assertEqual(ha[0]['scanner'], ep['scanner'])

    def test_flag_families_detected_under_own_key(self):
        for fam in ('fin', 'null', 'xmas'):
            alerts, _, _ = run_trace(fam, 0, 60, 10)
            self.assertTrue(any(a['family'] == fam for a in alerts), fam)

    def test_repeated_bursts_rearm_per_burst(self):
        alerts, _, labels = run_trace('repeated-vertical-bursts', 0, 60, 10)
        n_bursts = len(labels['episodes'])
        va = [a for a in alerts if a['direction'] == 'vertical']
        self.assertEqual(len(va), n_bursts)  # re-arm per burst, one alert each

    def test_continuous_campaign_single_alert(self):
        # fast-vertical is one continuous campaign: gaps 10-50ms << any W,
        # so no re-arm and exactly one alert at every grid setting.
        alerts, _, _ = run_trace('fast-vertical-syn', 0, 300, 20)
        va = [a for a in alerts if a['direction'] == 'vertical']
        self.assertEqual(len(va), 1)

    def test_slow_syn_is_out_of_scope_stress(self):
        # spec: gap U[120,240]s keeps <=3 probes in the widest window
        # (300s) at every grid T >= 5: zero alerts by design.
        for W in (10, 60, 300):
            for T in (5, 10, 15, 20):
                alerts, _, _ = run_trace('slow-syn', 0, W, T)
                va = [a for a in alerts if a['direction'] == 'vertical']
                self.assertEqual(va, [], (W, T))

    def test_zero_tolerance_controls(self):
        for fam in ('normal-sessions', 'few-port-retries', 'fin-ack-teardown'):
            for W in (10, 60, 300):
                for T in (5, 10, 15, 20):
                    alerts, _, _ = run_trace(fam, 0, W, T)
                    self.assertEqual(alerts, [], (fam, W, T))

    def test_service_discovery_vertical_zero(self):
        for T in (5, 10, 15, 20):
            alerts, _, _ = run_trace('service-discovery', 0, 60, T)
            va = [a for a in alerts if a['direction'] == 'vertical']
            self.assertEqual(va, [], T)


if __name__ == '__main__':
    unittest.main()
