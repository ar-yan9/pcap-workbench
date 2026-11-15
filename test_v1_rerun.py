"""Hermetic tests for the v1.1 seeded generator (research/v1-rerun).

The legacy regression anchors v1.1 to the frozen revision-3 fixture: default
arguments must reproduce data/seed-20261027/ byte-exact, so the strengthened
evaluation extends the published study instead of replacing it. Variation-mode
tests check family-preserving invariants and determinism. No detector metrics
are asserted here; corpus metrics come from real evaluation runs only.
"""

import json
import struct
import zipfile
import subprocess
import sys
import tempfile
import unittest
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parent
GENERATOR = REPO / 'research' / 'v1-rerun' / 'generators' / 'gen_capture_v1_1.py'
FROZEN_ZIP = REPO / '1-portscan-study-v3.zip'


def frozen_member(name):
    """Anchor fixture bytes from the published frozen revision-3 ZIP."""
    with zipfile.ZipFile(FROZEN_ZIP) as z:
        return z.read('portscan-study-v3/data/' + name)

EXPECTED_COUNTS = {'NORMAL': 780, 'FAST': 50, 'SLOW': 12, 'DIST': 50,
                   'UDPSCAN': 20, 'V6FAST': 25, 'ADMIN': 24, 'RETRY': 25}


def generate(workdir, name, *args):
    pcap = Path(workdir) / (name + '.pcap')
    labels = Path(workdir) / (name + '.labels')
    subprocess.run([sys.executable, str(GENERATOR), str(pcap), str(labels), *args],
                   check=True, capture_output=True, text=True)
    return pcap, labels


def read_frames(pcap):
    data = Path(pcap).read_bytes()
    assert data[:4] == struct.pack('<I', 0xa1b2c3d4), 'not a classic little-endian pcap'
    frames = []
    pos = 24
    while pos < len(data):
        sec, usec, incl, orig = struct.unpack_from('<IIII', data, pos)
        assert incl == orig, 'truncated capture record'
        frames.append(data[pos + 16:pos + 16 + incl])
        pos += 16 + incl
    return frames


def dport(frame):
    """Destination port of a TCP/UDP frame built by this generator."""
    kind = struct.unpack('!H', frame[12:14])[0]
    if kind == 0x0800:
        ihl = (frame[14] & 0x0F) * 4
        return struct.unpack('!H', frame[14 + ihl + 2:14 + ihl + 4])[0]
    if kind == 0x86DD:
        return struct.unpack('!H', frame[14 + 40 + 2:14 + 40 + 4])[0]
    raise AssertionError('unexpected ethertype %#x' % kind)


def labeled_dports(pcap, labels):
    frames = read_frames(pcap)
    names = [line.split('\t')[1].strip() for line in Path(labels).read_text().splitlines()]
    assert len(frames) == len(names)
    out = {}
    for frame, name in zip(frames, names):
        out.setdefault(name, []).append(dport(frame))
    return out


class LegacyRegressionTests(unittest.TestCase):
    def test_default_arguments_reproduce_frozen_fixture_byte_exact(self):
        with tempfile.TemporaryDirectory() as workdir:
            pcap, labels = generate(workdir, 'eval')
            self.assertEqual(pcap.read_bytes(), frozen_member('eval.pcap'))
            self.assertEqual(labels.read_bytes(), frozen_member('eval.labels'))
            self.assertEqual(Path(str(labels) + '.events.json').read_bytes(),
                             frozen_member('eval.labels.events.json'))

    def test_explicit_legacy_seed_reproduces_frozen_fixture(self):
        with tempfile.TemporaryDirectory() as workdir:
            pcap, labels = generate(workdir, 'eval', '20261027')
            self.assertEqual(pcap.read_bytes(), frozen_member('eval.pcap'))


class VariationTests(unittest.TestCase):
    def test_deterministic_per_seed_and_distinct_across_seeds(self):
        with tempfile.TemporaryDirectory() as workdir:
            a_pcap, a_labels = generate(workdir, 'a', '1', 'vary')
            b_pcap = Path(workdir) / 'b.pcap'
            b_labels = Path(workdir) / 'b.labels'
            subprocess.run([sys.executable, str(GENERATOR), str(b_pcap), str(b_labels),
                            '1', 'vary'], check=True, capture_output=True)
            self.assertEqual(a_pcap.read_bytes(), b_pcap.read_bytes())
            self.assertEqual(a_labels.read_bytes(), b_labels.read_bytes())
            c_pcap, _ = generate(workdir, 'c', '2', 'vary')
            self.assertNotEqual(a_pcap.read_bytes(), c_pcap.read_bytes())

    def test_family_structure_preserved(self):
        with tempfile.TemporaryDirectory() as workdir:
            pcap, labels = generate(workdir, 'eval', '7', 'vary')
            names = [line.split('\t')[1].strip()
                     for line in Path(labels).read_text().splitlines()]
            self.assertEqual(dict(Counter(names)), EXPECTED_COUNTS)
            units = json.loads(Path(str(labels) + '.events.json').read_text())
            by_id = {unit['id']: unit for unit in units}
            self.assertEqual(set(by_id), set(EXPECTED_COUNTS))
            for unit in units:
                self.assertGreater(unit['end_ns'], unit['start_ns'])
            # FAST stays a ~20 s burst; SLOW stays a ~110 s crawl.
            self.assertLess(by_id['FAST']['end_ns'] - by_id['FAST']['start_ns'], 25 * 10 ** 9)
            self.assertGreater(by_id['SLOW']['end_ns'] - by_id['SLOW']['start_ns'], 100 * 10 ** 9)

    def test_port_semantics_preserved(self):
        with tempfile.TemporaryDirectory() as workdir:
            pcap, labels = generate(workdir, 'eval', '11', 'vary')
            ports = labeled_dports(pcap, labels)
            self.assertEqual(len(set(ports['FAST'])), 50)
            self.assertEqual(len(set(ports['SLOW'])), 12)
            self.assertEqual(len(set(ports['UDPSCAN'])), 20)
            self.assertEqual(len(set(ports['V6FAST'])), 25)
            # 12 probed service ports plus the client port 44444 as the
            # destination of each labeled server ACK reply.
            self.assertEqual(len(set(ports['ADMIN'])), 13)
            # RETRY must remain a single-port retransmission pattern.
            self.assertEqual(len(set(ports['RETRY'])), 1)
            # DIST keeps five distinct ports per scenario.
            self.assertEqual(len(set(ports['DIST'])), 5)

    def test_variation_actually_varies_ports(self):
        with tempfile.TemporaryDirectory() as workdir:
            pcap1, labels1 = generate(workdir, 'one', '3', 'vary')
            pcap2, labels2 = generate(workdir, 'two', '4', 'vary')
            fast1 = labeled_dports(pcap1, labels1)['FAST']
            fast2 = labeled_dports(pcap2, labels2)['FAST']
            self.assertNotEqual(fast1, fast2)

    def test_checksums_valid_under_variation(self):
        with tempfile.TemporaryDirectory() as workdir:
            pcap, labels = generate(workdir, 'eval', '5', 'vary')
            for frame in read_frames(pcap):
                kind = struct.unpack('!H', frame[12:14])[0]
                if kind == 0x0800:
                    ihl = (frame[14] & 0x0F) * 4
                    header = frame[14:14 + ihl]
                    total = struct.unpack('!H', header[2:4])[0]
                    self.assertEqual(len(frame), 14 + total)
                    check = sum(struct.unpack('!%dH' % (ihl // 2), header))
                    check = (check >> 16) + (check & 0xffff)
                    check += check >> 16
                    self.assertEqual(check & 0xffff, 0xffff, 'bad IPv4 header checksum')


if __name__ == '__main__':
    unittest.main()

class CorpusRunnerTests(unittest.TestCase):
    """Mini corpus run (3 seeds) through the real runner: output shape and
    agreement with the frozen anchor evaluation. Full 30-seed runs happen via
    corpus_runner.py itself; this test guards the aggregation plumbing."""

    def test_mini_corpus(self):
        import subprocess, tempfile, shutil
        runner = REPO / 'research' / 'v1-rerun' / 'corpus_runner.py'
        with tempfile.TemporaryDirectory() as workdir:
            # Mini run fully sandboxed: canonical corpus artifacts untouched.
            data_dir = Path(workdir) / 'data'
            results_dir = Path(workdir) / 'results'
            manifest = Path(workdir) / 'manifest.json'
            subprocess.run([sys.executable, str(runner), '--seeds', '101', '102', '103',
                            '--data-dir', str(data_dir), '--results-dir', str(results_dir),
                            '--manifest', str(manifest)],
                           check=True, capture_output=True, text=True)
            summary = json.loads((results_dir / 'corpus_summary.json').read_text())
            self.assertEqual(summary['seeds'], [101, 102, 103])
            self.assertEqual(len(summary['settings']), 8)
            runs = json.loads((results_dir / 'corpus_runs.json').read_text())
            for seed in ('101', '102', '103'):
                self.assertIn(seed, runs['runs'])
                self.assertEqual(runs['runs'][seed]['records'], 986)
            anchor = runs['anchor_seed_20261027']
            # The anchor run must match the evaluation shipped in the frozen ZIP.
            import zipfile
            with zipfile.ZipFile(REPO / '1-portscan-study-v3.zip') as z:
                names = [n for n in z.namelist() if n.endswith('results/evaluation.json')]
                self.assertEqual(len(names), 1)
                frozen_eval = json.loads(z.read(names[0]))
            # Published corpus rows drop per-alert match details by design.
            for row in frozen_eval['results']:
                row.pop('matches', None)
            self.assertEqual(json.dumps(anchor, sort_keys=True),
                             json.dumps(frozen_eval, sort_keys=True))
