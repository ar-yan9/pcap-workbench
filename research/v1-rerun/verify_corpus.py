#!/usr/bin/env python3
"""Verify the published v1.1 corpus against manifest.json.

Extracts data/corpus-seeds-0-29.tar.gz to a temporary directory and compares
every fixture's sha256 against the manifest; also checks the anchor fixture,
which ships inside the frozen revision-3 ZIP at the repo root. Exit 0 when
everything matches.

    python3 verify_corpus.py
"""
import hashlib
import json
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
DATA = HERE / 'data'
TARBALL = DATA / 'corpus-seeds-0-29.tar.gz'
FROZEN_ZIP = HERE.parent.parent / '1-portscan-study-v3.zip'
MEMBERS = ['eval.pcap', 'eval.labels', 'eval.labels.events.json']


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    manifest = json.loads((HERE / 'manifest.json').read_text())
    fixtures = manifest['fixtures']
    failures = []
    checked = 0

    with tempfile.TemporaryDirectory() as tmp:
        with tarfile.open(TARBALL) as tar:
            tar.extractall(tmp, filter='data')
        with zipfile.ZipFile(FROZEN_ZIP) as z:
            anchor_bytes = {m: z.read('portscan-study-v3/data/' + m) for m in MEMBERS}
        for name, hashes in sorted(fixtures.items()):
            anchor = name == 'seed-%d' % manifest['anchor_seed']
            for member in MEMBERS:
                expected = hashes[member]
                if anchor:
                    actual = hashlib.sha256(anchor_bytes[member]).hexdigest()
                else:
                    path = Path(tmp) / name / member
                    if not path.exists():
                        failures.append('%s/%s: missing' % (name, member))
                        continue
                    actual = sha256(path)
                checked += 1
                if actual != expected:
                    failures.append('%s/%s: %s != %s' % (name, member, actual, expected))

    if failures:
        print('CORPUS VERIFICATION FAILED (%d problems):' % len(failures))
        for f in failures:
            print(' -', f)
        return 1
    print('corpus verification OK: %d files match manifest.json' % checked)
    return 0


if __name__ == '__main__':
    sys.exit(main())
