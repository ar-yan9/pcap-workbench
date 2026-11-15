# v1-rerun: strengthened v1 evaluation

This directory extends the published v1 port-scan study with a real,
repeatable multi-seed evaluation. It changes nothing the v1 paper reported:
the frozen detector, the frozen fixture and the frozen eight-setting grid are
reused verbatim. What it adds is *volume of evidence* — the same evaluation
run across many freshly generated captures instead of one.

## What is frozen and what is new

Frozen (reused byte-exact, no edits):

- the v1 detector (`evaluated_workbench.py`, pinned at commit `063ad1d`),
- the original seed-20261027 fixture, kept here as a regression anchor in
  `data/seed-20261027/`,
- the eight evaluation settings and the strict one-to-one matching scorer
  (`evaluate.py`).

New (clearly marked `[v1.1]` in code):

- `generators/gen_capture_v1_1.py` — the frozen generator with two
  argv-controlled additions: a seed parameter and an optional `vary` mode.

## The v1.1 generator

    python3 gen_capture_v1_1.py out.pcap out.labels [seed] [vary]

- With no extra arguments it reproduces the frozen seed-20261027 fixture
  byte-exact (pcap, labels, and events sidecar). `test_v1_rerun.py` enforces
  this, so the strengthened study can never silently drift from the published
  one.
- `vary` mode keeps every scenario's family, packet count, duration, and
  label structure identical, but re-randomizes the port choices, source
  addresses, and sub-second timing jitter from an independent per-seed
  stream. Attack stays attack, benign-lookalike stays benign-lookalike; only
  the surface details move.
- Generation is deterministic per seed: rerunning seed N always yields the
  same bytes, and the seed stream is fixed across machines and Python
  processes (string-seeded `random.Random`, not process-hash-dependent).

All addresses remain documentation prefixes (TEST-NET-1/2/3, 2001:db8).
No real captures are ever used or published.

## Corpus layout (C1)

The legacy anchor fixture ships inside the frozen revision-3 ZIP
(`1-portscan-study-v3.zip` at the repo root); the generator's regression
tests and the corpus runner read those exact published bytes from the ZIP.
The 30 varied fixtures ship as
`data/corpus-seeds-0-29.tar.gz` (deterministic archive: sorted members, zeroed
metadata); `verify_corpus.py` extracts it and checks every fixture's sha256
against `manifest.json`. Because generation is seed-deterministic, the same
fixtures can also be regenerated from scratch with `corpus_runner.py`. Metrics
per fixture come from running the frozen evaluator; aggregate summaries (with
bootstrap confidence intervals) are produced by the corpus runner and live in
`results/`.

Numbers in the v1.1 manuscript come only from committed artifacts under
`results/`. Anything else is a draft, not a result.
