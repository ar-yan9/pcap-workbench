# Reproducibility evidence note, 25 November 2026

For the paper's reproducibility claims. All events below are real, recorded
in run logs; local commits 48851a8 and 4ab901b on research/v2.

On 25 November 2026 the working sandbox was fully wiped (all local files
lost). Recovery re-ran the entire pipeline from public sources and the
frozen in-repo specifications:

1. **Binary reproduction.** Snort 3.13.2.0 rebuilt byte-identical for the
   5th independent time (sha256 f38f8adf7a66509974162cc37021644e1580860332573d19aa0f0a1af494db7c).
   Zeek 8.0.11 (Release build, flags per PROVISIONING-v0.1.md) reproduced
   byte-identical on an independent rebuild on a different day
   (sha256 f05433a7c88de8b9a70b64f16089c57508aa6a5084cd0ca47454292619b5fe4c).
   Source tarball digests re-verified at every rebuild (libdaq 136deba7...,
   snort 29836752..., zeek 2679a5f1...; the Zeek tarball digest agrees
   across download.zeek.org and the GitHub release asset).
2. **Corpus regeneration.** The frozen deterministic generator
   re-derived all 180 development traces; the frozen development selection
   re-run still selects (W=300 s, T=5) at development recall 0.975,
   matching dev-selection-2026-11-18.json.
3. **Result reproduction.** Re-running the real engines over the
   regenerated corpus reproduced both baseline raw records BYTE-IDENTICAL:
   dev-baselines-2026-11-22.json (git blob 55dce21e41d931da33d0f728c0a03573bbc70319)
   and dev-baselines-sensitivity-2026-11-22.json (git blob
   98db48439493effa76c44cd3a8199b5831c5ec90), across independent engine
   builds on different days.
4. **Activation record.** The activation re-run reproduced every
   load-bearing field of activation-2026-11-22.json (control packet
   digests, checksum verification counts, per-engine alert counts and
   records, binary digests, scanner pins). Its git blob differs
   (551be3e2... vs faad016e...) only in run metadata the runner embeds:
   wall-clock start/end timestamps, the repo revision, and the dirty flag.
   Byte-identical reproduction of that file is impossible by construction;
   content-level reproduction is what the record supports.
5. **Authored-file recovery.** The seven authored files (protocol with
   Amendment A3, provisioning record, runners, caveats, drafts, readiness
   review) were restored byte-identical from authoring transcripts, each
   verified against its previously recorded git blob sha.

Claim discipline: this note documents reproduction of builds and generated
records. It is not evidence about held-out performance (seeds 10..29 remain
untouched) and changes no frozen artifact.
