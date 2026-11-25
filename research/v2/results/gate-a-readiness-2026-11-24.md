# Gate A readiness review, 24 November 2026

Prepared against protocol.md v0.2 "Gates and amendments". Gate A close is a
protocol state change: this review presents evidence and a recommendation;
the close decision rests with the maintainer. All commits named below are
LOCAL (research/v2); remote publication of nine files is pending GitHub 2FA.

## Protocol Gate A criteria

1. **Current tests and frozen evaluator tests/verify pass.**
   Re-verified 24 November 2026 on local head 467bb48: 149/149 unittest
   tests pass (test_workbench, test_v1_rerun, test_v2_activation,
   test_v2_adapters, test_v2_corpus, test_v2_detector, test_v2_matching;
   the suite grew from the original 47+9 as v2 contract/adapter/corpus/
   detector/matching tests were added). Frozen v1 corpus verification:
   `research/v1-rerun/verify_corpus.py` OK, 93 files match manifest.json.
   CI check-runs are green through published head 9e5bc474 (18 Nov); the
   five local commits since (9e70364..467bb48) have no CI signal until
   publication.
2. **Protocol and evaluator contract versioned.**
   protocol.md v0.2 + Amendments A1, A2, A2.1, A3 (A3 frozen 22 Nov before
   its run); evaluator-contract.md versioned alongside.
3. **Pinned engines both pass positive and negative controls.**
   Activation re-run 22 Nov 2026 (results/raw/activation-2026-11-22.json):
   Zeek 8.0.11 (bin sha256 f05433a7...) 1 alert on positive / 0 on
   negative; Snort 3.13.2.0 (bin sha256 f38f8adf...) 1 / 0. Controls
   600-packet positive (sha 444641f7) and 64-packet negative (sha
   f1babb76), TShark checksum-verified. Provisioning record:
   engines/PROVISIONING-v0.1.md.

## Supporting Gate A work (beyond the letter of the gate)

- Evaluator contract + adapters + matcher + compatibility gates: complete,
  test-covered (test_v2_adapters, test_v2_matching).
- Synthetic corpus spec frozen (synthetic-corpus-spec-v0.1.md + Errata
  E1/E2); generator deterministic.
- Benign-alert budget fixed pre-selection (A2, A2.1).
- v2 detector implemented per contract; development operating point
  selected 18 Nov: (W=300 s, T=5), dev campaign recall 0.975
  (results/raw/dev-selection-2026-11-18.json; operating-point-selection.md).
- Baseline comparison at pinned defaults complete 22 Nov
  (dev-baselines-2026-11-22.json: Zeek+packages 0/80, Snort 0/80 attack
  recall, 10 expected-class alerts; zero zero-tolerance violations).
- Amendment A3 sensitivity S1 complete 22 Nov
  (dev-baselines-sensitivity-2026-11-22.json: 33/80 = 0.4125 with only
  private_address_space_is_local=F). Interpretation and claim discipline in
  results/baseline-caveats-2026-11-22.md.
- Paper baseline-results subsection drafted 23 Nov
  (baseline-results-subsection-DRAFT-2026-11-23.md), all prose numbers
  verified against raw JSONs.

## Outstanding before Gate A can be called closed

1. Remote publication of the nine queued files (blocked on GitHub SMS 2FA;
   parent owns the user ask). Publication is not a protocol criterion, but
   the record should be publicly inspectable before the gate is declared
   closed, and CI should confirm green on the published head.
2. Maintainer sign-off on this review.

## Recommendation

Evidence supports closing Gate A once the publication step lands and CI is
green on the published head. Closing Gate A unblocks, under the frozen
protocol: held-out grid/baseline/ablation runs (seeds 10..29, untouched so
far), then Gate B/C work (full detector freeze, corpus provenance audit,
public-capture validation). No held-out data has been generated, read or
scored to date.
