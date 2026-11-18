# Development operating-point selection rule

Version 1.0, 18 November 2026. Frozen before any development scoring run.
Governs selection of the v2 detector's (W, T) operating point per protocol
section "Episode labels and deterministic matching" and Amendments A2/A2.1.
Held-out seeds 10..29 are not generated or inspected for this procedure.

## Inputs

- Frozen generator spec v0.1 (+ Errata E1/E2) and generator at the recorded
  commit; development traces are generated fresh for seeds 0..9 only.
- The v2 selection detector (`research/v2/detectors/v2_detector.py`) at the
  recorded commit.
- The frozen matcher (`research/v2/adapters/matching.py`) and evaluator
  contract v0.1.
- The benign-alert budget: Amendment A2 as scoped per key dimension by
  Amendment A2.1.

## Grid

W in {10, 60, 300} seconds, T in {5, 10, 15, 20}; H = T by the declared
convention. 12 candidate settings, all evaluated on identical inputs.

## Procedure

1. Generate development traces for all 18 families, seeds 0..9, recording
   the generator commit, spec blob SHA-256 and output manifest SHA-256s.
2. Run the detector at every grid setting on every development trace;
   record the run manifest per protocol (argument vector, seed/split,
   input/output SHA-256, counters). A failed or cap-exhausted run is
   failed/incomplete, never a zero-alert success.
3. Budget filter (per key dimension, over all dev benign traces):
   - Zero-tolerance: normal-sessions (12), few-port-retries (13),
     fin-ack-teardown (17) under both dimensions; service-discovery (16)
     under vertical keys. Any alert disqualifies the setting.
   - Expected-alert: approved-admin-scan (14) vertical; nat-shared-source
     (15) vertical at the shared target; service-discovery (16) horizontal.
     Alerts are allowed; duplicates within a label-derived contiguous
     campaign segment (maximal run of episode probes with consecutive gaps
     <= W) are burden; budget is 0 such duplicates per unit.
4. Selection: among settings passing step 3, maximal development episode
   recall over attack episodes (families in supported scope: vertical SYN,
   horizontal SYN, FIN, NULL, Xmas, repeated bursts, threshold-edge, mixed;
   slow-syn, distributed and UDP are named stress/out-of-scope and are
   reported separately, never counted in selection recall). Recall uses the
   frozen matcher at campaign level; ambiguous episodes are excluded per
   the evaluator contract.
5. Tie-break, in order: (a) fewer expected-class alerts per benign unit;
   (b) lexicographic (W descending, T descending).
6. If no setting passes step 3, that outcome is the result and is reported;
   the budget is not relaxed after looking at scores.
7. The selected setting, full per-setting recall and burden tables, and all
   manifests are frozen in `research/v2/results/raw/` with a dated record
   before any held-out generation.

## Explicit non-goals

No held-out seeds, no lab captures, no CIC data, no baseline tuning. Zeek
and Snort runs are separately labeled comparisons and never tune (W, T).
Development selection is not evidence of held-out performance.
