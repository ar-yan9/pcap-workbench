# Synthetic corpus specification v0.1 (FROZEN at check-in)

16 November 2026. Companion to protocol v0.2/A1 and evaluator contract v0.1.
Status: frozen parameter specification. This document exists before any v2
corpus trace is generated. No held-out trace, lab capture or CIC label
influenced any value here; every distribution is fixed from the protocol's
detector grid arithmetic, the pinned detector contract, and the declared
design intent of each family. Changes after first generation require a dated
protocol amendment naming the observed reason, and any trace generated before
such an amendment keeps its original labels and hashes.

Nothing in this file is a result. "Expected" columns state design intent used
to place a family inside or outside supported scope; they are predictions the
experiments test, not measurements.

## 1. Determinism and seed separation

- 30 seeds per family, IDs 0..29. Seeds 0..9 are development, 10..29 held out.
- Sub-seed per (family, seed):
  `sub = int.from_bytes(sha256(b"v2-synth-corpus-v0.1|" + family + b"|" + str(seed)).digest()[:8], "big")`,
  then `rng = random.Random(sub)`. One rng per trace, consumed in the fixed
  field order the generator documents. No wall clock, no os.urandom.
- Trace epoch base: `1700000000 + (seed * 18 + family_index) * 86400` seconds,
  family_index from the fixed numbering in sections 3-4 (0..17). Each
  (family, seed) pair gets its own day, so traces never share a timestamp
  range even for the longest spans; timestamps remain synthetic.
- 18 families/units x 30 seeds = 540 traces total, matching the protocol.
- Generated pcaps: Ethernet linktype (1), microsecond timestamp resolution
  stored as integer nanoseconds internally, valid IPv4 and TCP checksums
  computed by the generator. Deterministic bytewise output: regenerating a
  trace from the same spec version and seed reproduces the identical file
  SHA-256, which the manifest records.
- Generator version string `v2-synth-corpus-v0.1` is embedded in every label
  record. A spec change bumps the version string and the sub-seed prefix.

## 2. Detector grid anchors (arithmetic, not results)

Grid: W in {10, 60, 300} seconds, T in {5, 10, 15, 20}; horizontal H = T by
declared convention. For evenly spaced vertical probes the frozen rule alerts
iff at least T distinct ports arrive with spacing <= W/(T-1):

- Strictest setting (10, 20): spacing <= 10/19 = 0.5263 s.
- Default (60, 10): spacing <= 60/9 = 6.667 s.
- Loosest (300, 5): spacing <= 300/4 = 75 s.
- Re-arm: a fresh alert for the same active key requires a gap strictly
  greater than W since its last qualifying probe.

Family timing below is placed against these three corners so the corpus
exercises inside-edge, outside-edge and clear regions of the grid without
any tuning against outputs.

## 3. Attack families (12)

Common: scanner addresses from TEST-NET-1 192.0.2.0/24, targets from
TEST-NET-2 198.51.100.0/24, background hosts from TEST-NET-3 203.0.113.0/24.
Port pool P: 1..1024 plus {1433, 1521, 2049, 2375, 3000, 3306, 3389, 4444,
5432, 5900, 6379, 8000, 8080, 8443, 9000, 9200, 27017} (1,041 values),
sampled without replacement within an episode. Every attack trace also
carries background traffic per section 5.

| # | family | structure | timing | placement vs grid |
| --- | --- | --- | --- | --- |
| 0 | fast-vertical-syn | 1 scanner -> 1 target, 60..120 distinct ports (uniform) | gap U[0.01, 0.05] s | alerts at all 12 settings (0.05 << 0.5263) |
| 1 | threshold-edge-syn | 1 scanner -> 1 target, exactly T-corner distinct ports, variant = seed mod 4 | v0: (W,T)=(10,20), spacing 0.50 s (inside); v1: same corner, 0.55 s (outside); v2: (300,5), 70 s (inside); v3: same corner, 80 s (outside) | inside variants alert at the named corner, outside variants do not; both alert/miss behavior at other settings is whatever the rule computes |
| 2 | slow-syn | 1 scanner -> 1 target, 15..25 distinct ports | gap U[120, 240] s | below all settings (min gap 120 > 75): stress family, out of supported scope |
| 3 | horizontal-syn | 1 scanner, 1 fixed port, H distinct hosts, H uniform in {8, 16, 24} | gap U[0.02, 0.10] s | alerts where T <= H: H=8 -> T in {5}; H=16 -> T in {5,10,15}; H=24 -> all T |
| 4 | fin | as fast-vertical-syn, flags = 0x01 | gap U[0.01, 0.05] s | supported scope, family classification under test |
| 5 | null | as fast-vertical-syn, flags = 0x00 | gap U[0.01, 0.05] s | supported scope |
| 6 | xmas | as fast-vertical-syn, flags = 0x29 | gap U[0.01, 0.05] s | supported scope |
| 7 | repeated-vertical-bursts | 3..5 bursts (uniform), each 25..40 probes at gap U[0.02, 0.10] s; inter-burst gap per burst boundary drawn U[400, 500] s | re-arm boundary: 400 > max W = 300, so every burst is a separate episode at every setting | supported scope; repeated-episode coverage |
| 8 | repeated-horizontal-bursts | as 7, horizontal: each burst 8..16 hosts on one port | as 7 | supported scope |
| 9 | mixed-families | 30..50 probes interleaving SYN and FIN to one target, order shuffled by rng | gap U[0.01, 0.05] s | labeled ambiguous at labeling time (contract section 2); excluded from primary metrics, reported separately |
| 10 | distributed-syn | K uniform in {8..16} scanner addresses, each probing 3..4 distinct ports on one shared target | per-scanner gap U[0.5, 2.0] s | no scanner reaches any T: stress family, out of supported scope |
| 11 | udp | 40..80 UDP datagrams, 1 scanner -> 1 target, distinct ports | gap U[0.01, 0.05] s | detector is TCP-only: stress family, out of supported scope |

Trace duration (attack families): episode span + 2 * max(W) = span + 600 s
declared margin, so window edges at capture start/end never clip an episode.
Timestamps start at the trace epoch base.

## 4. Benign units (6)

One benign control trace per (unit, seed). Duration exactly 3600 s each,
giving 30 trace-hours per unit and 180 trace-hours in total (60 development,
120 held out) for the benign-alert-rate denominators of contract section 6.

| # | unit | structure | intent vs detector |
| --- | --- | --- | --- |
| 12 | normal-sessions | 40..120 complete TCP connections (uniform): SYN, SYN/ACK, ACK, 0..8 data segments each way, FIN teardown; 2..6 concurrent | no unanswered-SYN fan-out: no alerts expected |
| 13 | few-port-retries | one source retrying 2..3 distinct ports, 2..4 attempts each, gaps U[1, 10] s | below T at every setting: no alerts expected |
| 14 | approved-admin-scan | one declared admin source (192.0.2.10), 30..60 distinct ports on one host, gap U[0.05, 0.2] s | alerts expected; benign operational control, so matches land in the benign-FP column (contract section 6) |
| 15 | nat-shared-source | one public source address aggregating 8..20 emulated clients, each running 1..4 normal sessions to distinct services; 4..8 of the clients also reach one shared popular target (198.51.100.20), each touching 2..5 distinct ports there | aggregate (source, target) distinct-port count 8..40 can cross T at some settings: honest FP pressure, expected-alert accounting as approved/shared-source, not attack |
| 16 | service-discovery | one host probing ports {22, 80, 443, 8080} on 6..12 hosts of a 203.0.113.0/27 block, gap U[30, 90] s | per-(source, port) count inside any window stays below H = T at every setting: no alerts expected |
| 17 | fin-ack-teardown | 20..40 sessions whose teardown uses FIN/ACK and RST/ACK mixes, plus 2..5 stray retransmitted FIN/ACKs | FIN+ACK is negative by contract: no FIN-family alerts expected |

## 5. Background traffic inside attack traces

Per attack trace: B uniform in {5..20} complete normal sessions (unit 12
structure, hosts from 203.0.113.0/24, never the episode scanner or target),
start times uniform across the trace duration, plus per-probe timing jitter
of plus/minus 2 ms uniform applied after gap sampling. Background never
shares a 4-tuple with episode traffic.

## 6. Labels (schema v0.1, emitted at generation)

One JSON sidecar per trace with: capture_id (`<family>-s<seed>`), generator
version, spec version, seed, family, plus one record per episode:
episode_id (`<capture_id>-e<i>`), intent (attack / benign / ambiguous),
family, scanner, target (vertical) or target_port + target host list
(horizontal), first/last qualifying probe time in integer ns, independently
known technique, provenance (spec version + sub-seed hex). Campaign IDs are
stable across W; per-W segmentation is a derived scoring unit computed at
analysis time, never generated here. UDP/distributed/slow stress episodes
carry intent=attack plus scope=out-of-scope-stress. Approved admin and NAT
units carry intent=benign with the operational-control qualifier.

## 7. Separation and change control

- Development seeds 0..9 may be generated, inspected and used for the
  operating-point selection only after the benign-alert budget amendment is
  dated. Held-out seeds 10..29 are generated only after this spec is checked
  in, and are never inspected for any selection decision.
- No capture publication: generated pcaps stay local; the repository receives
  this spec, the generator, the label schema validator and derived
  hashes/counts only.
- Any parameter change after first generation: dated amendment + version
  bump + new sub-seed prefix; old traces and labels are preserved, never
  regenerated in place.

## Erratum E1, 17 November 2026

Found during pre-results validation of the benign-alert budget (Amendment A2);
no development or held-out evaluation runs had occurred.

1. **normal-sessions (12) and nat-shared-source non-shared sessions.** The
   5-service port pools with uniform host-pair draws allowed, with probability
   of order 1e-6 per trace, one ordered (source, target) pair to accumulate
   all 5 distinct pool ports inside one window, mimicking a vertical scan at
   T = 5. Generation now caps distinct ports per ordered (source, target) pair
   at 4 for benign session traffic (`pick_capped_session` in
   `synthetic_corpus.py`), making the no-alert invariant structural rather
   than statistical. The cap conditions on per-pair history, so it changes
   the joint traffic distribution by design; draws for fresh keys remain
   uniform over the pool, and no distributional equivalence beyond that is
   claimed. Attack-trace background already used a 4-port pool and was never
   affected.
2. **service-discovery (16), "H = T" phrasing.** Written assuming vertical
   (source, target) aggregation only. The frozen v2 detector contract DOES
   define horizontal keys (source, target_port, family) with H = T; see
   Erratum E2 for the resulting reclassification.


## Erratum E2, 17 November 2026

Found while reconciling the frozen "Detector contract to implement before
test runs" (horizontal keys with H = T, flag families) with the benign-alert
budget, before any v2 detector implementation or scoring run.

1. **Horizontal fan-out of benign session traffic.** normal-sessions (12),
   nat-shared-source non-shared sessions (15) and attack-trace background all
   let one (source, port) key accumulate 5+ distinct destinations with small
   probability (for 15's non-shared sessions, near-certainty at T = 5),
   mimicking a horizontal scan. Generation now caps distinct destinations per
   (source, port) at 4 for all benign session traffic, same `pick_capped_session`
   mechanism and joint-distribution caveat as E1. The no-horizontal-alert
   invariant for these units is now structural.
2. **service-discovery (16) reclassified.** Under the frozen horizontal key
   (source, target_port, family) with H = T, this family's 6..12 hosts per
   port can cross H at lower T. That is designed benign pressure: family 16
   is an expected-alert control under horizontal keys (alerts allowed, burden
   bounded per Amendment A2) and remains zero-tolerance under vertical keys
   (2..4 distinct ports per (source, host)). Alerting is permitted, not
   guaranteed, at any given (W, T).
3. **Expected-alert semantics.** Across A2's expected-alert class, an alert
   is allowed burden, never a requirement: nat-shared-source's shared-target
   union (8..40 distinct ports) crosses only T <= the realized union, and
   approved-admin-scan crosses every grid T. Budget accounting binds burden
   at settings where alerts occur.
