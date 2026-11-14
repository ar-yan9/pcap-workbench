# Evaluator contract v0.1

14 November 2026. Companion to protocol v0.2/A1. Status: draft for Gate A; no
scoring run is authorized by this document, and no held-out data was used to
choose any rule here. Every rule is justified from pinned engine documentation,
the pinned package source, or the published development activation controls.
Changes after first scoring require a dated protocol amendment.

This contract fixes how raw Zeek and Snort 3 outputs become prediction records,
which episode/alert pairs may match, how timing is classified, and what scoring
must report separately. It does not select an operating point, a benign-alert
budget, or generator parameter ranges; those remain separate frozen artifacts.

## 1. Prediction records

Both adapters emit the protocol prediction schema: engine, capture_id,
alert_id, family, direction, scanner, target/group fields, event_time_ns,
decision_time_ns, qualifiers, evidence_reference, raw_record_reference.
alert_id is deterministic from capture_id, source file and raw record position,
so re-parsing the same immutable raw output reproduces the same IDs.

### Zeek (8.0.11 + pinned bro-simple-scan, amendment A1)

Source: notice.log, parsed with its own #separator/#fields/#types header;
unset and empty markers honored. Only Scan::Address_Scan, Scan::Port_Scan and
Scan::Random_Scan become predictions; any other notice is ignored with a count,
never parsed as scan evidence.

Message formats are the five exact forms in the pinned package's
analyze_unique_hostports/generate_notice ("N unique hosts on port P",
"N unique ports on host H", the <=5 multi variants, "N hosts on M ports"),
optional "kk: " knockknock prefix, and the "%dm%ds" duration of the installed
duration_to_mins_secs. A scan notice outside these forms raises an error; the
adapter never guesses. Direction comes from the notice type and must agree
with the parsed message; the src field must equal the message scanner. Targets
are recovered only from the message: single host, single port, or the
enumerated <=5 lists. Random_Scan carries counts only, no target identities.
Engine-reported count, duration, local/remote side, knockknock flag and
suppress_for are kept in qualifiers. event_time_ns is the notice ts; it is an
emission timestamp, not a decision time (section 4).

### Snort 3 (3.13.2.0 port_scan inspector)

Source: alert_json output, one JSON object per line. The gid 122 sid table is
frozen from the pinned build's own port_scan module help saved at provisioning:
sid classes portscan (vertical), portsweep (horizontal), with decoy, filtered
and distributed qualifiers, across tcp/udp/ip/icmp, plus protocol scans and
open port. The alert msg must equal the documented sid message and the proto
must agree with the sid class; undocumented sids, contradictions and malformed
lines raise. Other gids are ignored with a count.

An alert references its triggering packet: scanner is src_addr; a portscan
alert's target_host is the triggering packet's dst_addr; a portsweep alert's
target_port is the triggering packet's dst_port. A sweep's scanned group is
not enumerable from one alert and is recorded as unknown-group; it is never
reconstructed from ground truth. event_time_ns is the packet epoch seconds
plus the timestamp fraction. decision_time_ns stays unset for both engines.

## 2. Family and direction compatibility

Both baselines emit family=generic-scan: neither pinned baseline reports the
probe technique (SYN/FIN/NULL/Xmas). Compatibility is therefore directional,
not technical:

- A vertical prediction (Zeek Port_Scan, Snort portscan) is a candidate for
  vertical label episodes: vertical SYN at any rate, FIN, NULL, Xmas.
- A horizontal prediction (Address_Scan, portsweep) is a candidate for
  horizontal SYN episodes.
- A random-aggregate prediction (Zeek Random_Scan) is a candidate for any
  same-scanner episode, flagged random-aggregate; primary recall is reported
  both including and excluding these edges.
- udp, icmp, ip protocol, distributed and open-port classes are outside
  supported scope: they produce no candidates and are recorded as unmatched
  with reason unsupported-direction. Decoy/filtered tcp qualifiers are
  candidates flagged in qualifiers.

Mixed-family episodes whose probes span directions are labeled ambiguous at
labeling time, not resolved by the evaluator.

## 3. Identity, target and group gates

A candidate requires, in order: same capture_id; exact scanner equality;
direction compatibility (section 2); target/group agreement. For vertical
episodes, the prediction's single host must equal the episode target, or the
episode target must be in the prediction's enumerated host list. For
horizontal episodes, the prediction's single port must equal the episode
target port, or the episode port must be in the enumerated port list. When an
engine reports no target identity for its direction class (sweep groups,
random scans), the gate passes as unknown-group and the edge says so. Ground
truth never supplies target identities the engine did not emit, and engine
predictions never relabel episodes.

## 4. Timing classification and the delayed/EOF allowance

Candidate timing is classified, not gated:

- within: alert event time inside the label's first/last qualifying probe
  interval; distance 0.
- delayed: after the interval; distance to the last probe. Allowed.
- early: before the interval; rejected with reason alert-before-episode. An
  alert cannot be caused by probes that had not happened.

The delayed allowance is required by documented engine behavior, not by test
outcomes. The pinned Zeek package aggregates failed attempts and emits one
notice at threshold crossing with a one-hour suppression; the development
diagnostic (adapters/README.md) showed offline EOF flushing moves the same
notice's ts from 24.9s to 40.0s when unrelated trailing traffic extends the
capture, with both runs exiting successfully. Rejecting delayed notices would
punish an engine for its documented flush behavior, and no small fixed grace
is defensible. Unbounded delay inside one capture risks stealing credit across
episodes; this is bounded by the exact matcher's minimum-distance tie-break
and by the protocol's >W episode separation, and scoring must report the
distance distribution of matched delayed edges.

Consequences: comparable baseline decision latency is unavailable for Zeek and
stays unreported; EOF/start timestamps are never reported as decision times.
Snort's event time is its triggering packet and is normally within the window,
but is still classified by the same rule.

## 5. Suppression and duplicate accounting

The pinned Zeek package suppresses repeat notices per scanner for one hour
(known_scanners, suppress_for 3600s in the activation evidence). Snort's
recorded default alert_all=false alerts on the first threshold-crossing event
per tracker. Therefore repeated episodes by one scanner inside a suppression
or first-only window produce no further alerts by design. Scoring must:

- report suppression-missing episodes (an alert exists earlier in the capture
  for the same scanner and direction) separately from never-detected episodes;
- report unmatched alerts that duplicate a matched episode as duplicate
  burden, separately from alerts matching no episode at all;
- never call an unmatched alert a false positive until it has passed through
  these two classifications and the ambiguity review of section 6.

## 6. Intent, ambiguity and denominators

Candidate edges record the episode's intent. Attack episodes drive recall.
Approved benign scans are benign operational controls: matches against them
are expected alerts and remain false positives for intent labels, reported in
their own column. Ambiguous episodes are excluded from primary recall and
precision and reported as a separate count with their reject reasons.

Finite benign units: each benign control trace (normal sessions, few-port
retries, approved administration, NAT-like shared sources, service discovery,
FIN/ACK teardown) is one unit; packets are not true-negative episodes. Benign
alert rate is alerts per unit per trace-hour with the trace durations
declared in the corpus specification. Precision denominators are
unique-matched-episode alerts; undefined precision stays undefined.

Denominators are reported as all-scenario and supported-scope, per the
protocol. Aggregate/random-aggregate matched recall is reported both ways
(section 2). Campaign-level results are reported separately from per-W
segmented units so segmentation cannot inflate recall.

## 7. Matching

Candidate edges feed the exact matcher (adapters/matching.py): maximum
cardinality, minimum total integer nanosecond distance, lexicographic
tie-break. One alert matches at most one episode; one episode takes at most
one alert. All candidates, near-miss rejects and per-alert gate-failure counts
are persisted with the scoring outputs for audit. The matcher's node/edge
caps raise instead of truncating; a study run that exceeds them fails and the
partition strategy required then is itself an amendment.

## 8. What remains open before Gate A closes

- Frozen synthetic generator specification: parameter ranges and exact
  background/jitter/port/gap distributions (protocol section "Corpus and
  separation"). No held-out generation before it exists.
- The benign-alert operating budget, fixed by dated amendment before final
  development operating-point selection.
- The development operating point (W,T) selection procedure itself, executed
  only on development seeds 0..9 after the budget exists.

No accuracy, recall, precision or latency numbers exist for v2 as of this
contract. Gate A closes when this contract, the adapters, the matcher and all
tests are published together with the existing passing controls.
