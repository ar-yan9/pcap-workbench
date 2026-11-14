# Independent evaluator components

Status, 14 November 2026: matching primitive, Zeek/Snort prediction adapters and compatible-edge construction are implemented and tested; evaluator contract v0.1 is drafted in `../evaluator-contract.md`. Gate A remains OPEN pending the frozen generator specification and the benign-alert budget amendment. No accuracy/recall values exist yet.

## Exact matching primitive

`matching.py` accepts episode IDs, alert IDs and independently established compatible candidate edges with integer nonnegative nanosecond distances. It returns pairs plus unmatched IDs and total distance. It does not infer identity, family, targets, timing tolerance, intent or ground truth.

The objective is exact and ordered:

1. Maximum number of one-to-one pairs.
2. Minimum total candidate-edge time distance at that cardinality.
3. Lexicographically smallest sorted `(episode_id, alert_id)` pair list at equal distance.

An aggregate alert can match at most one episode. A second alert for the same episode remains unmatched; later scoring must distinguish duplicate burden from unrelated false alerts under the frozen contract. Candidate edges are sorted before graph construction, so input ordering cannot pick a favorable answer.

Implementation: unit-capacity min-cost flow with successive shortest augmenting paths. Bellman-Ford handles negative residual reverse edges. Integer binary edge signatures provide an exact lexicographic secondary cost, not floating-point epsilon tie-breaking. Explicit defaults are 256 graph nodes (including source/sink) and 4,096 candidate edges. Exceeding a cap raises an error, never a partial matching. These are conservative implementation limits, not a measured scaling claim. A future need to partition larger graphs must preserve independent components and be tested before use.

`test_v2_matching.py` checks greedy traps, time-distance priority, lexical ties, aggregate/duplicate alerts, disconnected graphs, invalid IDs, float/bool distances and cap failures. It compares against a separate brute-force oracle on all 19,683 three-by-three graphs whose edges are absent or have distance 0/1 ns, plus 250 fixed-seed random graphs up to four-by-four. These are algorithm tests, not experimental samples or detector performance results.

## Prediction adapters and compatible edges, 14 November 2026

`zeek_notice.py` parses notice.log into prediction records using the pinned bro-simple-scan source's five exact message forms, cross-checking note type, direction, scanner and port formats; unknown scan content raises. `snort_alert.py` parses alert_json with the gid 122 sid table frozen from the pinned build's own port_scan module help; sid/message/proto contradictions raise. Both record engine evidence only: no technique is invented (family stays generic-scan), sweep groups stay unknown-group, and Zeek notice ts is an emission timestamp, never a decision time.

`compatibility.py` builds candidate edges under the contract gates (capture, scanner, direction, target/group), classifies timing as within/delayed/early, rejects early alerts, flags random-aggregate edges, and preserves every candidate, near-miss reject and per-alert gate-failure count for audit. `test_v2_adapters.py` covers real published activation outputs, all documented message shapes, strictness failures, gate behavior, delayed/duplicate matching against the exact matcher, and intent/group-evidence recording. These are format and contract tests, not detector performance results.

## Still required before scoring

- Frozen synthetic generator parameter ranges and distributions (protocol corpus section); no held-out generation before it exists.
- The benign-alert budget amendment and the development-only operating-point selection on seeds 0..9.

Do not turn a missing baseline packet-ID field into automatic failure, or use detector-produced labels as independent truth. Do not call an unmatched alert a false positive until it has passed the contract's suppression, duplicate and ambiguity classifications. Save every candidate edge and unmatched/ambiguous reason so later evaluation can be audited.

## Timing diagnostic to resolve in the contract

A private offline development diagnostic used exactly 250 unanswered SYNs spaced 0.1 seconds apart. With the trace ending at 24.9 seconds, Zeek+bro-simple-scan produced a Port_Scan notice at 24.9 seconds. Adding an unrelated complete benign connection at 40 seconds moved the same notice timestamp to 40.0 seconds. Both runs exited successfully. These observations concern this pinned engine/package and tiny diagnostic only; they are not general latency measurements.

Installed Zeek declares a 5-second TCP attempt delay and timer-driven connection handling, while offline end-of-file handling can flush events. The diagnostic confirms that a notice timestamp alone is not a safe comparable decision-delay metric, and a small fixed matching grace can reject genuine timer-delayed notices. The final adapter needs independently justified attribution evidence and tests; comparable latency stays unavailable unless separately verified. Do not pick a tolerance merely because it improves recall.

Raw diagnostic PCAPs remain local and were not published. The exact allowance/instrumentation decision is unresolved, not silently settled here. No held-out data has been used to select these rules.
