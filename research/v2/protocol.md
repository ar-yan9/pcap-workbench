# Port-scan v2 evaluation protocol

Protocol version: 0.1, 13 November 2026. Status: preregistered design, Gate A OPEN. No v2 accuracy, baseline-comparison or performance results exist yet. Changes after pilot work require a dated amendment stating what was observed and which data remain held out.

## Scope and immutable starting point

Source: `b7a7c90d28368ca4a0d00bc333012bd6694b498e`. Historical detector: `063ad1d4d75de970fbf84c7c5d5f46ef9709e36f`. Historical artifact: `1-portscan-study-v3.zip`, SHA-256 `1a5f761d11820309e51c4a30b5765b17c930c1eff25d6b2e0ad7475fa6a8357e`. Do not alter this ZIP or rewrite its results. Evaluate frozen v1 and current parser with v1 logic separately.

Research questions: coverage across TCP scan families and repeated episodes; operational trade-offs versus Zeek and Snort 3; resource use and explicit limit behavior; generalization from synthetic development traces to held-out traces, lab captures and audited public-data slices. This is an offline reconnaissance-pattern study, not proof of malicious intent or a general IDS superiority claim.

Supported scope to implement: Ethernet IPv4/IPv6 TCP vertical SYN, horizontal SYN, FIN-only, NULL and Xmas probes. UDP, distributed campaigns and scans slower than the chosen window remain named stress/out-of-scope cases. No capture publication, license selection, venue submission or spending is authorized by this protocol.

## Repository layout and provenance

`research/v2/` contains `protocol.md`, `configs/`, `manifests/`, `generators/`, `runners/`, `adapters/`, `tests/`, `results/raw/`, `analysis/` and `paper/`. Populate these as each component becomes executable; this layout is not a claim that the components already exist. Real payloads and identity maps remain outside the public repository. Synthetic PCAPs may be generated locally; publish code and permitted derived data, not captures.

Each run manifest records source commit, engine and build pin, configuration and corpus/label SHA-256, exact argument vector, seed/split, UTC start/end, exit status, resource limit, actual input/decoded counts, skip/truncation counters and raw-output reference. A nonzero exit, missing expected output, unread packets or limit hit is a failed/incomplete run, never a zero-alert success. Raw outputs are immutable; analysis creates new files.

## Detector contract to implement before test runs

Events retain original packet number, integer timestamp, address family, source/destination, ports and full TCP flags. Public pseudonyms are not evaluation join keys. Sorted detection-only input can stream; unsorted input must be explicitly rejected or externally sorted with a stable original-ID map. Do not call the existing in-memory whole-report mode streaming.

Primary grid: W={10,60,300} seconds x T={5,10,15,20}; horizontal H=T as a declared convention, not equivalence between hosts and ports. Thresholds count distinct values in inclusive [t-W,t]. Vertical keys are (source,target,family), horizontal keys (source,target_port,family). SYN means SYN set and ACK clear. FIN/NULL/Xmas use the low six TCP control bits equal to 0x01/0x00/0x29 respectively; ECE/CWR are ignored for this classification and are retained in evidence. FIN+ACK is negative. Exact classifier masks require tests before freeze.

Emit at most once per active key/family episode; re-arm only when the gap since its last qualifying probe is strictly greater than W. Continuous campaigns without this gap do not generate a fresh alert. Expire idle keys globally, maintain distinct-value reference counts under retransmission, and make state-cap exhaustion visible. Development-only proposed safety budgets: at most 100,000 active keys and 1,000,000 retained probe events; tune downward if the runner needs it, then freeze before held-out runs. These are proposed implementation budgets, not verified capacity. Record caps in every run. Never evict silently and score as complete.

## Corpus and separation

Synthetic families: fast vertical SYN, threshold-edge SYN, slow SYN, horizontal SYN, FIN, NULL, Xmas, repeated vertical bursts, repeated horizontal bursts, mixed families, distributed SYN and UDP; plus normal sessions, few-port retries, approved high-fan-out administration, NAT-like shared-source clients, service discovery and FIN/ACK teardown. Approved scans are benign operational controls, so their alerts remain false positives for intent labels.

Use 30 seeds per family, 10 development and 20 held out: 540 traces total. Deterministic seed IDs are 0..29 for each family; IDs 0..9 are development and 10..29 held out. Generator uses `random.Random(seed)` with the family ID in a SHA-256-derived sub-seed to avoid accidental stream reuse. Parameter ranges and exact background/jitter/port/gap distributions must be frozen in a checked-in generator specification before generating held-out content. No held-out generation or inspection occurs while this specification is pending. A changed address alone is not a fresh traffic replicate.

Lab matrix proposed: six techniques (vertical SYN/connect/FIN/NULL/Xmas and horizontal SYN), three timing templates T2/T3/T4, two documented response states and three fresh capture repetitions: 108 attack runs. Use 32 owned ports/addresses and independent benign sessions. Fresh traffic captures, not repeated analysis of one PCAP, define replicates. Network namespaces must have no external route or uplink; only owned veth endpoints. Validate Ethernet link type, checksums, packet drops, request/reply visibility, Nmap XML, firewall/service state and command times. Do not use Linux cooked capture as supported Ethernet input.

Public validation: original CIC-IDS2017 PCAP plus corresponding labels, not feature CSV alone. Predeclare Friday PortScan/time-matched benign and Monday benign slices after provenance/timezone/label audit. Include >=300 seconds warm-up and enough post-roll for connection-based baseline decisions. Audit observed tuples and labeling defects; preserve ambiguity/exclusion counts. No tuning on CIC labels. If reliable episode mapping fails, report qualitative coverage/benign alerts only, not external accuracy. Friday is not all PortScan.

## Baseline activation and freeze

Zeek candidate: 8.0.11, upstream OBS Ubuntu 22.04 amd64 core package. Snort candidate: 3.13.2.0 tag (`fe29cbe7403acc0dd428065a69d8f29cc311c18e`) with LibDAQ 3.0.29 (`c8d4083904f7791f596d853178aca4ef1e20f7d3`). These are selected pins, not a claim that controls passed. Save package/build digests, compile features, exact configuration and logger help. Snort 2 is not a substitute. Docker is a possible provisioning mechanism, not a scientific baseline or prerequisite if native offline binaries work.

Zeek explicitly loads `policy/misc/scan`; record installed policy defaults and failed-connection semantics. Snort explicitly activates its `port_scan` inspector, validates configuration with `-T`, and saves inspector/logger help plus raw alerts and packet counters. Primary baseline runs are single-threaded default configurations; development-selected tuning is a separately labeled comparison. Do not equate Snort sensitivity numerically to W/T.

For every engine, before evaluation, use valid-checksum positive and negative PCAP controls. Positive must contain enough closed-port/rejected probes to exercise the actual policy; negative must have ordinary complete sessions and few-port retries. Assert packets were read and expected positive alerts exist. Zero output from an inactive inspector fails activation. Keep control fixtures independent of held-out performance data. Both controls, adapters and existing tests must pass for Gate A.

## Episode labels and deterministic matching

Label schema v0.1: capture_id, episode_id, intent (attack/benign/ambiguous), family, scanner, target (vertical) or target_port plus target set (horizontal), first/last qualifying probe time, independently known technique, provenance/evidence reference. Same scanner/target/family activity separated by >W belongs to separate detector episodes; ground-truth campaign IDs remain stable and independent of W, with per-W segmentation supplied as derived units. Report campaign-level results separately so segmentation cannot inflate recall.

Prediction schema: engine, config_hash, capture_id, alert_id, family (or explicit generic-scan), scanner, target/group, event_time, decision_time_if_observable, evidence_reference and raw_record_reference. Do not require baseline packet IDs. Match only same capture/scanner, compatible family and target/group, and a label interval expanded by a predeclared baseline decision allowance. The allowance, generic-family compatibility table and aggregation rules must be fixed in evaluator-contract.md from documented baseline semantics and development controls before Gate A closes. Until then no scoring runs are allowed.

Use deterministic maximum-cardinality one-to-one bipartite matching; among equal-cardinality solutions minimize total time distance, then lexicographic (episode_id,alert_id). Record all unmatched and ambiguous candidates. Duplicate alerts for an already matched campaign are analyst burden and reported separately. Tests must cover duplicate, overlap, aggregate host-scan, late/EOF, generic family, wrong-scanner and wrong-target predictions. Threshold tuning uses development data only, selecting maximal recall subject to a benign-alert budget fixed by a dated amendment before final development selection; if no setting meets it, report that instead of relaxing it after looking at tests. No operational budget is guessed here.

## Metrics, uncertainty and failure accounting

Primary metrics: episode recall by family, unique-matched-episode precision, benign alert episodes/hour, duplicate burden and latency where genuinely observable. Report all-scenario and supported-scope recall with denominators. Undefined precision stays undefined. Finite benign-control units must be specified before a confusion matrix; packets are not true-negative episodes. Keep old strict duplicate-penalized fixture metrics separately labeled if reproduced.

Cluster bootstrap 10,000 resamples, fixed analysis seed 20261113, stratified by family over independently generated traces or fresh lab captures; pair engines on the same trace. Do not treat packets/flows as independent replicates or CIC flow rows as independent campaigns. Publish wide intervals. Report attack-start-to-alert and v2 threshold-eligible delay; unavailable baseline decision time stays unavailable. EOF/start timestamps do not become invented decision timestamps.

Resource suite: benign sessions, dense SYN fan-out, many keys, horizontal fan-out, slow/repeated traffic and mixtures. Start at 10k/25k/50k/100k records; larger inputs only after bounded processing passes. Three generation seeds, one warm-up and ten fresh-process measurements per workload/size/seed. Interleave engine order with fixed thread policy. Save wall time, peak child RSS, CPU time, counts, active-key/queue peaks and output size. Report whole-tool and internal breakdown separately. Shared-runner numbers are exploratory; generation is not analysis time. The old ACK-only fixture is parser-heavy reference evidence, not a scan-heavy benchmark.

## Gates and amendments

A: current 47 tests and frozen 9 evaluator tests/verify pass; protocol and evaluator contract versioned; pinned engines both pass positive and negative controls. B: full flags, families, re-arming, limits/order and evidence tests pass; detector frozen. C: corpus provenance, hashes, labels, splits and public-label audit complete. Only then run held-out grid/baseline/ablation/performance work, rewrite from measured outputs and independently reproduce. Venue choice and submission remain separate user decisions.

Initial reproduction on 13 November 2026: current 47/47 tests pass; frozen verify.py regenerates the 986-packet fixture, eight metric rows and manifest hashes; 9/9 frozen evaluator tests pass. These are historical reproduction results only. Baseline controls, new corpus and v2 experiments are pending. No favorable outcome is promised.

Official provisioning references inspected: https://github.com/zeek/zeek/wiki/Binary-Packages ; https://docs.snort.org/start/installation ; https://www.snort.org/downloads.html . Full research-plan source ledger is maintained separately. Next amendment closes evaluator/parameter details before any held-out data access.
