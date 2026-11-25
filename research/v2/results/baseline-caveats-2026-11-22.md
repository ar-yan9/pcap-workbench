# Baseline result caveats, 22 November 2026

Applies to: `raw/dev-baselines-2026-11-22.json` (Zeek 8.0.11 with the
pinned third-party scanner packages ncsa/bro-simple-scan 35cf19cf and
ncsa/bro-is-darknet 7564a8f2, and Snort 3.13.2.0's port_scan inspector,
both at pinned default configurations, development seeds 0..9, 180
traces). The Zeek baseline is Zeek plus these specific packages, not
generic Zeek capability; Zeek's detection behavior depends on the loaded
policy.

This note must travel with any use of those numbers, including the paper.

## What the default-configuration results support

- On this synthetic corpus, the pinned default configuration of the Zeek
  baseline produced zero alerts on the development attack families, and the
  pinned default Snort port_scan inspector likewise produced no attack-family
  alerts (campaign recall 0.0 over 80 attack campaigns for both). Neither
  produced any alert on the zero-tolerance benign families.
- Snort defaults alerted exactly once per approved-admin-scan trace (10
  alerts, the expected-alert class), zero duplicate burden.
- Because the Zeek null is confounded by the addressing interaction below,
  these default results cannot anchor an unqualified superiority claim, even
  alongside the Amendment A3 sensitivity numbers.

## What they do NOT support

- They are not evidence that Zeek or Snort cannot detect these scan
  techniques under realistic deployment configuration.
- The Zeek null result is materially driven by an addressing interaction,
  not only by detection logic. Zeek 8 defaults
  `Site::private_address_space_is_local = T`, which copies the IANA
  special-purpose registry (including TEST-NET 192.0.2.0/24 and
  198.51.100.0/24, used by the frozen synthetic corpus) into
  `Site::local_nets`. The pinned bro-simple-scan package then applies its
  LOCAL scan threshold (250 unique attempts) instead of the remote
  threshold (25). No development episode reaches 250 unique attempts.
  Verified mechanism: a diagnostic run differing only in
  `private_address_space_is_local = F` raises Scan::Port_Scan on
  fast-vertical-syn-s0 (70 unique attempts >= 25). The 600-probe frozen
  activation control also fired under full defaults (600 >= 250),
  consistent with this mechanism.
- Snort's default port_scan sensitivity misses slow, low-count, distributed
  and non-SYN techniques in this corpus; that is genuine default behavior,
  but the corpus's synthetic traffic lacks the background noise against
  which Snort's default sensitivity was calibrated.

## Consequences for claims

- Report baseline numbers only together with this addressing/threshold
  interaction, naming the exact configuration (Zeek plus the pinned
  third-party scanner packages, or Snort's port_scan inspector, at pinned
  defaults). "These pinned default configurations produce no attack-campaign
  alerts on this synthetic corpus" is supportable; "commodity detectors
  cannot detect these scans" is not.
- Development operating-point recall (0.975 at W=300, T=5) is development
  selection performance, never held-out performance; held-out seeds 10..29
  remain untouched.
- The sensitivity analysis quantifying the addressing interaction is
  protocol Amendment A3 (protocol.md, accepted and frozen 22 November 2026
  before its run). Its S1 results exist (raw/dev-baselines-sensitivity-2026-11-22.json):
  with only private_address_space_is_local=F and all detection thresholds
  still at package defaults, the Zeek baseline reaches development campaign
  recall 0.4125 (33/80: all seeds of fast-vertical-syn, repeated-vertical-bursts
  and repeated-horizontal-bursts, 3/10 horizontal-syn), 55 alerts total, zero
  zero-tolerance violations, expected-alert burden within the A2/A2.1
  accounting. The remaining gap to the v2 detector's development selection
  recall (0.975) comes from the package's default count thresholds missing
  slow, low-count, distributed, UDP and flag-based techniques; the default-run
  null is explained by the addressing interaction. Neither number is held-out
  or deployment performance, and the confounded default run still cannot
  anchor an unqualified superiority claim.
