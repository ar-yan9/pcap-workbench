# Baseline results subsection DRAFT, 23 November 2026

Status: draft text for the v2 paper's baseline-comparison subsection. Every
number below comes from real recorded runs (raw JSONs cited inline; blobs
verified against local commits). Development split only: nothing here is
held-out or deployment performance, and the dev operating-point recall is
selection performance. Per Amendment A3, neither the default nor the
sensitivity numbers support an unqualified headline superiority claim; the
comparative statements below name the configuration and the addressing
interaction. Do not edit toward stronger claims without a protocol
amendment.

---

We compared the v2 detector against two commodity baselines on the
development split (seeds 0-9, 180 synthetic traces, 80 attack campaigns).
The Zeek baseline is Zeek 8.0.11 with the pinned third-party scanner
packages ncsa/bro-simple-scan (35cf19cf) and ncsa/bro-is-darknet (7564a8f2)
loaded per Amendment A1; the Snort baseline is Snort 3.13.2.0 with its
port_scan inspector. Both ran at their pinned default configurations with
verified binary digests, and all predictions passed through the same
independent matcher and contract gates as the v2 detector
(dev-baselines-2026-11-22.json).

At these defaults, neither baseline raised any alert on an attack campaign
(campaign recall 0.0/80 for both). The Snort inspector alerted exactly once
per approved-admin-scan trace (10 alerts, the expected-alert class, no
duplicate burden), and neither engine alerted on the zero-tolerance benign
families.

The Zeek null is explained by an addressing interaction rather than pure
detection capability. Zeek 8 defaults
`Site::private_address_space_is_local = T`, which classifies the corpus's
TEST-NET addresses as local; the scanner package then applies its local
threshold of 250 unique failed attempts instead of the remote threshold of
25, which no development episode reaches. Amendment A3 (frozen before the
run) isolates this interaction with a single deployment-environment change
(`private_address_space_is_local = F`), leaving every detection threshold
at its package default. Under this separately labeled sensitivity
diagnostic (dev-baselines-sensitivity-2026-11-22.json), the same Zeek
baseline detects all seeds of the three aggressive SYN burst families and
3/10 horizontal-syn campaigns (campaign recall 0.4125, 55 alerts, no
zero-tolerance violations), while still missing the slow, low-count,
distributed, UDP and flag-anomaly families. Snort has no analogous variant:
its port_scan inspector performs no local/remote classification.

For reference, the v2 detector's development operating point (W = 300 s,
T = 5), selected under the predeclared benign-alert budget of Amendments
A2/A2.1, attains development campaign recall 0.975
(dev-selection-2026-11-18.json). These results show that detection of the
harder scan families requires counting semantics beyond both engines'
default configurations on this corpus; they do not show that commodity
detectors cannot be configured to detect them, and the default-configuration
null for the Zeek baseline specifically reflects the addressing interaction
described above. Held-out evaluation (seeds 10-29) and public-capture
validation remain future work under the frozen protocol.

---

Open drafting notes:
- Table (engine x config x recall x alerts x ZT violations) to be generated
  from the two raw JSONs at paper build time; numbers above are the prose
  anchors.
- Citation placeholders needed for Zeek 8 local_nets behavior and the
  scanner package defaults; add during publication pass.
- If reviewers want a per-family table, per_family objects in both raw
  JSONs provide it verbatim.
