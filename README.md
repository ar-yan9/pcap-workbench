# PCAP Investigation Workbench

Offline Python analysis of **classic PCAP** captures. It summarizes directional TCP/UDP flows, counts DNS questions, and flags a source sending TCP SYN packets to many ports on one target within a time window. It reads a file; it never captures live traffic, sends packets, probes hosts or contacts servers.

This is a working investigation starter inspired by offline network-analysis tools, **not a Zeek replacement**, intrusion-prevention system or confirmed-attack detector. [Zeek's official guide](https://docs.zeek.org/en/master/quickstart.html) describes its broader offline-PCAP workflow. The [classic-PCAP format reference](https://wiki.wireshark.org/Development/LibpcapFileFormat) explains capture headers and record framing.

## Windows quick start

Requires Python 3.10+; no external Python packages, paid tools, administrator rights, Linux or WSL needed for this milestone.

```bat
git clone https://github.com/ar-yan9/pcap-workbench.git
cd pcap-workbench
py -3 -m unittest -v
py -3 make_demo.py demo.pcap
py -3 workbench.py demo.pcap
py -3 workbench.py demo.pcap --format json
```

On Linux/macOS, replace `py -3` with `python3`. If `demo.pcap` already exists, use a new filename. The generator deliberately refuses to overwrite any existing file or symlink.

Expected demo: **13 decoded packets**, **12 TCP + 1 UDP**, **1 DNS question**, and **1 possible-port-scan alert**. At default settings the alert triggers on the tenth distinct destination port. Its evidence is capture packet numbers 1-10. All packets are generated locally with documentation-only addresses and `demo.test`; no real traffic is included or sent.

Exit codes: **0** = no heuristic alerts in the decoded scope; **1** = review alerts; **2** = unsupported header, invalid settings, unavailable input or an incomplete file/limit notice. Skipped protocol counts remain in the report; a zero exit does not mean a capture is safe or completely decoded.

## What works now

- Classic PCAP version 2.4, Ethernet link type 1; little/big endian and micro/nanosecond timestamp formats.
- Ethernet IPv4 with up to two VLAN tags; complete unfragmented TCP/UDP packets.
- Directional five-tuple flows (source/target address, source/target port, protocol), packet counts and IPv4 byte counts. Top 20 by bytes.
- First uncompressed DNS question in UDP destination port 53; top 20 query-name/type counts. Names are pseudonymized, not printed.
- Inclusive sliding-window TCP SYN-without-ACK rule: at least 10 distinct destination ports from one source to one target within 60 seconds, by default. Retransmissions to the same port do not increase the distinct-port count.
- JSON/text reports, parser bounds, packet-number evidence and generic error messages.

```bat
py -3 workbench.py demo.pcap --ports 15
py -3 workbench.py demo.pcap --window 5
py -3 workbench.py "C:\captures\authorized.pcap" --max-packets 100000 --max-bytes 67108864
```

The first two commands produce no scan alert for the demo. This is a threshold demonstration, not an accuracy benchmark. Reports print per-run keyed HMAC labels instead of raw IPs and DNS names. Labels correlate within a report and change across runs. No payload bytes or MAC addresses are exported. Ports, counts, timestamps and evidence numbers can still be sensitive: **pseudonymization is not anonymization**. Keep real captures and reports private.

## Coverage and honest limits

PCAPNG, Linux cooked capture, raw-IP link types, IPv6, ARP, IPv4 fragments, TCP stream reassembly, TCP DNS, encrypted-DNS interpretation, compressed DNS question names and HTTP/TLS parsing are unsupported. Unsupported/malformed packets are counted by reason. Checksums are not validated. TCP flags describe observed packets, not successful connections. A source/target pair is alerted once per report; separate later bursts are not separate alerts.

Snap-length truncation counts are visible. Packets too short for their advertised IPv4 size are skipped; malformed record framing stops analysis with a notice. Default input bounds are 100,000 records and 64 MiB of consumed record data including headers. Declared snap length is capped at 16 MiB. Valid records/events are held in memory for sorting, so this is not a large-capture streaming engine. Top-20 displays do not show every flow/query, though total counts are reported.

Shared NAT, monitoring software and legitimate administration can resemble scans. Distributed, slow, UDP and non-SYN scans can evade this rule. It does not infer malware, exfiltration, exploit success or a person's identity. Review evidence locally before taking any action.

Only analyze captures you own, are authorized to inspect, or that were intentionally released as safe training data. Never sniff someone else's network or publish real captures, identities or findings. No external practice capture is bundled in v1.

## Tests and next milestones

24 synthetic tests cover all four file magic variants, VLANs, fragments, malformed framing/transport headers, DNS bounds, resource limits, redaction, port thresholds, inclusive windows, repeated ports, SYN/ACK exclusion, exit states and overwrite protection. CI runs on Windows 2022 and Ubuntu 24.04 with Python 3.10-3.13.

Next real work: PCAPNG/IPv6 support with fixtures; richer DNS decoding; bidirectional sessions and Zeek-log import; a local investigation UI and timeline; benchmarks against known safe capture fixtures. These are roadmap items, not delivered features. Learn the binary parser, five-tuple grouping and window rule before claiming interview ownership or production deployment.
