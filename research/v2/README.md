# Baseline activation and research status

Gate A is still OPEN. This directory contains a frozen design, pinned environment evidence and activation tooling. It does not yet contain a v2 detector or held-out accuracy/performance results. Read `protocol.md`, including the dated Zeek package correction.

## Offline activation runner

The runner generates two local control PCAPs, runs the pinned engines without sending network traffic and fails if the controls cannot establish activation. It is not an installer. Provision the versions in `manifests/environment-2026-11-13.json` first. Linux x86-64 is the tested engine platform; POSIX process groups are required for timeout cleanup. Windows CI runs the platform-independent fixture/log checks and skips the POSIX process tests.

Expected prefix layout:

- `opt/zeek/bin/zeek` and `opt/zeek/share/zeek/`: Zeek 8.0.11.
- `bin/snort`, `lib/daq/`, `etc/snort/snort.lua` and `etc/snort/snort_defaults.lua`: Snort 3.13.2.0, LibDAQ 3.0.29, native pcap/savefile support.
- `usr/bin/tshark` and `usr/lib/x86_64-linux-gnu/`: TShark 3.6.2 and required runtime libraries.
- Source directory holds clean git checkouts `bro-simple-scan` at `35cf19cf64ba9f9989022a56dce0c8ad6ae2f3f2` and `bro-is-darknet` at `7564a8f2035aa62359199b64086ff14749f35f73`. Source directory paths must not contain whitespace or quotes, because Zeek load directives use token paths.

Use a new output directory outside the repository. Its parent must already exist. The runner refuses existing directories and symlinks. No sudo, Docker daemon or raw-packet privileges are needed for these offline controls.

```sh
python3 research/v2/runners/activate_baselines.py \
  --prefix /path/to/provisioned-prefix \
  --sources /path/to/pinned-source-checkouts \
  --output /path/to/new-local-run \
  --timeout 60
```

Exit 0 means all activation checks passed. Exit 2 means failure; read `run-manifest.json` and retained stdout/stderr. Input/argument errors before a new directory is created fail without overwriting any earlier output. Timeouts kill the command's process group and count as failure. A missing binary, changed scanner checkout, wrong version, malformed log or incomplete packet accounting cannot become a successful zero-alert result.

The run manifest records source revision and dirty status, runner/generator hashes, binary and configuration hashes, source pins, exact commands, UTC times, exit codes, checksum checks and control assertions. It hashes raw output files. It does not assume that a version string establishes a source commit; binary hashes and the separate provisioning manifest retain that provenance.

Current controls:

| Control | Packets | Traffic | Required result |
| --- | ---: | --- | --- |
| Positive | 600 | 300 SYN/closed-port RST exchanges | One Zeek Port_Scan and one Snort TCP portscan |
| Negative | 64 | 10 complete TCP sessions and 2 same-port refusals | No scan or unexpected inspector alerts |

Every IPv4/TCP checksum is verified with TShark, and both engines must account for every packet. Zeek sees 300 positive and 12 negative connections. Its installed defaults treat documentation addresses as local, so the positive exceeds the package's 250-failure local threshold without lowering it. The earlier insufficient 120-port control is documented as a failed pilot. Zeek's control-only/pre-filtered warning remains in stderr; these fixtures are activation checks, not realistic network evidence.

## Tests

```sh
python3 -m unittest -v
```

`test_v2_activation.py` checks deterministic fixture hashes, every generated checksum, overwrite/symlink protection, strict versions, incomplete/malformed logs, packet-accounting scope, missing/wrong alerts, process failure, timeout and failure-manifest preservation. It does not require installed Zeek/Snort or send packets. The original detector tests are unchanged.

## Reproduction limits and next gate items

The automated installer/build recipe is still pending. The current runner expects an already provisioned prefix rather than claiming that the recorded environment manifest installs itself. Full source-package signature verification, a different-machine rerun and final research engine/configuration freeze are separate checks. Shared-runner timings in activation manifests are operational logs, not benchmark evidence.

Gate A still needs independent prediction adapters, deterministic matching tests and a closed evaluator contract. Generator parameter ranges and the development operating-point selection rule must be versioned before held-out generation. No held-out seed, CIC label or final experiment may influence those choices. Only then proceed to the v2 detector and later corpus gates.

Do not commit generated captures, payloads or private identity mappings. Do not change the frozen revision-3 ZIP. This branch does not authorize a venue submission, spending or a license change.
