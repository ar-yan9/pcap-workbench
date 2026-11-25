# Engine provisioning record v0.1 (21 Nov 2026)

Implements protocol.md line-39 pins. Built unprivileged from source on Ubuntu 22.04 (x86_64, gcc 11) because the OBS xUbuntu_22.04 repo no longer serves 8.0.11 debs (rotated to 9.0.1); recorded 21 Nov with dated rationale.

## Binaries (sha256)
- zeek 8.0.11: f05433a7c88de8b9a70b64f16089c57508aa6a5084cd0ca47454292619b5fe4c
  - Source: zeek-8.0.11.tar.gz sha256 2679a5f1871ee525b0cd627c2fc003043ea73d3a0ffd84f7a95154167efc5fb7 (identical from download.zeek.org and the GitHub v8.0.11 release asset; tag = 4d1333b2ad2055c67f6f29f692b0542a0d27b086)
  - Configure: --build-type=Release --disable-spicy --disable-broker-tests --disable-zeekctl --disable-btest --disable-zkg --disable-python. Spicy/cluster/python components are not used by the conn-log-based scan analysis; broker lib + ZeroMQ 4.3 built in.
- snort 3.13.2.0: f38f8adf7a66509974162cc37021644e1580860332573d19aa0f0a1af494db7c
  - Source: tag 3.13.2.0 = fe29cbe7403acc0dd428065a69d8f29cc311c18e, tarball sha256 298367524a31f0d4725ef12b2b06265b4e76e6545f990ae3dc3b5e4c10f6e0ea
  - Built --without-libml (SnortML mock; not used by port_scan inspector). Byte-identical across 4 independent clean rebuilds.
- libdaq 3.0.29: tag v3.0.29 = c8d4083904f7791f596d853178aca4ef1e20f7d3, tarball sha256 136deba78d195163687eb71a6dc81b725c27fde7765b7ef70eb741c371e887a8

## Scanner packages (Amendment A1 pins, from github.com/ncsa)
- bro-simple-scan @ 35cf19cf64ba9f9989022a56dce0c8ad6ae2f3f2 (loaded via @load of scripts/)
- bro-is-darknet @ 7564a8f2035aa62359199b64086ff14749f35f73

## Build dependencies
Ubuntu 22.04 archive debs extracted unprivileged (no root): libpcap 1.10.1, OpenSSL 3.0.2, PCRE2 10.39, LuaJIT 2.1.0-beta3, hwloc 2.7.0, libdumbnet, libsafec 3.7.1, libunwind 1.3.2, ZeroMQ 4.3, lzma, zlib, uuid, bison 3.8.2, flex 2.6.4, swig 4.0, python3.10-dev. Per-deb sha256 recorded at build time.

## Smoke evidence (21 Nov, synthetic fast-vertical-syn seed 0, 196 frames)
- zeek -r trace + scanner.zeek: loaded pinned packages with zero errors/warnings; wrote conn.log, weird.log, packet_filter.log.
- snort -c ps.lua -T (port_scan inspector, memcap 1000000): "Snort successfully validated the configuration (with 0 warnings)".
- snort -r trace: analyzed 196/196 packets, 9 sessions, clean exit.
- No accuracy claim is made from smoke runs; activation controls remain the pass/fail gate.
