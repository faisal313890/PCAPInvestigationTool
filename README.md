# PCAP Investigation Tool

A local network-investigation portfolio project for inspecting saved captures, summarizing directional flows and DNS question metadata, and reviewing explainable traffic patterns with frame-number evidence. Includes JSON, flows CSV and print/Save as PDF reports. **No API keys, pip dependencies, administrator rights, live capture, packet sending or external lookups are required.** Uses Python 3.12+ and its standard library.

## Windows — start here

1. Extract the ZIP and open **PCAPInvestigationTool**.
2. Run **start_windows.cmd**. Keep its CMD window open.
3. Open **http://127.0.0.1:8810**.
4. Click **Normal PCAP**, then **Investigate capture**.

From CMD inside the project folder:

```bat
py -3.12 server.py
```

Press Ctrl+C to stop. No Wireshark, Scapy or Npcap installation is needed to read the supported capture files. The tool does not capture from your network adapter.

If port 8810 is occupied:

```bat
set "PCAP_TOOL_PORT=8811"
py -3.12 server.py
```

Then open http://127.0.0.1:8811. Linux/macOS: `python3 server.py` with Python 3.12+.

## Built-in acceptance checks

| Sample button | Packet records read | IP packets | Directional flows | DNS packets | Review alerts | Informational observations |
|---|---:|---:|---:|---:|---:|---:|
| Normal PCAP | 6 | 6 | 4 | 2 | 0 | 0 |
| Normal PCAPNG | 6 | 6 | 4 | 2 | 0 | 0 |
| Review patterns | 19 | 19 | 14 | 7 | 3 | 0 |
| Plaintext HTTP | 1 | 1 | 1 | 0 | 0 | 1 |
| Parsing gaps | 7 | 6 | 4 | 2 | 0 | 0 |

Normal captures contain one UDP DNS query and one response, plus four TCP packets. The response illustrates NOERROR header/question metadata; the tool does not decode or claim an answer IP.

The review sample demonstrates many SYN destination ports, repeated DNS header response codes of 3, and a long DNS label. The HTTP sample contains synthetic request text and a synthetic authorization placeholder to test that payloads are not exported. Parsing gaps adds one truncated/incomplete Ethernet frame: expect **PARTIAL**, one packet with coverage issues, and one capture-truncated packet.

Load a sample, then click Investigate capture. Samples reset the SYN-port threshold to 10. Export JSON and flows CSV, then print/save a PDF. Synthetic captures use documentation IPs and `.test` names; the sample builder writes bytes to files and does not transmit packets.

## What is supported

### Capture containers

- Classic PCAP version 2.4, little or big endian, microsecond or nanosecond timestamps.
- PCAPNG section version 1.0, little or big endian, interface description blocks and enhanced packet blocks.
- Per-interface decimal/binary timestamp resolution and timestamp offset options; multiple sections/interfaces remain separate.
- Simple Packet Blocks are read using the first interface and explicitly marked as having no timestamp. They are excluded from time-window rules; non-time rules may still inspect their available packet metadata.
- Obsolete Packet Blocks are counted as unsupported packet records with diagnostics. Unknown non-packet metadata blocks are ignored and counted; comments, name-resolution, secrets and interface-statistics contents are not exported.

Limits: 10 MiB per input, at most 20,000 packet records, and 262,144 captured bytes per packet. Compressed captures, ZIP files, modified-PCAP variants, unsupported section versions and other capture formats are not supported. The filename extension is not trusted; signatures and bounds are checked.

If corruption occurs after valid records, the readable prefix is retained and the report is **PARTIAL**. Subsequent records/blocks are not read. Counts then describe records read, not the total traffic originally captured. If no valid prefix can be read, invalid captures are rejected. A valid empty capture is reported as having no packets, with no traffic assessment.

### Packet metadata profile

- Ethernet, up to four 802.1Q/802.1ad VLAN tags, raw IP linktypes 101/228/229, and Linux cooked v1/v2 linktypes 113/276.
- IPv4 and IPv6 base address/header fields.
- Direct TCP/UDP headers, TCP flag bytes, basic ICMP/ICMPv6 header availability.
- ARP EtherType identification only; ARP address fields or spoofing are not analyzed.
- UDP port 53 DNS header fields and up to 16 question entries. DNS names support bounded backward compression pointers; binary label bytes are escaped for display. Types/classes are numeric. Answer records, DNSSEC validation, EDNS extended RCODEs and transaction matching are not performed.
- Complete HTTP/1.x request-line markers at the start of an individual TCP payload. Only the method marker is retained; paths, headers, authorization text and bodies are withheld.

IPv4 fragments, IPv6 extension/fragment chains, Wi-Fi/loopback encapsulations, unknown network types/protocols, short or malformed headers and invalid lengths produce visible coverage diagnostics. Some address metadata can still be summarized when transport metadata is unavailable. TCP DNS, DoH/DoT, QUIC, TLS contents, arbitrary applications, TCP stream reconstruction, IP reassembly and checksum validation are outside the profile.

**PROFILE DECODED** means only that the supported metadata profile was decoded without recorded issues, not that all traffic content is understood or the capture is benign.

## Flows, volume and evidence

Flows are grouped by **interface, source IP, destination IP, protocol, source port and destination port**. Reverse traffic appears in another row. They are not TCP sessions or proof of a completed connection. Rows with unavailable ports retain null values; do not treat those as known application endpoints.

Each flow includes packet count, captured-frame byte count, unverified original-wire lengths from the file, time range and example frame numbers. Captured bytes include link/network/transport headers; they are not application payload or unique transferred bytes. Retransmissions and duplicate/mirrored packets are counted. Interfaces/sections are kept separate to reduce cross-interface mixing; their clocks and identities are not verified.

DNS rows aggregate question metadata by interface, source/destination, name, type, response flag and low-four-bit RCODE, with an example frame. DNS packet counts count packets, not unique queries/transactions. Queries display no response-code interpretation. No DNS question is resolved by the tool.

## Review patterns

| Rule | Criterion | Interpretation |
|---|---|---|
| PCI-001 | At least 10 distinct TCP SYN destination ports without ACK to the same destination within 60 seconds, grouped by interface/source/destination | Can resemble probing; administrative tools and other activity can share the pattern. No scan outcome is established. Threshold adjustable from 3–100. |
| PCI-002 | At least 5 UDP DNS responses with header RCODE low bits equal to 3 within 60 seconds, grouped by interface/source/destination | Can reflect NXDOMAIN responses, typos, retries or misconfiguration. EDNS extended codes and transaction authenticity are not checked. |
| PCI-003 | At least one UDP DNS query with a label ≥50 bytes or name ≥180 wire bytes | Long-name observation only; not proof of DNS tunneling or exfiltration. |
| PCI-004 | HTTP/1.x request markers observed | Informational plaintext-protocol observation, not proof that sensitive information was exposed. |

Time-window rules use recorded timestamps, sorted for analysis, and include both window endpoints. Untimed/out-of-range timestamp records are excluded from those rules. Timestamps are normalized to UTC; nanosecond integers are used for window comparisons. PCAPNG fractional timestamps finer than one nanosecond are floored to nanoseconds. No clock-skew correction, interface-clock alignment or deduplication is performed.

Each time-window rule returns its strongest qualifying window per interface/source/destination grouping, not every episode. Name-length and HTTP observations aggregate matching packets per such grouping. The report includes thresholds, observed metrics, timestamps and up to 20 frame references per observation. Overlapping rules do not represent separate confirmed incidents. No overall security score or malware verdict is assigned.

## Report limits and privacy

Reports return up to 500 flow rows, 200 DNS metadata rows, 200 packet previews, 200 alert/observation details, and 50 packet diagnostics. Omitted-detail counts and full aggregate/rule counts are explicit. CSV exports the returned flow rows only; alert and parser context is in JSON/the printable report. Large expanded print reports can span many pages.

The original input SHA-256 identifies file bytes, not authenticity. Frame references are 1-based file packet-record numbers; unsupported packet blocks still occupy a number. Malformed trailing records that cannot be read do not become fabricated frames. Use the original capture to inspect payloads or details outside the preview.

The application processes uploads in memory and does not intentionally retain input/report history. Captures are not sent to external services. The browser connects only to the local UI server. Explicit exports and CLI options write report files. Browser/OS memory, user downloads and operating-system behavior are outside this guarantee. Clear session removes current UI input/results; downloaded files remain.

Raw packet bytes, HTTP paths/headers/bodies and capture-secret blocks are not exported. Reports still expose IPs, ports, DNS question names, timestamps, capture filenames and hashes. DNS names may carry sensitive or attacker-controlled content, including encoded data. Review before sharing. Results are rendered as text; DNS names are not clickable links.

## Command line

From CMD inside the project folder:

```bat
py -3.12 analyzer.py examples\normal.pcap --out reports\normal.json --csv reports\flows.csv
py -3.12 analyzer.py examples\suspicious.pcap --port-threshold 10 --out reports\review.json
```

Use a file you are authorized to inspect. Exit code 0 means the metadata profile decoded without recorded coverage issues; it does not mean no alerts or safe traffic. Exit 1 indicates partial/empty coverage; exit 2 indicates file/configuration/parser failure.

## Project layout

```text
capture.py                   Bounded PCAP and documented PCAPNG readers
analyzer.py                  Metadata decoders, summaries, review rules, CLI/CSV
server.py                    Local browser upload/report service
sample_builder.py            Offline synthetic sample file generator
static/                      Interface, styles and exports
start_windows.cmd            Windows Python 3.12 launcher
examples/                    Five synthetic captures plus generated sample reports
tests/test_tool.py           Container, protocol, rule and HTTP integration tests
VALIDATION.md                What was tested and remaining limitations
```

Regenerate examples without network activity:

```bat
py -3.12 sample_builder.py
```

Run tests:

```bat
py -3.12 -m unittest discover -s tests -v
```

This is a single-user localhost prototype with Host/Origin/custom-header checks, upload limits, static-route allowlisting, a restrictive CSP and text rendering. It has no authentication, sandboxed parser process, production deployment hardening, multi-user isolation or SIEM integration. Keep it local. This small decoder is not a replacement for Wireshark's comprehensive dissectors, and has not been fuzz-tested or independently audited for hostile capture files.

## References

- Wireshark capture formats: https://www.wireshark.org/docs/wsug_html_chunked/ChIOOpenSection.html
- PCAP format: https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcap/
- PCAPNG format: https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcapng/
- DNS questions/compression: https://www.rfc-editor.org/rfc/rfc1035.html
