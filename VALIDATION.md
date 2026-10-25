# Validation — PCAP Investigation Tool 0.1.0

Validated on 2026-10-25 in Linux with Python 3.12.14.

## Passed

- 40 automated tests: `python -m unittest discover -s tests -v`.
- PCAP micro/nanosecond timestamps and both byte orders; PCAPNG byte orders, binary resolution, timestamp offsets, enhanced/simple packet blocks, sections/interfaces, unknown interface and trailer/record bounds.
- Classic-PCAP and PCAPNG normal fixtures return identical aggregate statistics and time ranges.
- `file` independently identifies normal.pcap as little-endian microsecond PCAP 2.4/Ethernet, and normal.pcapng as PCAPNG version 1.0. This confirms signatures/format recognition, not full dissection equivalence.
- Ethernet/VLAN, raw IP, Linux cooked headers, IPv4 fragment exclusion, basic IPv6/direct UDP, and explicit IPv6-extension coverage gaps.
- DNS query/response headers, backward compression, pointer cycles/forward-pointer rejection, short data, and question-count limits.
- Threshold and inclusive-window boundaries, retransmission-resistant distinct-port counting, SYN-ACK exclusion, destination/interface scoping, out-of-order capture timestamps, and sample rule counts.
- HTTP request paths, authorization placeholders and raw payload text are absent from JSON and flows CSV.
- No-network analysis test blocks socket/DNS calls while capture analysis succeeds.
- Real loopback upload-to-report test returns six packets from the PCAPNG sample and generates CSV. Origin/custom-header restrictions, sample endpoints and static routes are checked.
- JavaScript syntax and UI element references passed; results use text nodes and no browser-storage calls.

## Expected sample results

Normal PCAP and Normal PCAPNG: 6 packet records / 6 IP packets / 4 directional flows / 2 DNS packets / 0 review alerts.

Review patterns: 19 packet records / 19 IP packets / 14 directional flows / 7 DNS packets / 3 review alerts (one each for PCI-001/002/003).

Plaintext HTTP: 1 packet / 1 IP packet / 1 flow / 0 review alerts / 1 informational observation.

Parsing gaps: 7 packet records / 6 IP packets / 4 flows / 1 packet with issues / PARTIAL.

## Not verified

- Windows execution, actual browser layout, downloads/print dialogs, mobile display and accessibility require local verification. No visual browser test was run.
- No comparison against Wireshark/TShark dissection on a diverse independent capture corpus. `file` recognizes the generated formats, but full interoperability and decoder accuracy have not been independently established.
- No production traffic benchmark, incident-labeled precision/recall measurement, fuzz testing, parser isolation or security audit. The reader supports the documented subset, not all PCAPNG or packet formats.
- No live capture, packet transmission, decryption, reassembly, checksum verification, external enrichment, or incident-response action.

## Local acceptance check

Start `start_windows.cmd`, open http://127.0.0.1:8810, and analyze Normal PCAP. Verify the expected counts, then Normal PCAPNG and Review patterns. Examine frame references, DNS rows and directional flow rows. Use Plaintext HTTP and Parsing gaps to confirm informational observations and coverage diagnostics. Export JSON/flows CSV and print/save a PDF. Original capture samples can also be opened in Wireshark for independent comparison if it is installed.
