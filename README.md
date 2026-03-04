# sharkviz

A fast Rust tool that reads a `.pcap` file, analyzes every packet across all OSI layers, and generates a **self-contained interactive HTML report** — no server, no dependencies, just open the file in a browser.

---

## Installing Rust

Rust is installed via `rustup`, the official Rust toolchain manager. It works on macOS, Linux, and Windows.

### macOS / Linux

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Follow the on-screen prompts (the defaults are fine) to add the path to your shell. Then reload your shell.

### Windows

Download and run the installer from [rustup.rs](https://rustup.rs). You will also need the [Microsoft C++ Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/) if not already installed.

### Verify installation

```bash
rustc --version
cargo --version
```

You should see something like `rustc 1.78.0` and `cargo 1.78.0`. Any version **1.70 or newer** works.

### Updating Rust

```bash
rustup update
```
---

## What sharkviz does

`sharkviz` parses each packet in a capture and extracts structured data for all reachable OSI layers:

| OSI Layer | What's extracted |
|---|---|
| **L1 Physical** | Frame size, link type, min/avg/max byte counts |
| **L2 Data Link** | Src/Dst MAC, Ethertype, 802.1Q VLAN ID, frame type |
| **L3 Network** | IPv4/IPv6/ARP: src/dst IP, TTL/hop limit, DSCP, ECN, flags (DF/MF), fragment offset, IP ID, checksum, IPv6 flow label |
| **L4 Transport** | TCP: seq/ack, flags (SYN/ACK/FIN/RST/PSH/URG/ECE/CWR), window size, checksum, data offset · UDP: length, checksum · ICMP/ICMPv6: type, code, human-readable description |
| **L5–L6 Session/Presentation** | TLS version detection, encryption status |
| **L7 Application** | Protocol identification (HTTP, DNS, TLS, DHCP, mDNS, NTP, QUIC, SSH, SMTP, SSDP/UPnP), request/response lines, DNS query/response details, DHCP message types and hostnames, payload byte count, ASCII payload preview |

---

## The Report

The output is a **single `.html` file** with all packet data embedded as JSON. Open it in any browser — no internet connection needed.

### Interface

```
┌──────────────────────────────────────────────────────┐
│  ⬡  sharkviz        41,391 pkts  30MB  2 src  1 flow │
├──────────────┬───────────────────────────────────────┤
│ Source ▾     │                                       │
│ Destination ▾│   OSI Layer Stack  ←→  OSI Layer Stack│
│ [ANALYZE]    │    (Outbound)            (Inbound)    │
│              │                                       │
│ Flow metrics │    L1 Physical ▶                      │
│ proto tags   │    L2 Data Link ▶                     │
│              │    L3 Network ▶                       │
│ Protocol     │    L4 Transport ▶                     │
│ histogram    │    L5-6 Session/Pres ▶                │
│              │    L7 Application ▶                   │
│              │                                       │
│              │    [Packet Timeline Grid]             │
│              │    Click any packet for full detail   │
└──────────────┴───────────────────────────────────────┘
```

### Controls

1. **Source dropdown** — lists every unique source IP (or MAC if no IP layer) found in the capture, sorted numerically
2. **Destination dropdown** — dynamically populated with only the destinations that have traffic to/from the selected source
3. **Analyze Flow** — builds the full OSI visualization for that pair
4. **OSI panels** — two side-by-side panels: Outbound (src→dst) and Inbound (dst→src). Each layer is collapsible. Click any layer header to expand it.
5. **Packet timeline** — a color-coded grid of every packet in the flow, ordered by frame number. Colors: green=TCP-out, orange=TCP-in, cyan=UDP, yellow=ICMP, purple=TLS
6. **Packet detail** — click any cell in the timeline to see every parsed field for that individual packet across all layers

---

## Build

```bash
# Requires Rust 1.70+  (https://rustup.rs)
cd sharkviz
cargo build --release
# Binary: target/release/sharkviz
```

---

## Usage

```
sharkviz [OPTIONS] --input <INPUT>

Options:
  -i, --input <INPUT>      Input .pcap file
  -o, --output <OUTPUT>    Output HTML report file [default: report.html]
  -t, --title <TITLE>      Title shown in the report [default: "Network Capture Analysis"]
  -h, --help               Print help
  -V, --version            Print version
```

### Basic

```bash
./sharkviz -i capture.pcap
# Creates report.html in current directory
```

### Custom html output file name and title

```bash
./sharkviz \
  -i capture.pcap \
  -o analysis.html \
  --title "Incident Response — 2025-03-04"
```

### Using with The Ultimate PCAP

```bash
./sharkviz \
  -i ultimate.pcap \
  -o ultimate_analysis.html \
  --title "Ultimate PCAP — OSI Analysis"
```
---

## Limitations

- **Legacy pcap only** — `.pcapng` not supported. Convert first:
  ```bash
  editcap -F pcap input.pcapng output.pcap
  ```
- **Encrypted payloads** — TLS/HTTPS content cannot be decoded without keys. The tool detects TLS and reports the handshake type, but application-layer content inside encrypted sessions is not visible. TLS SNI is not extracted (use `capwash - https://github.com/adamhott/capwash with the flag --redact-tls-sni` before analyzing if you want SNI logged separately).
- **Large captures** — All packet data is embedded in the HTML. For very large captures (>100k packets), the HTML file may be large and take a few seconds to load. The tool processes 41k packets in ~2 seconds.
- **Flow matching** — Flows are matched bidirectionally by IP address (or MAC if no IP layer). If a capture contains NAT or proxied traffic, the IP-based flow view will reflect the post-NAT addresses.
- **Checksum validation** — Checksums are extracted and displayed but not verified. Wireshark-offloaded captures often show incorrect checksums.

---

## Example output stats

```
Opening "ultimate.pcap"
Parsing packets...
Parsed 41,391 packets, building flows...
Building HTML report...
Done! Report written to "report.html"
  Flows:    847
  Sources:  23
  Duration: 142.3s
```

---

## How it relates to capwash

These two tools are complementary:

| Tool | Purpose |
|---|---|
| `capwash` | Sanitize a capture before sharing — remove IPs, MACs, credentials, fingerprints |
| `sharkviz` | Analyze a capture — explore OSI layers, protocol distribution, per-flow traffic |

**Recommended workflow:**
```bash
# 1. Analyze the raw capture
./sharkviz -i raw.pcap -o analysis_raw.html

# 2. Redact before sharing (check for proper flags)
./capwash -i raw.pcap -o redacted.pcap --flags

# 3. Verify redaction didn't destroy protocol structure
./sharkviz -i redacted.pcap -o analysis_redacted.html
```
