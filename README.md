# Network Packet Analyzer & Security Dashboard

A Python-based network analysis tool that captures and analyzes traffic in
real-time or from saved PCAP files, detects common attack patterns, and
generates an interactive visual security dashboard.

## What it does

- Sniffs live network traffic or reads from an existing `.pcap` file
- Detects Nmap SYN port scans by tracking per-IP SYN flag counts
- Identifies Metasploit exploit signatures in TCP payloads (`meterpreter`,
  shellcode NOP sleds, reverse shell strings)
- Flags unencrypted HTTP traffic, FTP, and Telnet connections
- Detects SQLi and XSS patterns in HTTP request paths
- Exports results to CSV and generates an interactive HTML dashboard using Plotly
- Shows a Seaborn bar chart of the top 5 most active IPs alongside a
  color-coded risk donut chart

## Tools & Libraries

- [Scapy](https://scapy.net/) — packet capture and parsing (requires Npcap on Windows)
- Pandas — data structuring and CSV export
- Plotly — interactive 3D scatter + donut chart dashboard
- Matplotlib / Seaborn — static summary charts

## Setup

Install dependencies:

```bash
pip install scapy pandas plotly matplotlib seaborn numpy
```

On Windows, also install [Npcap](https://npcap.com/) for live packet capture.

## Usage

```bash
python network_sniffer.py
```

Choose your mode when prompted:
- **Mode 1** — Live sniffing, captures 100 packets from your active interface
- **Mode 2** — PCAP analysis, provide a path to any `.pcap` file (e.g. from Wireshark)

After capture, results are saved to `network_log.csv` and a dashboard opens
automatically in your browser as `security_dashboard.html`.

## Detection categories

| Category | Trigger |
|----------|---------|
| Nmap Scan Detected | >15 unique ports hit from same source IP via SYN |
| Metasploit Exploit | Known payload signatures in TCP raw data |
| Possible SQLi/XSS | `'`, `union select`, `<script>`, `javascript:` in HTTP path |
| Warning: Unencrypted HTTP | Port 80 traffic |
| Critical Risk | Traffic on FTP (21) or Telnet (23) |
| Bulk Data Transfer | Packets over 1200 bytes |

## Note

For educational and authorized network monitoring purposes only.
Live sniffing requires administrator/root privileges.
