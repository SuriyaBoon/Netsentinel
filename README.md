# NetSentinel — Network Recon & Port Scanner

A multithreaded Python CLI tool for host discovery, port scanning, and
service fingerprinting — built from scratch to understand how tools like
Nmap actually work under the hood, rather than just how to run them.

Built alongside Google Cybersecurity coursework and HackTheBox retired-
machine practice; the scan methodology (discovery → port scan → service
fingerprint) mirrors real-world enumeration workflows.

## Features

- **Host discovery** — concurrent ping sweep across a subnet (CIDR-aware),
  with automatic fallback to TCP-based liveness checks if ICMP is
  blocked or `ping` isn't available on the system.
- **TCP connect scan** — full three-way-handshake scanning via
  `socket.connect_ex()`. No special privileges required.
- **TCP SYN scan** — hand-rolled "half-open" scan using raw sockets
  (manually crafted IP/TCP headers + checksums). Requires root /
  `CAP_NET_RAW`. Sends a RST after a SYN/ACK to avoid leaving
  half-open connections behind.
- **UDP scan** — empty-datagram probing with open / closed /
  open|filtered classification.
- **Banner grabbing / service fingerprinting** — listens for
  unprompted banners (SSH, FTP, SMTP) and falls back to an HTTP probe
  for anything that stays silent, so it isn't limited to a hardcoded
  list of "web" ports.
- **Multithreaded** — configurable thread pool and per-probe timeout;
  scans a /24 in seconds rather than minutes.
- **Structured output** — colour-coded terminal report plus a
  machine-readable JSON export (`-o report.json`).
- **Optional Shodan enrichment** — cross-references a public target IP
  against Shodan's index (org, known open ports, known CVEs) for
  external attack-surface context during recon.

## Installation

```bash
git clone https://github.com/SuriyaBoon/netsentinel.git
cd netsentinel
pip install -e .
```

No third-party dependencies are required for the core tool — it's
built entirely on the Python standard library (`socket`, `struct`,
`threading`, `concurrent.futures`). `requests`/`pytest` are only used
for optional extras and the test suite.

## Usage

```text
netsentinel --target <IP|CIDR|hostname> [options]

  -t, --target        IP, hostname, or CIDR (e.g. 192.168.1.0/24)   [required]
  -p, --ports         Port spec: '22,80,443' | '1-1024' | 'top100'  (default: 1-1024)
  -m, --mode          Comma-separated: tcp, syn, udp, banner        (default: tcp)
      --threads       Thread pool size                              (default: 100)
      --timeout       Per-probe timeout in seconds                  (default: 1.0)
      --discover-only Only run host discovery, skip port scanning
      --skip-discovery Skip discovery, scan all targets directly
  -o, --output        Write JSON report to FILE
      --shodan-key    Shodan API key (or set SHODAN_API_KEY env var)
      --no-color      Disable coloured terminal output
```

### Examples

```bash
# Find live hosts on a /24 without scanning anything
netsentinel --target 192.168.1.0/24 --discover-only

# Standard TCP connect scan + service banners on one host
netsentinel --target 192.168.1.10 --ports 1-1024 --mode tcp,banner

# Half-open SYN scan (root required) across the top 100 common ports
sudo netsentinel --target 10.0.0.5 --ports top100 --mode syn

# UDP scan of common infrastructure ports
netsentinel --target 10.0.0.5 --ports 53,67,123,161 --mode udp

# Full subnet recon with JSON export for later reporting
netsentinel --target 10.0.0.0/24 --ports top100 --mode tcp,banner -o report.json
```

### Sample output

```text
[*] NetSentinel — target=192.168.1.10 ports=1024 mode=banner,tcp threads=100
[*] Discovering live hosts among 1 candidate(s)...
[+] 1 host(s) alive (0.4s)
    192.168.1.10

192.168.1.10  (3 open / 1024 scanned)
     22/tcp OPEN       ssh   — SSH-2.0-OpenSSH_8.9p1
     80/tcp OPEN       http  — HTTP/1.1 200 OK
    443/tcp OPEN       https

[+] JSON report written to report.json
```

## How the SYN scan works

Rather than reaching for `scapy`, the SYN scanner builds raw IP and TCP
headers by hand with `struct.pack`, computes the IP/TCP checksums, and
sends the packet through a `SOCK_RAW` socket with `IP_HDRINCL` set. A
second raw socket listens for the matching SYN/ACK (open) or RST
(closed) response. This was deliberately implemented from scratch as a
learning exercise in how the TCP handshake and IP/TCP header format
work at the byte level — the same fundamentals Nmap's SYN scan (`-sS`)
is built on.

## Project structure

```
netsentinel/
├── netsentinel/
│   ├── cli.py            # argparse entrypoint, orchestrates a full scan
│   ├── discovery.py       # host discovery / ping sweep
│   ├── scanner.py          # TCP connect, TCP SYN, UDP scan engines
│   ├── banner.py            # service fingerprinting / banner grabbing
│   ├── report.py             # colour terminal + JSON reporting
│   └── shodan_enrich.py       # optional Shodan API lookups
├── tests/
│   └── test_netsentinel.py     # pytest suite (parsing, discovery, live scans)
├── requirements.txt
└── setup.py
```

## Testing

```bash
pip install -e ".[dev]"   # or: pip install pytest
pytest tests/ -v
```

Tests spin up a local server on loopback so they run anywhere without
needing real network targets.

## Legal / responsible use

This tool is intended for scanning systems you own or are explicitly
authorized to test (home lab, CTF targets, employer-sanctioned
assessments). Port scanning networks you don't have permission to test
may violate laws such as the U.S. Computer Fraud and Abuse Act or
equivalent legislation elsewhere. Always get authorization first.

## Author

Suriya Boonsanong — [github.com/SuriyaBoon](https://github.com/SuriyaBoon)
