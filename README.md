# NetSentinel — Network Recon & Port Scanner

A multithreaded Python CLI tool for host discovery, port scanning, and
service fingerprinting — built from scratch to understand how tools like
Nmap actually work under the hood, rather than just how to run them.

Built alongside Google Cybersecurity coursework and HackTheBox retired-machine practice; the scan methodology (discovery → port scan → service
fingerprint) mirrors real-world enumeration workflows.

## Features

- **Zero runtime dependencies** — pure Python standard library (`>=3.8`).
  Core uses only `socket`, `struct`, `threading`, `concurrent.futures`,
  `argparse`, `ssl`, `json`, `ipaddress`, `platform`, `shutil`, `time`,
  `os`, `sys`, `urllib`, and `random`.
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
- **2-step TLS/HTTPS inspection** (`grab_tls_banner`) — on TLS ports
  (`443`, `465`, `993`, `995`, `6443`, `8443`, `9443`) performs a verified
  `ssl.create_default_context()` handshake to capture TLS version,
  certificate `commonName` / first SAN DNS entry, `expires` expiry, and
  the inner `HEAD / HTTP/1.0` banner line; on `ssl.SSLCertVerificationError`
  (self-signed certs or raw IP targets) automatically retries with an
  unverified `CERT_NONE` context tagged `[unverified-cert]` so inspection
  still succeeds without crashing. Non-TLS ports keep the plain banner flow.
- **`--open` filter** — keeps only `state == "open"` results before
  terminal printing and JSON export, hiding closed/filtered ports.
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
built entirely on the Python standard library. `pytest`, `ruff`, and
`mypy` are dev-only tooling (used by tests, linting, typechecking, and CI).

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
      --open          Only show open ports in terminal and JSON output
      --no-color      Disable coloured terminal output
```

### Port spec (`--ports`)

Accepts comma-separated ports (`22,80,443`), ranges (`1-1024`), or the
`top100` preset. Empty tokens, non-numeric values, and incomplete or
multi-dash ranges (`"80-"`, `"-80"`, `"80-90-100"`, `""`, `"80,,443"`) are
rejected with `[!] Invalid --ports value: ...` and exit code `2`.

Reversed ranges (`"443-80"`) are also rejected with exit code `2`.

### Target validation (`--target`)

Target specifications are validated before scanning. Empty targets,
targets containing whitespace, flag-like arguments starting with `-`
(e.g., `-t`, `--help`), and CIDR networks larger than `/16` (65,536
addresses) are rejected with `[!] Invalid --target value: ...` and
exit code `2`. Hostnames are passed through unchanged.

### Examples

```bash
# Find live hosts on a /24 without scanning anything
netsentinel --target 192.168.1.0/24 --discover-only

# Skip discovery and scan loopback directly
netsentinel --target 127.0.0.1 --skip-discovery --ports 22,80 --mode tcp

# Standard TCP connect scan + service banners on one host
netsentinel --target 192.168.1.10 --ports 1-1024 --mode tcp,banner

# Half-open SYN scan (root required) across the top 100 common ports
sudo netsentinel --target 10.0.0.5 --ports top100 --mode syn

# UDP scan of common infrastructure ports
netsentinel --target 10.0.0.5 --ports 53,67,123,161 --mode udp

# TLS/HTTPS inspection with self-signed-cert fallback, open ports only
netsentinel --target 10.0.0.5 --ports 443,8443,9443 --mode tcp,banner --open

# Full subnet recon with JSON export for later reporting
netsentinel --target 10.0.0.0/24 --ports top100 --mode tcp,banner -o report.json

# Full subnet recon with Shodan enrichment
netsentinel --target 10.0.0.0/24 --ports top100 --mode tcp,banner \
    --shodan-key $SHODAN_API_KEY -o report.json
```

### Privilege notes (`--mode syn`)

The SYN scanner opens a `SOCK_RAW` socket, which requires elevated
privileges:

- **POSIX (Linux/macOS):** run with `sudo` or `CAP_NET_RAW`.
- **Windows:** `os.geteuid()` does not exist, so NetSentinel raises a
  clean `PermissionError` (not `AttributeError`) and suggests using
  `--mode tcp` for a privilege-free connect scan instead.
- `cli.main` catches `PermissionError` and continues scanning other
  modes rather than crashing with a traceback.

### Sample output

```text
[*] NetSentinel — target=192.168.1.10 ports=1024 mode=banner,tcp threads=100
[*] Discovering live hosts among 1 candidate(s)...
[+] 1 host(s) alive (0.4s)
    192.168.1.10

192.168.1.10  (3 open / 1024 scanned)
     22/tcp OPEN       ssh   — SSH-2.0-OpenSSH_8.9p1
     80/tcp OPEN       http  — HTTP/1.1 200 OK
    443/tcp OPEN       https — TLS TLSv1.3 | CN=example.com | expires Dec 31 23:59:59 2026 GMT | HTTP/1.0 200 OK

[+] JSON report written to report.json
```

With `--open`, the same scan prints only `22/tcp`, `80/tcp`, `443/tcp`
and the header reports `(3 open / 3 scanned)`.

## How the SYN scan works

Rather than reaching for `scapy`, the SYN scanner builds raw IP and TCP
headers by hand with `struct.pack`, computes the IP/TCP checksums in
network byte order (`!H`), and sends the packet through a `SOCK_RAW`
socket with `IP_HDRINCL` set. A second raw socket listens for the
matching SYN/ACK (open) or RST (closed) response, then sends a checksum-correct RST (flags `0x04`, seq = peer ACK) to tear down the half-open
connection cleanly. This was deliberately implemented from scratch as a
learning exercise in how the TCP handshake and IP/TCP header format work
at the byte level — the same fundamentals Nmap's SYN scan (`-sS`) is
built on.

## Project structure

```
netsentinel/
├── netsentinel/
│   ├── cli.py            # argparse entrypoint, orchestrates a full scan
│   ├── discovery.py       # host discovery / ping sweep
│   ├── scanner.py          # TCP connect, TCP SYN, UDP scan engines
│   ├── banner.py            # service fingerprinting + 2-step TLS inspection
│   ├── report.py             # colour terminal + JSON reporting
│   ├── shodan_enrich.py       # optional Shodan API lookups
│   └── __init__.py         # package metadata (__version__, __author__)
├── tests/
│   └── test_netsentinel.py     # pytest suite (parsing, discovery, live scans)
├── .github/
│   └── workflows/
│       └── ci.yml             # ruff + mypy + pytest on Ubuntu & Windows
├── requirements.txt
├── setup.py
└── pyproject.toml            # dev-only ruff + mypy configuration
```

## Development & Verification

Core runtime is stdlib-only and stays dependency-free; dev tools are
installed separately and are **not** added to `setup.py` `install_requires`.

```bash
# Install dev tools
pip install pytest ruff "mypy>=1.11,<1.15"

# Run the full test suite (49 loopback-safe tests, no root or network needed)
pytest tests/ -v

# Lint
ruff check .

# Typecheck (python_version 3.8 target)
mypy netsentinel tests
```

All three checks run on every push/PR via GitHub Actions CI
(`.github/workflows/ci.yml`) across a matrix of Ubuntu + Windows with
Python 3.10 and 3.12.

## Testing

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
