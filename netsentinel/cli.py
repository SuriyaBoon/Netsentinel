"""
cli.py — NetSentinel command-line entrypoint.

Examples:
  # Discover live hosts on a subnet
  netsentinel --target 192.168.1.0/24 --discover-only

  # TCP connect scan of common ports on one host
  netsentinel --target 192.168.1.10 --ports 1-1024 --mode tcp

  # TCP SYN scan (requires sudo) + banner grabbing + JSON export
  sudo netsentinel --target 10.0.0.5 --ports 1-1000 --mode syn,banner -o scan.json

  # UDP scan
  netsentinel --target 10.0.0.5 --ports 53,67,123,161 --mode udp

  # Full subnet sweep + scan with Shodan enrichment
  netsentinel --target 10.0.0.0/24 --ports top100 --mode tcp,banner \
      --shodan-key $SHODAN_API_KEY -o report.json
"""

import argparse
import os
import sys
import time
from typing import List, Optional

from . import discovery, scanner, banner, report

TOP_100_PORTS = (
    "7,9,13,21,22,23,25,26,37,53,79,80,81,88,106,110,111,113,119,135,139,143,144,"
    "179,199,389,427,443,444,445,465,513,514,515,543,544,548,554,587,631,646,873,"
    "990,993,995,1025,1026,1027,1028,1029,1110,1433,1720,1723,1755,1900,2000,2001,"
    "2049,2121,2717,3000,3128,3306,3389,3986,4899,5000,5009,5051,5060,5101,5190,"
    "5357,5432,5631,5666,5800,5900,6000,6001,6646,7070,8000,8008,8009,8080,8081,"
    "8443,8888,9100,9999,10000,32768,49152,49153,49154,49155,49156,49157"
)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="netsentinel",
        description="NetSentinel — multithreaded network recon & port scanner",
    )
    p.add_argument("--target", "-t", required=True,
                    help="IP, hostname, or CIDR range (e.g. 192.168.1.0/24)")
    p.add_argument("--ports", "-p", default="1-1024",
                    help="Port spec: '22,80,443', '1-1024', or 'top100' (default: 1-1024)")
    p.add_argument("--mode", "-m", default="tcp",
                    help="Comma-separated: tcp, syn, udp, banner (default: tcp)")
    p.add_argument("--threads", type=int, default=100,
                    help="Thread pool size (default: 100)")
    p.add_argument("--timeout", type=float, default=1.0,
                    help="Per-probe timeout in seconds (default: 1.0)")
    p.add_argument("--discover-only", action="store_true",
                    help="Only run host discovery (ping sweep), skip port scanning")
    p.add_argument("--skip-discovery", action="store_true",
                    help="Skip host discovery and scan all targets directly")
    p.add_argument("-o", "--output", metavar="FILE",
                    help="Write structured JSON report to FILE")
    p.add_argument("--shodan-key", metavar="KEY", default=os.environ.get("SHODAN_API_KEY"),
                    help="Shodan API key for public-IP enrichment (or set SHODAN_API_KEY)")
    p.add_argument("--no-color", action="store_true", help="Disable colored output")
    return p


def _resolve_live_hosts(args, candidates: List[str], use_color: bool) -> List[str]:
    """Run host discovery unless --skip-discovery is set; return live hosts."""
    if args.skip_discovery:
        return candidates
    print(f"[*] Discovering live hosts among {len(candidates)} candidate(s)...")
    t0 = time.time()
    live_hosts = discovery.sweep(candidates, threads=min(args.threads, 200))
    print(f"[+] {len(live_hosts)} host(s) alive ({time.time() - t0:.1f}s)")
    for h in live_hosts:
        print(f"    {h}")
    return live_hosts


def _scan_single_host(
    host: str,
    ports: List[int],
    modes: set[str],
    threads: int,
    timeout: float,
    use_color: bool,
    shodan_key: Optional[str],
) -> List:
    """Scan one host across all enabled modes and report results."""
    results = []
    if "tcp" in modes:
        results += scanner.tcp_connect_scan(host, ports, threads, timeout)
    if "syn" in modes:
        try:
            results += scanner.tcp_syn_scan(host, ports, threads, timeout)
        except PermissionError as exc:
            print(f"[!] {exc}")
    if "udp" in modes:
        results += scanner.udp_scan(host, ports, min(threads, 100), max(timeout, 1.5))

    if "banner" in modes:
        for r in results:
            if r.state == "open" and r.protocol == "tcp":
                r.banner = banner.grab_banner(host, r.port, timeout=timeout + 1)
            r.service_guess = banner.guess_service(r.port, r.banner)
    else:
        for r in results:
            r.service_guess = banner.guess_service(r.port, None)

    report.print_host_results(host, results, use_color=use_color)

    if shodan_key:
        from . import shodan_enrich
        info = shodan_enrich.enrich(host, shodan_key)
        if info:
            print(f"  [shodan] org={info['org']} country={info['country']} "
                  f"known_open_ports={info['known_open_ports']}")
            if info["vulns"]:
                print(f"  [shodan] known CVEs: {', '.join(info['vulns'][:10])}")

    return results


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    modes = {m.strip().lower() for m in args.mode.split(",")}
    use_color = not args.no_color and sys.stdout.isatty()

    port_spec = TOP_100_PORTS if args.ports == "top100" else args.ports
    try:
        ports = scanner.parse_port_spec(port_spec)
    except ValueError as exc:
        print(f"[!] Invalid --ports value: {exc}")
        return 2

    print(f"[*] NetSentinel — target={args.target} ports={len(ports)} "
          f"mode={','.join(sorted(modes))} threads={args.threads}")

    candidates = discovery.expand_targets(args.target)
    live_hosts = _resolve_live_hosts(args, candidates, use_color)

    if args.discover_only or not live_hosts:
        return 0

    all_results = {}
    for host in live_hosts:
        results = _scan_single_host(
            host, ports, modes, args.threads, args.timeout,
            use_color, args.shodan_key,
        )
        all_results[host] = results

    if args.output:
        meta = {
            "target": args.target,
            "ports_scanned": len(ports),
            "mode": sorted(modes),
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        }
        report.write_json_report(args.output, all_results, meta)

    return 0


if __name__ == "__main__":
    sys.exit(main())
