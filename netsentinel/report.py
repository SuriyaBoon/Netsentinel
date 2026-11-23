"""
report.py — Terminal (colour-coded) and structured JSON reporting.
"""

import json
from typing import Dict, List

from .scanner import PortResult

# ANSI colour codes (no external dependency; degrade gracefully on
# terminals that don't support them).
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

STATE_COLOR = {
    "open": GREEN,
    "closed": RED,
    "filtered": YELLOW,
    "open|filtered": YELLOW,
}


def _color(text: str, code: str, use_color: bool) -> str:
    return f"{code}{text}{RESET}" if use_color else text


def print_host_results(host: str, results: List[PortResult], use_color: bool = True) -> None:
    open_results = [r for r in results if r.state.startswith("open")]
    print(f"\n{_color(BOLD + host, CYAN, use_color)}  "
          f"({len(open_results)} open / {len(results)} scanned)")
    if not open_results:
        print("  no open ports found")
        return
    for r in sorted(open_results, key=lambda x: x.port):
        state_str = _color(r.state.upper(), STATE_COLOR.get(r.state, ""), use_color)
        service = f" {r.service_guess}" if r.service_guess else ""
        banner = f"  — {r.banner}" if r.banner else ""
        print(f"  {r.port:>5}/{r.protocol:<3} {state_str:<10}{service}{banner}")


def build_json_report(scan_results: Dict[str, List[PortResult]], meta: dict) -> dict:
    return {
        "meta": meta,
        "hosts": {
            host: [
                {
                    "port": r.port,
                    "protocol": r.protocol,
                    "state": r.state,
                    "service": r.service_guess,
                    "banner": r.banner,
                }
                for r in results
            ]
            for host, results in scan_results.items()
        },
    }


def write_json_report(path: str, scan_results: Dict[str, List[PortResult]], meta: dict) -> None:
    report = build_json_report(scan_results, meta)
    with open(path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\n[+] JSON report written to {path}")
