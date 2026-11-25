"""
shodan_enrich.py — Optional Shodan API enrichment for public IPs.

Adds external attack-surface context (known open ports, org, banners
Shodan has already indexed) for a target IP. Useful during the recon
phase to cross-reference active scan results against what's already
publicly visible. Requires a Shodan API key (free tier works for
basic host lookups).

This module makes a read-only GET request to Shodan's REST API and
does not perform any scanning itself.
"""

import ipaddress
import json
import socket
import urllib.error
import urllib.parse
import urllib.request
from typing import Optional


SHODAN_HOST_URL = "https://api.shodan.io/shodan/host/{ip}?key={key}"


def enrich(ip: str, api_key: str, timeout: float = 5.0) -> Optional[dict]:
    """
    Look up `ip` on Shodan. Returns a trimmed dict of relevant fields,
    or None if the lookup fails (private IP, not indexed, bad key, etc).

    Validates that `ip` resolves to a global (public) IPv4/IPv6 address;
    returns None for private/loopback/reserved addresses. URL-encodes
    both `ip` and `api_key` before building the request.
    """
    # Resolve hostname if needed, then validate IP
    try:
        ip_addr = ipaddress.ip_address(ip)
    except ValueError:
        try:
            resolved = socket.gethostbyname(ip)
            ip_addr = ipaddress.ip_address(resolved)
        except (socket.gaierror, ValueError):
            return None

    # Reject non-global (private, loopback, link-local, multicast, reserved) IPs
    if not ip_addr.is_global:
        return None

    if not api_key:
        return None

    # URL-encode both parameters
    safe_ip = urllib.parse.quote(str(ip_addr), safe="")
    safe_key = urllib.parse.quote(api_key, safe="")
    url = SHODAN_HOST_URL.format(ip=safe_ip, key=safe_key)

    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            data = json.loads(resp.read().decode())
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, ValueError):
        return None

    return {
        "org": data.get("org"),
        "isp": data.get("isp"),
        "country": data.get("country_name"),
        "known_open_ports": data.get("ports", []),
        "hostnames": data.get("hostnames", []),
        "vulns": list(data.get("vulns", [])) if "vulns" in data else [],
        "last_update": data.get("last_update"),
    }
