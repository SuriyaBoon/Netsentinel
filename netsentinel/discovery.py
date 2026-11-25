"""
discovery.py — Host discovery (ping sweep) module.

Uses the system `ping` utility (cross-platform, no root required) to
determine which hosts in a target range are alive. This avoids needing
raw ICMP sockets (root-only on Linux/macOS, tricky on Windows) while
still giving reliable liveness results for a home-lab / authorized
network.
"""

import ipaddress
import platform
import shutil
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List

# Fallback probe ports used when ICMP ping isn't available (missing binary,
# blocked by a firewall, or no raw-socket permission). A host that accepts
# a TCP connection on any of these common ports is considered alive.
_FALLBACK_PROBE_PORTS = (80, 443, 22, 445, 3389)

_PING_AVAILABLE = shutil.which("ping") is not None

# Maximum number of host IPs to expand from a CIDR network (/16 = 65536 hosts).
# Larger networks (e.g., /8 = 16.7M) would cause unbounded memory allocation.
MAX_CIDR_HOSTS = 65536


def _tcp_fallback_ping(host: str, timeout_ms: int) -> bool:
    """Liveness check via TCP connect attempts, used when ICMP is unavailable."""
    timeout_s = max(0.2, timeout_ms / 1000 / len(_FALLBACK_PROBE_PORTS))
    for port in _FALLBACK_PROBE_PORTS:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout_s)
        try:
            # connect_ex returning 0 (open) or a "connection refused" style
            # error (port closed but host reachable) both indicate a live
            # host. Only a timeout tells us nothing.
            result = sock.connect_ex((host, port))
            if result in (0, 111, 61):  # 0=open, 111=ECONNREFUSED(linux), 61=ECONNREFUSED(mac)
                return True
        except socket.timeout:
            continue
        except OSError:
            continue
        finally:
            sock.close()
    return False


def _ping_once(host: str, timeout_ms: int = 800) -> bool:
    """Return True if `host` appears alive, via ICMP ping or a TCP fallback."""
    if not _PING_AVAILABLE:
        return _tcp_fallback_ping(host, timeout_ms)

    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), host]
    else:
        # -c 1: one packet, -W: timeout in seconds (Linux) / ms varies by OS,
        # so we convert to whole seconds with a minimum of 1.
        timeout_s = max(1, round(timeout_ms / 1000))
        cmd = ["ping", "-c", "1", "-W", str(timeout_s), host]

    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=(timeout_ms / 1000) + 1,
        )
        if result.returncode == 0:
            return True
        # ICMP may be blocked even though the host is up — confirm with
        # the TCP fallback before declaring it dead.
        return _tcp_fallback_ping(host, timeout_ms)
    except (subprocess.TimeoutExpired, OSError):
        return _tcp_fallback_ping(host, timeout_ms)


def expand_targets(target: str) -> List[str]:
    """
    Expand a target spec into a list of individual host IPs.
    Supports: single IP, CIDR ('192.168.1.0/24'), or hostname.
    Raises ValueError if target is empty, contains whitespace, starts with '-',
    or if a CIDR network exceeds MAX_CIDR_HOSTS host addresses.
    """
    # Check for whitespace before stripping (rejects leading/trailing/internal)
    if any(ch.isspace() for ch in target):
        raise ValueError(f"Target contains whitespace: {target!r}")
    
    target = target.strip()
    if not target:
        raise ValueError("Empty target")
    if target.startswith("-"):
        raise ValueError(f"Target cannot start with '-': {target!r}")

    # Validate IP/CIDR format first
    try:
        network = ipaddress.ip_network(target, strict=False)
    except ValueError:
        # Not an IP/CIDR — treat as a hostname/single target
        return [target]

    # Now enforce CIDR size limit (after successful parsing)
    if network.num_addresses > 1:
        if network.num_addresses > MAX_CIDR_HOSTS:
            raise ValueError(
                f"CIDR {target!r} expands to {network.num_addresses} addresses "
                f"(limit: {MAX_CIDR_HOSTS})"
            )
        return [str(ip) for ip in network.hosts()]
    return [str(network.network_address)]


def sweep(targets: List[str], threads: int = 50, timeout_ms: int = 800) -> List[str]:
    """
    Ping every host in `targets` concurrently.
    Returns the list of hosts that responded (alive).
    """
    alive = []
    with ThreadPoolExecutor(max_workers=threads) as pool:
        future_to_host = {
            pool.submit(_ping_once, host, timeout_ms): host for host in targets
        }
        for future in as_completed(future_to_host):
            host = future_to_host[future]
            try:
                if future.result():
                    alive.append(host)
            except Exception:
                continue
    return sorted(alive, key=lambda ip: tuple(int(p) for p in ip.split(".")) if ip.count(".") == 3 else (0,))
