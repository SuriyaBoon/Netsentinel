"""
banner.py — Lightweight service fingerprinting via banner grabbing.

Connects to open TCP ports and either reads whatever the service sends
unprompted (common for SSH, FTP, SMTP) or sends a minimal protocol-aware
probe (HTTP HEAD) to elicit a response. This is a simplified version of
what Nmap's -sV does with its probe database.
"""

import socket
from typing import Optional

# Common ports mapped to a friendly service guess, used when a banner
# can't be read but the port number is a strong signal on its own.
WELL_KNOWN_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc",
    139: "netbios-ssn", 143: "imap", 443: "https", 445: "microsoft-ds",
    3306: "mysql", 3389: "rdp", 5432: "postgresql", 5900: "vnc",
    6379: "redis", 8080: "http-alt", 8443: "https-alt", 27017: "mongodb",
}

HTTP_PROBE = b"HEAD / HTTP/1.0\r\nHost: %s\r\nConnection: close\r\n\r\n"


def grab_banner(host: str, port: int, timeout: float = 2.0) -> Optional[str]:
    """
    Attempt to read a service banner from an open TCP port.
    Returns the first line of readable text, or None if nothing usable
    was received.
    """
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            data = b""

            # Many services (SSH, FTP, SMTP) announce a banner unprompted
            # as soon as the connection opens — listen briefly first.
            try:
                data = sock.recv(1024)
            except socket.timeout:
                data = b""

            # Nothing volunteered — try an HTTP-style probe as a fallback,
            # since HTTP servers wait for a request before responding and
            # may be running on a non-standard port.
            if not data:
                try:
                    sock.sendall(HTTP_PROBE % host.encode())
                    data = sock.recv(1024)
                except (socket.timeout, OSError):
                    data = b""

            if not data:
                return None
            text = data.decode(errors="ignore").strip()
            # Return just the first non-empty line to keep output tidy.
            for line in text.splitlines():
                if line.strip():
                    return line.strip()[:200]
            return None
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None


def guess_service(port: int, banner: Optional[str]) -> str:
    """Best-effort service name, preferring banner content over port number."""
    if banner:
        lowered = banner.lower()
        if "ssh" in lowered:
            return "ssh"
        if "http" in lowered or lowered.startswith("<"):
            return "http"
        if "ftp" in lowered:
            return "ftp"
        if "smtp" in lowered or "esmtp" in lowered:
            return "smtp"
    return WELL_KNOWN_PORTS.get(port, "unknown")
