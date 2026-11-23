"""
banner.py — Lightweight service fingerprinting via banner grabbing.

Connects to open TCP ports and either reads whatever the service sends
unprompted (common for SSH, FTP, SMTP) or sends a minimal protocol-aware
probe (HTTP HEAD) to elicit a response. This is a simplified version of
what Nmap's -sV does with its probe database.

TLS-enabled ports are inspected with the standard-library ``ssl`` module
using a two-step handshake: a verified handshake first (capturing the TLS
version, certificate name and expiry), then an unverified fallback when
the certificate cannot be validated (self-signed or IP-addressed targets)
so inspection still succeeds without crashing.
"""

import socket
import ssl
from typing import Any, Dict, Optional, Tuple

# Common ports mapped to a friendly service guess, used when a banner
# can't be read but the port number is a strong signal on its own.
WELL_KNOWN_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc",
    139: "netbios-ssn", 143: "imap", 443: "https", 445: "microsoft-ds",
    465: "smtps", 993: "imaps", 995: "pop3s", 3306: "mysql",
    3389: "rdp", 5432: "postgresql", 5900: "vnc", 6379: "redis",
    6443: "https", 8080: "http-alt", 8443: "https", 9443: "https",
    27017: "mongodb",
}

# Ports where a TLS handshake is expected before any application data.
DEFAULT_TLS_PORTS = {443, 465, 993, 995, 6443, 8443, 9443}

# TLS services that greet the client instead of waiting for an HTTP request.
_TLS_GREETING_PORTS = {465, 993, 995}

# Ports that normally speak HTTPS (and therefore accept a HEAD probe).
_HTTPS_PORTS = {443, 6443, 8443, 9443}

HTTP_PROBE = b"HEAD / HTTP/1.0\r\nHost: %s\r\nConnection: close\r\n\r\n"


def _first_line(data: bytes) -> Optional[str]:
    """Return the first non-empty decoded line, capped at 200 characters."""
    text = data.decode(errors="ignore").strip()
    for line in text.splitlines():
        if line.strip():
            return line.strip()[:200]
    return None


def _cert_name(cert: Dict[str, Any]) -> Optional[str]:
    """Prefer the certificate commonName, then the first subjectAltName DNS entry."""
    for rdn in cert.get("subject") or ():
        for key, value in rdn:
            if key == "commonName":
                return str(value)
    for entry in cert.get("subjectAltName") or ():
        if len(entry) >= 2 and entry[0] == "DNS":
            return str(entry[1])
    return None


def _format_tls_banner(
    version: Optional[str],
    cert: Dict[str, Any],
    line: Optional[str],
    unverified: bool,
) -> Optional[str]:
    """Compact one-line TLS description, capped at 200 characters."""
    parts = []
    if version:
        parts.append("TLS {}".format(version))
    name = _cert_name(cert)
    if name:
        parts.append("CN={}".format(name))
    not_after = cert.get("notAfter")
    if not_after:
        parts.append("expires {}".format(not_after))
    if unverified:
        parts.append("[unverified-cert]")
    if line:
        parts.append(line)
    if not parts:
        return None
    return " | ".join(parts)[:200]


def _tls_handshake(
    host: str, port: int, timeout: float, context: ssl.SSLContext
) -> Tuple[ssl.SSLSocket, Optional[str], Dict[str, Any]]:
    """Open a TCP connection and wrap it in TLS, returning socket and metadata."""
    raw = socket.create_connection((host, port), timeout=timeout)
    try:
        ssock = context.wrap_socket(raw, server_hostname=host)
    except Exception:
        raw.close()
        raise
    ssock.settimeout(timeout)
    cert = ssock.getpeercert() or {}
    return ssock, ssock.version(), cert


def _tls_inner_banner(
    host: str, port: int, ssock: ssl.SSLSocket, timeout: float
) -> Optional[str]:
    """Read the first application-level line inside an established TLS session."""
    data = b""
    try:
        if port in _HTTPS_PORTS:
            ssock.sendall(HTTP_PROBE % host.encode())
        data = ssock.recv(1024)
    except (socket.timeout, OSError, ssl.SSLError):
        data = b""
    return _first_line(data)


def _tls_banner_with(
    host: str,
    port: int,
    timeout: float,
    context: ssl.SSLContext,
    unverified: bool,
) -> Optional[str]:
    """Run one TLS inspection pass and format its banner."""
    ssock, version, cert = _tls_handshake(host, port, timeout, context)
    try:
        line = _tls_inner_banner(host, port, ssock, timeout)
    finally:
        try:
            ssock.close()
        except OSError:
            pass
    return _format_tls_banner(version, cert, line, unverified=unverified)


def grab_tls_banner(host: str, port: int, timeout: float = 2.0) -> Optional[str]:
    """
    Inspect a TLS port with a verified handshake, falling back to an
    unverified one when the certificate cannot be validated.
    """
    try:
        context = ssl.create_default_context()
        return _tls_banner_with(host, port, timeout, context, unverified=False)
    except ssl.SSLCertVerificationError:
        pass
    except (ssl.SSLError, OSError):
        return None

    # Verified handshake failed on the certificate: retry without validation
    # so self-signed and IP-addressed endpoints are still fingerprinted.
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return _tls_banner_with(host, port, timeout, context, unverified=True)
    except (ssl.SSLError, OSError):
        return None


def grab_banner(host: str, port: int, timeout: float = 2.0) -> Optional[str]:
    """
    Attempt to read a service banner from an open TCP port.
    Returns the first line of readable text, or None if nothing usable
    was received. TLS ports use the two-step TLS inspection above.
    """
    if port in DEFAULT_TLS_PORTS:
        return grab_tls_banner(host, port, timeout)

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

            return _first_line(data)
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None


def guess_service(port: int, banner: Optional[str]) -> str:
    """Best-effort service name, preferring banner content over port number."""
    if banner:
        lowered = banner.lower()
        if "[unverified-cert]" in lowered or "tls " in lowered or "tlsv" in lowered:
            if "http" in lowered or port in _HTTPS_PORTS:
                return "https"
            return WELL_KNOWN_PORTS.get(port, "tls")
        if "ssh" in lowered:
            return "ssh"
        if "http" in lowered or lowered.startswith("<"):
            return "http"
        if "ftp" in lowered:
            return "ftp"
        if "smtp" in lowered or "esmtp" in lowered:
            return "smtp"
    return WELL_KNOWN_PORTS.get(port, "unknown")
