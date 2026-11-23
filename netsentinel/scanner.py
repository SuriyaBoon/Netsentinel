"""
scanner.py — Core port scanning engine.

Implements three scan modes to mirror how Nmap's internals work:

  * TCP connect scan  — full three-way handshake via socket.connect_ex().
                         No special privileges required. Reliable, slightly
                         noisier (completes the handshake, so it is logged
                         by the target).
  * TCP SYN scan      — "half-open" scan. Crafts raw IP/TCP packets, sends
                         a SYN, and inspects the response (SYN/ACK = open,
                         RST = closed, no response = filtered) without
                         completing the handshake. Requires raw sockets
                         (root / CAP_NET_RAW on Linux).
  * UDP scan          — sends an empty UDP datagram. No response = open|
                         filtered. ICMP port-unreachable = closed.

All scans are multithreaded via ThreadPoolExecutor with a configurable
thread count and per-socket timeout.
"""

import os
import random
import socket
import struct
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class PortResult:
    port: int
    protocol: str          # "tcp" or "udp"
    state: str              # "open", "closed", "filtered", "open|filtered"
    banner: Optional[str] = None
    service_guess: Optional[str] = None


def parse_port_spec(spec: str) -> List[int]:
    """
    Parse a port spec like '22,80,443' or '1-1024' or '1-100,443,8000-8100'
    into a sorted list of unique ports.
    """
    ports = set()
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            start, end = chunk.split("-", 1)
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(chunk))
    return sorted(p for p in ports if 0 < p <= 65535)


# --------------------------------------------------------------------------
# TCP connect scan (default — no root required)
# --------------------------------------------------------------------------

def _tcp_connect_probe(host: str, port: int, timeout: float) -> PortResult:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((host, port))
        state = "open" if result == 0 else "closed"
    except socket.timeout:
        state = "filtered"
    except OSError:
        state = "filtered"
    finally:
        sock.close()
    return PortResult(port=port, protocol="tcp", state=state)


def tcp_connect_scan(host: str, ports: List[int], threads: int, timeout: float) -> List[PortResult]:
    results = []
    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = [pool.submit(_tcp_connect_probe, host, p, timeout) for p in ports]
        for future in as_completed(futures):
            results.append(future.result())
    return sorted(results, key=lambda r: r.port)


# --------------------------------------------------------------------------
# TCP SYN scan (raw sockets — requires root / CAP_NET_RAW)
# --------------------------------------------------------------------------

def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return (~total) & 0xFFFF


def _build_syn_packet(src_ip: str, dst_ip: str, src_port: int, dst_port: int) -> bytes:
    # --- IP header ---
    ip_ihl_ver = (4 << 4) + 5
    ip_tos = 0
    ip_tot_len = 40
    ip_id = random.randint(0, 65535)
    ip_frag_off = 0
    ip_ttl = 64
    ip_proto = socket.IPPROTO_TCP
    ip_check = 0
    ip_saddr = socket.inet_aton(src_ip)
    ip_daddr = socket.inet_aton(dst_ip)

    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off,
        ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr,
    )

    # --- TCP header ---
    tcp_seq = random.randint(0, 4294967295)
    tcp_ack_seq = 0
    tcp_doff = 5
    tcp_flags_syn = 0x02
    tcp_window = socket.htons(5840)
    tcp_check = 0
    tcp_urg_ptr = 0
    offset_res = (tcp_doff << 4) + 0

    tcp_header = struct.pack(
        "!HHLLBBHHH",
        src_port, dst_port, tcp_seq, tcp_ack_seq,
        offset_res, tcp_flags_syn, tcp_window, tcp_check, tcp_urg_ptr,
    )

    pseudo_header = struct.pack(
        "!4s4sBBH", ip_saddr, ip_daddr, 0, socket.IPPROTO_TCP, len(tcp_header)
    )
    tcp_check = _checksum(pseudo_header + tcp_header)

    tcp_header = struct.pack(
        "!HHLLBBH",
        src_port, dst_port, tcp_seq, tcp_ack_seq, offset_res, tcp_flags_syn, tcp_window,
    ) + struct.pack("H", tcp_check) + struct.pack("!H", tcp_urg_ptr)

    return ip_header + tcp_header


def _get_local_ip(dst_ip: str) -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((dst_ip, 80))
        return s.getsockname()[0]
    finally:
        s.close()


def _syn_probe_one(host: str, port: int, timeout: float, src_ip: str) -> PortResult:
    """
    Send one raw SYN packet and listen for a reply on a separate raw
    socket. Falls back to 'filtered' on timeout (no distinguishable
    response), matching Nmap's convention for a silently dropped SYN.
    """
    src_port = random.randint(1025, 65534)

    send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    recv_sock.settimeout(timeout)

    state = "filtered"
    try:
        packet = _build_syn_packet(src_ip, host, src_port, port)
        send_sock.sendto(packet, (host, 0))

        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                data, _ = recv_sock.recvfrom(65535)
            except socket.timeout:
                break
            ip_header = data[:20]
            iph = struct.unpack("!BBHHHBBH4s4s", ip_header)
            if socket.inet_ntoa(iph[8]) != host:
                continue
            tcp_header = data[20:40]
            tcph = struct.unpack("!HHLLBBHHH", tcp_header)
            resp_src_port, resp_dst_port, _, _, _, flags = tcph[0], tcph[1], tcph[2], tcph[3], tcph[4], tcph[5]
            if resp_src_port == port and resp_dst_port == src_port:
                if flags & 0x12 == 0x12:      # SYN+ACK
                    state = "open"
                    # Send RST to close the half-open connection cleanly
                    rst = _build_syn_packet(src_ip, host, src_port, port)
                    send_sock.sendto(rst, (host, 0))
                elif flags & 0x14 == 0x14:    # RST+ACK
                    state = "closed"
                break
    except PermissionError:
        state = "error:permission-denied (run as root/CAP_NET_RAW)"
    except OSError as exc:
        state = f"error:{exc}"
    finally:
        send_sock.close()
        recv_sock.close()

    return PortResult(port=port, protocol="tcp", state=state)


def _require_raw_socket_privileges() -> None:
    """Raise PermissionError unless the process may open raw sockets."""
    geteuid = getattr(os, "geteuid", None)
    if geteuid is None:
        # os.geteuid does not exist on Windows; raw sockets there need an
        # elevated shell, which we cannot detect portably.
        raise PermissionError(
            "TCP SYN scan requires raw sockets and elevated privileges. "
            "On Windows, run from an Administrator shell, or use --mode tcp "
            "for a connect scan instead."
        )
    if geteuid() != 0:
        raise PermissionError(
            "TCP SYN scan requires root privileges (raw sockets). "
            "Re-run with sudo, or use --mode tcp for a connect scan instead."
        )


def tcp_syn_scan(host: str, ports: List[int], threads: int, timeout: float) -> List[PortResult]:
    _require_raw_socket_privileges()
    src_ip = _get_local_ip(host)
    results = []
    # SYN scan is intentionally lower-concurrency by default since all
    # threads share the same raw receive socket path per host.
    with ThreadPoolExecutor(max_workers=min(threads, 20)) as pool:
        futures = [pool.submit(_syn_probe_one, host, p, timeout, src_ip) for p in ports]
        for future in as_completed(futures):
            results.append(future.result())
    return sorted(results, key=lambda r: r.port)


# --------------------------------------------------------------------------
# UDP scan
# --------------------------------------------------------------------------

def _udp_probe(host: str, port: int, timeout: float) -> PortResult:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    state = "open|filtered"
    try:
        sock.sendto(b"", (host, port))
        try:
            sock.recvfrom(1024)
            state = "open"
        except socket.timeout:
            state = "open|filtered"
    except ConnectionResetError:
        # ICMP port-unreachable surfaces as a connection reset on some OSes
        state = "closed"
    except OSError:
        state = "closed"
    finally:
        sock.close()
    return PortResult(port=port, protocol="udp", state=state)


def udp_scan(host: str, ports: List[int], threads: int, timeout: float) -> List[PortResult]:
    results = []
    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = [pool.submit(_udp_probe, host, p, timeout) for p in ports]
        for future in as_completed(futures):
            results.append(future.result())
    return sorted(results, key=lambda r: r.port)
