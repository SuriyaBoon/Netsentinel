"""
Basic test suite for NetSentinel.

Run with: pytest tests/ -v

These tests spin up a local TCP/HTTP server on loopback so they run
anywhere (CI, laptop, VM) without needing real network targets.
"""

import http.server
import socket
import socketserver
import struct
import threading
import time

import pytest

from netsentinel import banner, cli, discovery, scanner


# --------------------------------------------------------------------------
# parse_port_spec
# --------------------------------------------------------------------------

def test_parse_single_ports():
    assert scanner.parse_port_spec("22,80,443") == [22, 80, 443]


def test_parse_range():
    assert scanner.parse_port_spec("1-5") == [1, 2, 3, 4, 5]


def test_parse_mixed():
    assert scanner.parse_port_spec("22,80,1000-1003") == [22, 80, 1000, 1001, 1002, 1003]


def test_parse_dedupes_and_sorts():
    assert scanner.parse_port_spec("80,22,80,22") == [22, 80]


def test_parse_ignores_out_of_range():
    result = scanner.parse_port_spec("0,70000,443")
    assert result == [443]


@pytest.mark.parametrize(
    "spec, fragment",
    [
        ("abc", "abc"),
        ("80-", "80-"),
        ("-80", "-80"),
        ("80-90-100", "80-90-100"),
        ("80,,443", "empty"),
        ("", "Empty"),
    ],
)
def test_parse_rejects_malformed_specs(spec, fragment):
    with pytest.raises(ValueError) as excinfo:
        scanner.parse_port_spec(spec)
    assert fragment in str(excinfo.value)


# --------------------------------------------------------------------------
# expand_targets
# --------------------------------------------------------------------------

def test_expand_single_ip():
    assert discovery.expand_targets("192.168.1.10") == ["192.168.1.10"]


def test_expand_cidr():
    hosts = discovery.expand_targets("192.168.1.0/30")
    # /30 has 2 usable host addresses
    assert hosts == ["192.168.1.1", "192.168.1.2"]


def test_expand_hostname_passthrough():
    assert discovery.expand_targets("example.internal") == ["example.internal"]


# --------------------------------------------------------------------------
# Live scan tests against a local test server
# --------------------------------------------------------------------------

class ReusableTCPServer(socketserver.TCPServer):
    allow_reuse_address = True


class _TestHandler(http.server.BaseHTTPRequestHandler):
    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Server", "NetSentinelTestServer/1.0")
        self.end_headers()

    def log_message(self, *args):
        pass  # silence test output


@pytest.fixture
def test_server():
    httpd = ReusableTCPServer(("127.0.0.1", 0), _TestHandler)
    port = httpd.server_address[1]
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    time.sleep(0.2)
    yield "127.0.0.1", port
    httpd.shutdown()


def test_tcp_connect_scan_finds_open_port(test_server):
    host, open_port = test_server
    closed_port = open_port + 1  # nothing listening here
    results = scanner.tcp_connect_scan(host, [open_port, closed_port], threads=5, timeout=1.0)
    states = {r.port: r.state for r in results}
    assert states[open_port] == "open"
    assert states[closed_port] == "closed"


def test_banner_grab_returns_http_response(test_server):
    host, port = test_server
    result = banner.grab_banner(host, port, timeout=1.5)
    assert result is not None
    assert "200" in result


def test_guess_service_uses_banner_over_port():
    assert banner.guess_service(9999, "SSH-2.0-OpenSSH_8.9") == "ssh"


def test_guess_service_falls_back_to_port_table():
    assert banner.guess_service(22, None) == "ssh"
    assert banner.guess_service(59999, None) == "unknown"


# --------------------------------------------------------------------------
# Platform guards
# --------------------------------------------------------------------------

def test_syn_scan_raises_permission_error_without_geteuid(monkeypatch):
    """Windows has no os.geteuid; the SYN scan must fail cleanly, not crash."""
    monkeypatch.delattr(scanner.os, "geteuid", raising=False)
    with pytest.raises(PermissionError, match="--mode tcp"):
        scanner.tcp_syn_scan("127.0.0.1", [80], threads=1, timeout=0.1)


# --------------------------------------------------------------------------
# Raw TCP packet construction (pure functions, no raw sockets)
# --------------------------------------------------------------------------

def test_syn_packet_defaults_to_syn_flag():
    packet = scanner._build_tcp_packet("10.0.0.1", "10.0.0.2", 40000, 80, tcp_seq=1000)
    tcp_header = struct.unpack("!HHLLBBHHH", packet[20:40])
    assert tcp_header[5] == 0x02


def test_rst_teardown_packet_has_rst_flag_and_valid_checksum():
    packet = scanner._build_tcp_packet(
        "10.0.0.1", "10.0.0.2", 40000, 80,
        tcp_flags=0x04, tcp_seq=123456,
    )
    ip_header = struct.unpack("!BBHHHBBH4s4s", packet[:20])
    tcp_header = struct.unpack("!HHLLBBHHH", packet[20:40])

    assert tcp_header[5] == 0x04          # RST flag
    assert tcp_header[2] == 123456        # seq mirrors the peer's ACK

    pseudo_header = struct.pack(
        "!4s4sBBH",
        ip_header[8], ip_header[9], 0, socket.IPPROTO_TCP, len(packet) - 20,
    )
    assert scanner._checksum(pseudo_header + packet[20:]) == 0


# --------------------------------------------------------------------------
# CLI error handling
# --------------------------------------------------------------------------

@pytest.mark.parametrize("bad_ports", ["abc", "80-", "-80", ""])
def test_cli_rejects_malformed_ports(bad_ports, capsys):
    exit_code = cli.main(["--target", "127.0.0.1", "--ports", bad_ports])
    captured = capsys.readouterr()
    assert exit_code != 0
    assert "[!]" in captured.out
    assert "Invalid --ports value" in captured.out


# --------------------------------------------------------------------------#
# CLI orchestration helpers (discover-only / skip-discovery)
# --------------------------------------------------------------------------#

def test_discover_only_stops_before_scanning(test_server, capsys):
    host, port = test_server
    exit_code = cli.main(["--target", host, "--discover-only", "--ports", str(port)])
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "Discovering live hosts" in captured.out
    # discover-only returns before port scanning, so the port number is never printed
    assert str(port) not in captured.out


def test_skip_discovery_scans_directly(test_server, capsys):
    host, port = test_server
    exit_code = cli.main(
        ["--target", host, "--skip-discovery", "--ports", str(port), "--mode", "tcp"]
    )
    assert exit_code == 0
    captured = capsys.readouterr()
    assert str(port) in captured.out
