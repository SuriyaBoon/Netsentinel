"""
Basic test suite for NetSentinel.

Run with: pytest tests/ -v

These tests spin up a local TCP/HTTP server on loopback so they run
anywhere (CI, laptop, VM) without needing real network targets.
"""

import socketserver
import threading
import time
import http.server

import pytest

from netsentinel import scanner, banner, discovery


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
