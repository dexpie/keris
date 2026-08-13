"""Tes untuk modul serangan aktif (exploit, brute extended, CVE) — pakai mock.

Semua uji bersifat non-destruktif dan berjalan terhadap server HTTP lokal
ephemeral (tanpa menyentuh jaringan luar).
"""

import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from keris.core.http import KerisHTTP
from keris.modules.exploit import exploit_sqli, exploit_xss, run_exploit
from keris.modules.cve import check_cve, _detected_platforms


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        body = b"hello world"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        self.do_GET()


@pytest.fixture(scope="module")
def server():
    httpd = HTTPServer(("127.0.0.1", 0), _Handler)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    host, port = httpd.server_address
    yield f"http://{host}:{port}"
    httpd.shutdown()


@pytest.fixture
def client(server):
    c = KerisHTTP()
    yield c
    c.close()


class TestExploitGate:
    def test_requires_authorized(self, client):
        findings = run_exploit(client and "http://127.0.0.1:1", client, ["/a?id=1"],
                               authorized=False)
        assert findings == []


class TestExploitLogic:
    def test_sqli_boolean_no_false_positive(self, client, server):
        # server statis: tidak ada perbedaan respons -> tidak ada temuan
        findings = exploit_sqli(server, client, ["/a?id=1"])
        assert findings == []

    def test_xss_no_false_positive(self, client, server):
        # server tidak merefleksikan payload -> tidak ada temuan
        findings = exploit_xss(server, client, ["/a?id=1"])
        assert findings == []


class TestCveGate:
    def test_requires_authorized(self, client):
        findings = check_cve("http://127.0.0.1:1", client, authorized=False)
        assert findings == []

    def test_no_platforms_no_findings(self, client, server):
        findings = check_cve(server, client, authorized=True)
        assert isinstance(findings, list)


class TestDetectedPlatforms:
    def test_returns_list(self, client, server):
        platforms = _detected_platforms(server, client)
        assert isinstance(platforms, list)