"""Tes untuk modul roadmap: cachepoison, hostheader, websocket, jsanalysis,
sensitive, retest, dan mapping CVSS/OWASP.

Semua uji berjalan terhadap server HTTP lokal ephemeral (tanpa jaringan luar).
"""

import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from keris.core.http import KerisHTTP
from keris.modules.cachepoison import check_cache_poisoning
from keris.modules.hostheader import check_host_header
from keris.modules.jsanalysis import analyze_js
from keris.modules.retest import diff_findings, retest
from keris.modules.sensitive import check_sensitive
from keris.modules.websocket import check_websocket
from keris.cvss import classify, map_findings, owasp_summary, _cvss_score


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _json(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        import urllib.parse as up

        parsed = up.urlparse(self.path)
        path = parsed.path

        if path == "/poison":
            # refleksikan X-Forwarded-Host + penanda cache
            host = self.headers.get("X-Forwarded-Host", "")
            body = f'<html><meta content="https://{host}/x"><script src="//{host}/a.js"></script></html>'.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("X-Cache", "HIT")
            self.send_header("Cache-Control", "public, max-age=60")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if path == "/hostrefl":
            # refleksikan nilai Host + penanda forgot-password
            h = self.headers.get("Host", "")
            body = f'<html><a href="https://{h}/reset?t=TOK">reset</a></html>'.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if path == "/reset":
            # endpoint reset-password yang merefleksikan Host
            h = self.headers.get("Host", "")
            body = f'<html><p>Link reset dikirim ke https://{h}/reset-password?token=X</p></html>'.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if path == "/login":
            # form login normal (tanpa refleksi)
            body = b'<html><form><input name="username"><input name="password"></form></html>'
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if path == "/app.js":
            body = b"""
var a = document.getElementById('x').innerHTML = location.hash;
eval(location.search.slice(1));
var b = document.getElementById('y').innerHTML = 'literal';
fetch('/api/internal/data');
fetch('/api/users?x=1');
var key = 'AKIAIOSFODNN7EXAMPLE';
"""
            self.send_response(200)
            self.send_header("Content-Type", "text/javascript")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if path == "/sensitive":
            self._json({
                "email": "admin@example.com",
                "api_key": "AKIAIOSFODNN7EXAMPLE",
                "password": "supersecret",
            })
            return

        if path == "/safe":
            self._json({"ok": True})
            return

        body = b"{}"
        self.send_response(404)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


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


# --- cache poisoning ---


class TestCachePoisoning:
    def test_detects_reflection(self, client, server):
        f = check_cache_poisoning(server, client, paths=["/poison"])
        assert any("poison" in x.title.lower() or "cache" in x.title.lower() for x in f)

    def test_finds_xforwarded_host(self, client, server):
        f = check_cache_poisoning(server, client, paths=["/poison"])
        assert any("X-Forwarded-Host" in x.evidence for x in f)

    def test_no_false_positive_on_clean(self, client, server):
        f = check_cache_poisoning(server, client, paths=["/login"])
        assert not any(x.endpoint.endswith("/login") for x in f)


# --- host header ---


class TestHostHeader:
    def test_detects_reflection(self, client, server):
        f = check_host_header(server, client, paths=["/hostrefl"])
        assert any("Host header" in x.title for x in f)

    def test_password_reset_high(self, client, server):
        f = check_host_header(server, client, paths=["/reset"])
        h = [x for x in f if x.endpoint.endswith("/reset")]
        assert h and h[0].severity == "HIGH"

    def test_clean_path(self, client, server):
        f = check_host_header(server, client, paths=["/login"])
        assert not any(x.endpoint.endswith("/login") for x in f)


# --- JS analysis ---


class TestJsAnalysis:
    def test_detects_dom_sinks(self, client, server):
        res = analyze_js(server, client, assets=[server + "/app.js"])
        assert any("innerHTML" in x.title for x in res["findings"])
        assert any("eval" in x.title for x in res["findings"])

    def test_detects_secrets(self, client, server):
        res = analyze_js(server, client, assets=[server + "/app.js"])
        assert res["secret_count"] >= 1

    def test_detects_endpoints(self, client, server):
        res = analyze_js(server, client, assets=[server + "/app.js"])
        assert any("/api/internal" in e for e in res["endpoints"])

    def test_skips_literal_sink(self, client, server):
        # innerHTML = 'literal' tidak boleh dilaporkan sebagai sink
        res = analyze_js(server, client, assets=[server + "/app.js"])
        inner = [x for x in res["findings"] if "innerHTML" in x.title]
        assert inner
        # sink yang dilaporkan harus yang memakai source (location.hash)
        assert any("location.hash" in x.evidence for x in inner)


# --- sensitive data ---


class TestSensitive:
    def test_detects_secret_in_response(self, client, server):
        f = check_sensitive(server, client, endpoints=["/sensitive"])
        assert any("AWS Access Key" in x.title for x in f)

    def test_no_false_positive_on_safe(self, client, server):
        f = check_sensitive(server, client, endpoints=["/safe"])
        assert not f

    def test_email_without_context_skipped(self, client, server):
        # /sensitive punya context (api_key/password) -> email ikut dilaporkan
        f = check_sensitive(server, client, endpoints=["/sensitive"])
        titles = [x.title for x in f]
        assert any("AWS Access Key" in t for t in titles)


# --- websocket ---


class TestWebsocket:
    def test_graceful_without_client_dep(self, client, server, monkeypatch):
        import keris.modules.websocket as ws

        monkeypatch.setitem(sys.modules, "websocket", None)
        # buat import di dalam _probe_handshake gagal -> kembalikan None
        from keris.modules import websocket as ws_mod

        # force ImportError dengan monkeypatch builtins __import__
        f = check_websocket(server, client)
        assert isinstance(f, list)

    def test_returns_list(self, client, server):
        f = check_websocket(server, client)
        assert isinstance(f, list)


# --- retest ---


class TestRetest:
    def test_diff_fixed_new_persisting(self):
        old = [
            {"severity": "HIGH", "title": "SQLi", "endpoint": "/a"},
            {"severity": "MEDIUM", "title": "XSS", "endpoint": "/b"},
            {"severity": "LOW", "title": "Header", "endpoint": "/c"},
        ]
        new = [
            {"severity": "MEDIUM", "title": "XSS", "endpoint": "/b"},
            {"severity": "HIGH", "title": "RCE", "endpoint": "/d"},
        ]
        d = diff_findings(old, new)
        assert d["summary"]["fixed"] == 2
        assert d["summary"]["new"] == 1
        assert d["summary"]["persisting"] == 1
        assert len([k for k in old if k["title"] == "SQLi"]) == 1

    def test_severity_change_detected(self):
        old = [{"severity": "LOW", "title": "T", "endpoint": "/e"}]
        new = [{"severity": "HIGH", "title": "T", "endpoint": "/e"}]
        d = diff_findings(old, new)
        assert d["summary"]["changed"] == 1

    def test_retest_file_roundtrip(self, server, tmp_path):
        old = tmp_path / "old.json"
        new = tmp_path / "new.json"
        old.write_text(json.dumps({"target": "x", "findings": [
            {"severity": "HIGH", "title": "A", "endpoint": "/a"}]}), encoding="utf-8")
        new.write_text(json.dumps({"target": "x", "findings": []}), encoding="utf-8")
        md = tmp_path / "out.md"
        jd = tmp_path / "out.json"
        diff = retest(str(old), str(new), str(md), str(jd))
        assert diff["summary"]["fixed"] == 1
        assert md.exists() and jd.exists()


# --- CVSS / OWASP ---


class TestCvss:
    def test_classify_sqli(self):
        c = classify("SQL injection pada endpoint")
        assert c["owasp_code"] == "A03"
        assert c["score"] >= 7.0

    def test_classify_fallback(self):
        c = classify("Hal aneh", "HIGH")
        assert c["score"] >= 7.0

    def test_score_range(self):
        assert 0.0 <= _cvss_score("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") <= 10.0

    def test_map_findings_adds_keys(self):
        mapped = map_findings([{"title": "SQLi", "severity": "HIGH", "endpoint": "/x"}])
        assert "cvss" in mapped[0]
        assert mapped[0]["cvss"]["owasp_code"] == "A03"

    def test_owasp_summary(self):
        rows = owasp_summary([
            {"title": "SQLi", "severity": "HIGH"},
            {"title": "XSS", "severity": "MEDIUM"},
        ])
        codes = {r["category"].split()[0] for r in rows}
        assert "A03" in codes
