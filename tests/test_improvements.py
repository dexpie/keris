"""Test fitur peningkatan: auth lintas modul, wordlist pintar, multi-target paralel,
live retest, dan attack-path visual report."""

import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import keris.__main__ as m
from keris.modules import discovery
from keris.modules.correlation import build_chains
from keris.modules.retest import diff_findings, generate_diff_data
from keris.report_html import _attack_path_html, _parse_chain
from keris.core.config import KerisConfig

PORT = 8173
BASE = f"http://127.0.0.1:{PORT}"


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path.startswith("/login"):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b'<form method="post" action="/login"><input name="user"><input name="pass"><button>Go</button></form>')
            return
        if self.path.startswith("/dashboard"):
            cookie = self.headers.get("Cookie", "")
            if "session=authed" in cookie:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"dashboard authed")
            else:
                self.send_response(302)
                self.send_header("Location", "/login")
                self.end_headers()
            return
        if self.path.startswith("/api/me"):
            cookie = self.headers.get("Cookie", "")
            if "session=authed" in cookie:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'{"user":"admin"}')
            else:
                self.send_response(401)
                self.end_headers()
            return
        if self.path.startswith("/api/fetch"):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"ok":1}')
            return
        if self.path.startswith("/wp-login.php") or self.path.startswith("/wp-json"):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"wp")
            return
        if self.path.startswith("/actuator"):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"status":"UP"}')
            return
        if self.path.startswith("/django-admin"):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"django admin")
            return
        if self.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("X-Powered-By", "WordPress 6.4")
            self.end_headers()
            self.wfile.write(b"<html><body>home</body></html>")
            return
        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        if self.path.startswith("/login"):
            self.send_response(302)
            self.send_header("Location", "/dashboard")
            self.send_header("Set-Cookie", "session=authed; Path=/")
            self.end_headers()
            return
        self.send_response(404)
        self.end_headers()


@pytest.fixture(scope="module")
def server():
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), _Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield srv
    srv.shutdown()


def _args(cmd, target, *extra):
    return m._parse_args([cmd, target, "--quiet", "--no-color", *extra])


def _cfg():
    return KerisConfig()


class TestAuthAcrossModules:
    """--login-username/--login-password harus memberi sesi ke semua subcommand."""

    def test_make_client_auto_login(self, server):
        args = _args("recon", BASE, "--login-username", "admin", "--login-password", "secret")
        cfg = _cfg()
        client = m._make_client(args, cfg, {}, BASE)
        try:
            r = client.get(BASE + "/api/me")
            assert r.status_code == 200
            assert "admin" in r.text
        finally:
            client.close()

    def test_no_creds_no_session(self, server):
        args = _args("recon", BASE)
        cfg = _cfg()
        client = m._make_client(args, cfg, {}, BASE)
        try:
            r = client.get(BASE + "/api/me")
            assert r.status_code == 401
        finally:
            client.close()


class TestSmartWordlist:
    def test_detect_stack_wordpress(self, server):
        args = _args("recon", BASE)
        cfg = _cfg()
        client = m._make_client(args, cfg, {}, BASE)
        try:
            recon = __import__("keris.modules.recon", fromlist=["run_recon"]).run_recon(BASE, client)
            stacks = discovery.detect_stack(recon)
            assert "wordpress" in stacks
        finally:
            client.close()

    def test_wordlists_for_stack(self):
        names = discovery.wordlists_for_stack(["wordpress", "java"])
        assert "dirs-wp.txt" in names
        assert "dirs-java.txt" in names

    def test_extra_wordlists_loaded(self):
        wp = discovery.load_wordlist("dirs-wp.txt")
        assert any("wp-json" in p for p in wp)
        java = discovery.load_wordlist("dirs-java.txt")
        assert any("actuator" in p for p in java)

    def test_brute_directories_stack(self, server):
        args = _args("discover", BASE)
        cfg = _cfg()
        client = m._make_client(args, cfg, {}, BASE)
        try:
            found = discovery.brute_directories(BASE, client, max_workers=4, stacks=["wordpress"])
            paths = {d["path"] for d in found}
            assert "wp-json" in paths or "wp-login.php" in paths
        finally:
            client.close()


class TestParallelScan:
    def test_parallel_flag_parses(self):
        args = _args("scan", BASE, "--parallel")
        assert args.parallel is True

    def test_suffixed_path(self):
        assert m._suffixed("scan.md", "abc") == "scan-abc.md"
        assert m._suffixed("scan", "abc") == "scan-abc"


class TestLiveRetest:
    def test_diff_findings_buckets(self):
        old = [{"endpoint": "/x", "title": "SQLi", "severity": "HIGH"}]
        new = [{"endpoint": "/y", "title": "XSS", "severity": "MEDIUM"}]
        d = diff_findings(old, new)
        assert d["summary"]["fixed"] == 1
        assert d["summary"]["new"] == 1
        assert d["summary"]["persisting"] == 0

    def test_generate_diff_data_markdown(self, tmp_path):
        old = [{"endpoint": "/a", "title": "SQLi", "severity": "HIGH"}]
        new = []
        md, d = generate_diff_data("http://x", old, "http://x", new)
        assert "Fixed" in md
        assert d["summary"]["fixed"] == 1
        assert d["summary"]["progress"] == 100.0

    def test_retest_live_requires_authorized(self):
        args = _args("retest", os.path.join(os.path.dirname(__file__), "data", "nonexistent.json"), "--live")
        assert m._cmd_retest(args, _cfg(), {}) == m.EXIT_ERROR

    def test_retest_live_no_new_json_fails(self):
        args = _args("retest", "somefile.json")
        assert m._cmd_retest(args, _cfg(), {}) == m.EXIT_ERROR


class TestAttackPathReport:
    def test_parse_chain(self):
        f = {"evidence": "Chain terbentuk dari: [LOW] cache @ /; [MEDIUM] xss @ /search2"}
        steps = _parse_chain(f)
        assert len(steps) == 2
        assert steps[0]["severity"] == "LOW"
        assert steps[1]["endpoint"] == "/search2"

    def test_attack_path_html_builds(self):
        findings = build_chains([
            {"severity": "LOW", "title": "Cache poisoning", "endpoint": "/", "detail": "x"},
            {"severity": "MEDIUM", "title": "Reflected XSS", "endpoint": "/search2", "detail": "y"},
        ])
        assert findings, "chain harus terbentuk dari cache+xss"
        html = _attack_path_html(findings)
        assert "Attack Paths" in html
        assert "arrow" in html

    def test_attack_path_no_chains(self):
        assert _attack_path_html([]) == ""
