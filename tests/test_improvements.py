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
                self.wfile.write(b"dashboard authed: password='secret', api_key='sk_1'")
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
        if self.path.startswith("/api/claim"):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"ok":true,"applied":1}')
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
        if self.path.startswith("/api/claim"):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"ok":true,"applied":1}')
            return
        self.send_response(404)
        self.end_headers()


@pytest.fixture(scope="module")
def server():
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), _Handler)
    srv.daemon_threads = True
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


class TestRiskScore:
    def test_clean_no_findings(self):
        from keris.modules.riskscore import risk_score

        rs = risk_score([])
        assert rs["grade"] == "A"
        assert rs["score"] == 100.0

    def test_single_high(self):
        from keris.modules.riskscore import risk_score

        rs = risk_score([{"severity": "HIGH"}, {"severity": "LOW"}])
        assert rs["grade"] == "C"

    def test_critical_drives_down(self):
        from keris.modules.riskscore import risk_score

        rs = risk_score([{"severity": "CRITICAL"}] * 3)
        assert rs["grade"] == "F"

    def test_no_critical_high_caps_grade(self):
        from keris.modules.riskscore import risk_score

        rs = risk_score([{"severity": "LOW"}] * 9)
        assert rs["grade"] in ("A", "B")


class TestRaceCondition:
    def test_race_parallel_hits_detected(self):
        from keris.core.http import KerisHTTP
        from keris.modules.race import race_findings

        client = KerisHTTP(timeout=10)
        try:
            findings = race_findings(BASE, ["/api/claim"], client, concurrency=6)
            # demo server: /api/claim menjawab 200, tiap request identik -> 6x sukses
            assert any(f.severity == "HIGH" for f in findings)
        finally:
            client.close()


class TestJsdeps:
    def test_extract_packages_json(self):
        from keris.modules.jsdeps import _extract_packages

        pkgs = _extract_packages('{"dependencies":{"lodash":"4.17.5","jquery":"^3.3.1"}}')
        assert pkgs["lodash"] == "4.17.5"

    def test_vuln_for_lodash(self):
        from keris.modules.jsdeps import _vuln_for

        sev, desc = _vuln_for("lodash", "4.17.5")
        assert sev in ("HIGH", "CRITICAL")

    def test_check_js_dependencies(self):
        from keris.modules.jsdeps import check_js_dependencies

        findings = check_js_dependencies("http://x", ['{"dependencies":{"lodash":"4.17.5"}}'])
        assert any("lodash" in f.title for f in findings)


class TestFavicon:
    def test_favicon_urls(self):
        from keris.modules.favicon import _favicon_urls

        urls = _favicon_urls("http://x", "<link rel='icon' href='/fav.ico'>")
        assert urls[0].endswith("/fav.ico")

    def test_no_favicon_no_finding(self):
        from keris.core.http import KerisHTTP
        from keris.modules.favicon import fingerprint_findings

        client = KerisHTTP(timeout=10)
        try:
            assert fingerprint_findings("http://x", client, html="<html></html>") == []
        finally:
            client.close()


class TestJwtAttack:
    def test_forge_and_verify(self):
        from keris.modules.jwtattack import (
            crack_hs_secret,
            forge_hs_token,
        )

        tok = forge_hs_token({"user": "u"}, "secret", "HS256")
        hit = crack_hs_secret(tok)
        assert hit is not None
        assert hit[0] == "secret"

    def test_forge_none_no_sig(self):
        from keris.modules.jwtattack import forge_none_token

        tok = forge_none_token({"user": "admin"})
        assert tok.endswith(".")
        assert len(tok.split(".")) == 3


class TestAuthChain:
    def test_probe_authed_endpoints(self):
        from keris.core.http import KerisHTTP
        from keris.modules.authchain import probe_authed_endpoints

        client = KerisHTTP(timeout=10)
        try:
            client.post(BASE + "/login", data={"user": "admin", "pass": "secret"})
            findings = probe_authed_endpoints(BASE, client, probes=["/dashboard"])
            assert any(f.severity == "HIGH" for f in findings)
        finally:
            client.close()
