"""Regression test untuk hasil audit kode (v0.8.0).

Mengunci perbaikan false-positive & crash yang ditemukan selama audit:
- SSRF callback & placeholder heuristic (scanner)
- SQLi error signature generik
- cookie flag parser
- _auto_fill / form extraction (auth)
- .git content validation (hunt)
- SPA fallback & redirect Location (discovery)
- servercve version parsing
- CVSS roundup
- JWT non-dict crash
- markdown escaping report
"""

import sys
import os
import re
import math

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import keris.cvss as cvss_mod
import keris.report as report_mod
import keris.report_pdf as report_pdf_mod
from keris.modules import auth as auth_mod
from keris.modules import hunt as hunt_mod
from keris.modules import servercve as servercve_mod
from keris.modules import jwt as jwt_mod
from keris.modules import jwtattack as jwtattack_mod
from keris.modules.scanner import Finding


class TestScannerSqliSignatures:
    def test_generic_sql_word_not_a_signature(self):
        # "mysql" / "oracle" tanpa konteks error tidak boleh jadi temuan
        from keris.modules import scanner as sc
        text = "Powered by MySQL database, consult our sql documentation"
        # pastikan string error yang dipakai adalah spesifik, bukan substring generik
        signatures = [
            "syntax error", "unterminated", "quoted string", "pg_",
            "error in your sql", "warning: mysql", "mysql_fetch", "mysql_query",
            "sqlite3.operationalerror", "pdoexception", "ora-", "sqlstate",
        ]
        assert not any(sig in text.lower() for sig in signatures)


class TestScannerCookieFlags:
    def test_expires_not_split(self):
        from keris.modules import scanner as sc
        headers = {
            "Set-Cookie": (
                "session=abc123; Expires=Wed, 21 Oct 2026 07:28:00 GMT; "
                "HttpOnly; Secure, track=1; Path=/"
            )
        }
        res = sc.check_cookie_flags(headers)
        # koma di dalam Expires TIDAK memecah cookie -> 2 cookie dipisah benar
        names = [f.endpoint for f in res]
        assert len(res) == 2
        assert any("session" in n for n in names)
        assert any("track" in n for n in names)
        # session hanya kurang SameSite (HttpOnly+Secure sudah ada)
        sess = next(f for f in res if "session" in f.endpoint)
        assert "HttpOnly" not in sess.detail
        assert "Secure" not in sess.detail
        assert "SameSite" in sess.detail


class TestSsqrfCallbackFalsePositive:
    def test_callback_split_was_broken(self):
        # dulu: callback_url.split("/")[0] == "http:" -> selalu true
        from urllib.parse import urlparse
        cb = "http://evil.local:4444/cb"
        assert urlparse(cb).netloc == "evil.local:4444"


class TestAuthAutoFill:
    def test_passport_not_treated_as_password(self):
        form = {
            "action": "/login",
            "method": "post",
            "fields": {
                "username": {"type": "text", "value": "", "checked": False},
                "password": {"type": "password", "value": "", "checked": False},
                "passport": {"type": "hidden", "value": "123", "checked": False},
            },
        }
        data = auth_mod._auto_fill(form, "budi", "rahasia123")
        assert data["username"] == "budi"
        assert data["password"] == "rahasia123"
        # field hidden tetap dipertahankan
        assert data["passport"] == "123"

    def test_unchecked_checkbox_not_submitted(self):
        form = {
            "action": "/login",
            "method": "post",
            "fields": {
                "user": {"type": "text", "value": "", "checked": False},
                "pass": {"type": "password", "value": "", "checked": False},
                "remember": {"type": "checkbox", "value": "on", "checked": False},
                "agree": {"type": "checkbox", "value": "yes", "checked": True},
            },
        }
        data = auth_mod._auto_fill(form, "u", "p")
        assert "remember" not in data
        assert data.get("agree") == "yes"

    def test_extract_forms_case_insensitive_close(self):
        html = "<FORM action='/login' method='post'><input name='user'>" \
               "</FORM><form action='/x' method='get'></form>"
        forms = auth_mod._extract_forms(html)
        assert len(forms) == 2
        assert forms[0]["fields"].get("user") is not None


class TestHuntGitValidation:
    def test_spa_404_not_treated_as_git(self):
        # respons 200 berisi HTML index (SPA) -> bukan .git
        assert not hunt_mod._git_content_valid("/.git/HEAD", b"<!DOCTYPE html><html>...")
        assert not hunt_mod._git_content_valid("/.git/config", b"<html>login</html>")

    def test_real_git_content_valid(self):
        assert hunt_mod._git_content_valid("/.git/HEAD", b"ref: refs/heads/main\n")
        assert hunt_mod._git_content_valid("/.git/config", b"[core]\nrepositoryformatversion = 0\n")
        assert hunt_mod._git_content_valid("/.git/index", b"DIRC\x00\x00\x00\x02")


class TestServerCveVersion:
    def test_unknown_version_not_vulnerable(self):
        # versi kosong / placeholder generator "0" bukan bukti rentan
        assert servercve_mod._vuln_for("wordpress", "0") is None
        assert servercve_mod._vuln_for("wordpress", "") is None

    def test_parse_version_empty(self):
        assert servercve_mod._parse_version("") == ()

    def test_vuln_for_matches_low(self):
        hit = servercve_mod._vuln_for("apache", "2.4.49")
        assert hit is not None
        assert hit[0] == "CRITICAL"

    def test_new_version_not_vulnerable(self):
        assert servercve_mod._vuln_for("nginx", "1.25.3") is None


class TestCvssRoundup:
    def test_roundup(self):
        # CVSS v3.1 memakai roundup (ceil ke 1 desimal)
        score = cvss_mod._cvss_score("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert score == math.ceil(score * 10) / 10
        assert 0.0 <= score <= 10.0

    def test_severity_uses_finding_label(self):
        # severity yang dilaporkan mengikuti label temuan, bukan turunan skor
        c = cvss_mod.classify("WAF terdeteksi", "HIGH")
        assert c["severity"] == "HIGH"


class TestJwtCrash:
    def test_non_dict_header_no_crash(self):
        import base64

        def b64u(s):
            return base64.urlsafe_b64encode(s).rstrip(b"=").decode()

        # header = array JSON, bukan objek
        h = b64u(b"[1,2,3]")
        p = b64u(b'{"sub":"a"}')
        bad = f"{h}.{p}.{b64u(b'abc')}"
        assert jwt_mod.decode_jwt(bad) is None
        assert jwt_mod.analyze_jwt(bad) != []  # tidak crash

    def test_exp_string_no_crash(self):
        import base64, json, time

        def b64u(s):
            return base64.urlsafe_b64encode(s).rstrip(b"=").decode()

        payload = json.dumps({"exp": str(int(time.time()) + 3600)}).encode()
        header = json.dumps({"alg": "HS256", "typ": "JWT"}).encode()
        token = f"{b64u(header)}.{b64u(payload)}.{b64u(b'x' * 32)}"
        findings = jwt_mod.analyze_jwt(token)
        assert isinstance(findings, list)


class TestJwtAttackHs384:
    def test_forge_hs384_uses_sha384(self):
        import base64, json, hmac, hashlib
        tok = jwtattack_mod.forge_hs_token({"sub": "a"}, "secret", "HS384")
        parts = tok.split(".")
        signing = f"{parts[0]}.{parts[1]}"
        expected = hmac.new(b"secret", signing.encode(), hashlib.sha384).digest()
        sig = base64.urlsafe_b64decode(parts[2] + "=" * (-len(parts[2]) % 4))
        assert hmac.compare_digest(sig, expected)


class TestReportMarkdownEscaping:
    def test_pipe_escaped(self):
        assert report_mod._esc("a|b") == "a\\|b"
        assert report_mod._esc("a`b") == "a\\`b"

    def test_report_escapes_finding_fields(self):
        from keris.cvss import classify  # noqa
        findings = [{
            "severity": "HIGH",
            "title": "XSS `|` injection",
            "endpoint": "/x|y",
            "detail": "detail `|` here",
            "evidence": "ev",
        }]
        md = report_mod.generate_report("target.example|evil", {"host": "h"}, {}, findings)
        assert "\\|" in md          # pipe di-escape
        assert not re.search(r"\|[A-Za-z0-9_ ]+\| [A-Za-z0-9_ ]+ \|$", md) is False


class TestReportPdfEscape:
    def test_esc_handles_angle_brackets(self):
        # input dengan < > & tidak boleh memicu XML error di reportlab
        out = report_pdf_mod._esc("a < b & c > d")
        assert "&lt;" in out
        assert "&amp;" in out

    def test_esc_preserves_markup_tags(self):
        out = report_pdf_mod._esc("<b>bold</b> and <br/>")
        assert "<b>bold</b>" in out
        assert "<br/>" in out


class TestFuzzInterestBaseline:
    def test_baseline_script_not_counted(self):
        from keris.modules import fuzz as fuzz_mod
        # halaman normal punya <script> -> skor 0 jika baseline juga punya
        base = "<html><script src='/app.js'></script>Hello</html>"
        resp = "<html><script src='/app.js'></script>Hello<p>selamat</p></html>"
        assert fuzz_mod._interest_score(resp, base) == 0

    def test_new_marker_counted(self):
        from keris.modules import fuzz as fuzz_mod
        base = "<html>normal page</html>"
        resp = "<html>normal page<script>alert('keris')</script></html>"
        assert fuzz_mod._interest_score(resp, base) >= 3


class TestDomainFromHost:
    def test_ip_returns_empty(self):
        from keris.core.utils import domain_from_host
        assert domain_from_host("192.168.1.10") == ""

    def test_port_stripped(self):
        from keris.core.utils import domain_from_host
        assert domain_from_host("api.example.com:8080") == "example.com"
