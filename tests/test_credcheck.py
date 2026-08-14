import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from keris.core.logger import brutal_warning
from keris.modules.credcheck import (
    _find_login_page, _try_form_login, _try_basic_auth,
    extract_creds_from_findings, _normalize_login,
)


class TestCredCheckHelpers:
    def test_normalize_login(self):
        urls = _normalize_login("http://x.com/")
        assert "http://x.com/login" in urls
        assert "http://x.com/wp-login.php" in urls

    def test_extract_creds_from_findings(self):
        findings = [{"evidence": "found admin:password123 in login form", "title": "x"}]
        creds = extract_creds_from_findings(findings)
        assert creds == [("admin", "password123")]

    def test_brutal_warning_contains_key_lines(self):
        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        with redirect_stdout(buf):
            brutal_warning("PWN")
        out = buf.getvalue()
        assert "OVERPOWERED" in out
        assert "RISIKO DITANGGUNG" in out
        assert "IZIN TERTULIS" in out


class TestCredCheckAgainstDemo:
    @classmethod
    def setup_class(cls):
        import subprocess, time
        cls.proc = subprocess.Popen(
            [sys.executable, os.path.join(os.path.dirname(__file__), "demo_vuln_server.py")],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1.5)

    @classmethod
    def teardown_class(cls):
        cls.proc.terminate()

    def test_find_login_page(self):
        import requests
        s = requests.Session()
        url = _find_login_page("http://127.0.0.1:8099", s)
        assert url and url.endswith("/login")

    def test_form_login_valid(self):
        import requests
        s = requests.Session()
        r = _try_form_login("http://127.0.0.1:8099", s, "admin", "password123",
                            "http://127.0.0.1:8099/login")
        assert r["ok"] is True

    def test_form_login_invalid(self):
        import requests
        s = requests.Session()
        r = _try_form_login("http://127.0.0.1:8099", s, "bad", "wrong",
                            "http://127.0.0.1:8099/login")
        assert r["ok"] is False

    def test_basic_auth_unknown_target(self):
        import requests
        s = requests.Session()
        r = _try_basic_auth("http://127.0.0.1:8099", s, "admin", "password123")
        assert r["method"] == "basic"