"""Test Template / Rule engine (YAML) v0.13.0: parsing, matchers, akurasi, integrasi."""

import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path == "/.env":
            body = b"DB_PASSWORD='secret'\nAWS_ACCESS_KEY_ID=AKIA123"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/uploads/":
            body = b"<html><h1>Index of /uploads/</h1><a href='a.txt'>a.txt</a></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/phpinfo.php":
            body = b"<html><h1>phpinfo()</h1><table><td>PHP Version</td></table></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html>Not Found</html>")


@pytest.fixture(scope="module")
def server_url():
    httpd = HTTPServer(("127.0.0.1", 0), _Handler)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()


def _tpl(id, severity, matchers, requests=None, conf=0.7):
    req = requests or [{"method": "GET", "path": "/x", "matchers": matchers}]
    return {"id": id, "info": {"name": id, "severity": severity,
                               "description": "d", "tags": ["t"],
                               "confidence": conf},
            "requests": req}


class TestParse:
    def test_valid_template(self):
        from keris.templates import parse_template
        t = parse_template(_tpl("a", "HIGH", [{"type": "status", "status": [200]}]))
        assert t.id == "a"
        assert t.severity == "HIGH"
        assert t.confidence == 0.7
        assert len(t.requests) == 1

    def test_missing_id_rejected(self):
        from keris.templates import TemplateError, parse_template
        with pytest.raises(TemplateError):
            parse_template({"info": {"name": "x"}, "requests": []})

    def test_no_matchers_rejected(self):
        from keris.templates import TemplateError, parse_template
        with pytest.raises(TemplateError):
            parse_template(_tpl("a", "HIGH", []))

    def test_bad_matcher_type_rejected(self):
        from keris.templates import TemplateError, parse_template
        with pytest.raises(TemplateError):
            parse_template(_tpl("a", "HIGH", [{"type": "bogus", "x": 1}]))

    def test_invalid_severity_defaults(self):
        from keris.templates import parse_template
        t = parse_template(_tpl("a", "weird", [{"type": "status", "status": [200]}]))
        assert t.severity == "INFO"

    def test_confidence_clamped(self):
        from keris.templates import parse_template
        t = parse_template(_tpl("a", "HIGH", [{"type": "status", "status": [200]}], conf=2.0))
        assert t.confidence <= 0.99


class TestMatchers:
    def test_word_and_condition(self):
        from keris.templates import _match_text
        m = {"type": "word", "words": ["abc", "def"], "condition": "and"}
        assert _match_text(m, "xx abc yy def zz") is True
        assert _match_text(m, "xx abc yy") is False

    def test_word_or_condition(self):
        from keris.templates import _match_text
        m = {"type": "word", "words": ["abc", "def"], "condition": "or"}
        assert _match_text(m, "xx def") is True

    def test_negative_word(self):
        from keris.templates import _match_text
        m = {"type": "word", "words": ["Not Found"], "negative": True}
        assert _match_text(m, "hello world") is True
        assert _match_text(m, "Page Not Found here") is False

    def test_regex_match(self):
        from keris.templates import _match_text
        m = {"type": "regex", "regex": ["(?m)^[A-Z][A-Z0-9_]{2,}\\s*="]}
        assert _match_text(m, "DB_PASSWORD='x'") is True
        assert _match_text(m, "hello world") is False

    def test_header_part(self):
        from keris.templates import _match_body
        m = {"type": "word", "words": ["nginx/1.18"], "part": "header"}
        assert _match_body(m, "<html></html>", {"server": "nginx/1.18"}) is True


class TestAccuracy:
    def test_dotenv_detected(self, server_url):
        from keris.core.http import KerisHTTP
        from keris.templates import load_templates, run_templates
        tpls = [t for t in load_templates() if t.id == "dotenv-exposed"]
        client = KerisHTTP(timeout=10)
        f = run_templates(tpls, client, server_url)
        assert any(x["endpoint"].endswith("/.env") for x in f)

    def test_directory_listing_detected(self, server_url):
        from keris.core.http import KerisHTTP
        from keris.templates import load_templates, run_templates
        tpls = [t for t in load_templates() if t.id == "directory-listing"]
        client = KerisHTTP(timeout=10)
        f = run_templates(tpls, client, server_url)
        assert any(x["endpoint"].endswith("/uploads/") for x in f)

    def test_phpinfo_detected(self, server_url):
        from keris.core.http import KerisHTTP
        from keris.templates import load_templates, run_templates
        tpls = [t for t in load_templates() if t.id == "phpinfo-exposed"]
        client = KerisHTTP(timeout=10)
        f = run_templates(tpls, client, server_url)
        assert any(x["endpoint"].endswith("/phpinfo.php") for x in f)

    def test_no_match_on_404_no_fp(self, server_url):
        from keris.core.http import KerisHTTP
        from keris.templates import load_templates, run_templates
        tpls = [t for t in load_templates() if t.id in ("git-config-exposed", "sql-backup-exposed")]
        client = KerisHTTP(timeout=10)
        f = run_templates(tpls, client, server_url)
        assert not f, "server uji tidak punya .git/db.sql -> tidak boleh ada temuan (no FP)"

    def test_confidence_uses_template_base(self):
        from keris.confidence import score_finding
        f = score_finding({"source": "template-git-config-exposed",
                           "title": "x", "detail": "y", "evidence": "z",
                           "confidence": 0.95, "severity": "HIGH"})
        assert f["confidence"] == pytest.approx(0.95, abs=0.01)

    def test_template_confidence_high_for_multi_matcher(self):
        from keris.templates import _template_confidence
        assert _template_confidence(
            {"matchers": [{"type": "status", "status": [200]},
                          {"type": "word", "words": ["a"]},
                          {"type": "regex", "regex": ["b"]}]}) >= 0.85


class TestLoadPack:
    def test_default_pack_loads(self):
        from keris.templates import load_templates
        t = load_templates()
        assert len(t) >= 8
        ids = {x.id for x in t}
        assert {"dotenv-exposed", "git-config-exposed", "directory-listing",
                "phpinfo-exposed", "sql-backup-exposed"} <= ids

    def test_run_template_keeps_confidence(self, server_url):
        from keris.templates import load_templates, run_templates
        tpl = [t for t in load_templates() if t.id == "dotenv-exposed"][0]
        from keris.core.http import KerisHTTP
        client = KerisHTTP(timeout=10)
        f = run_templates([tpl], client, server_url)
        assert f, "dotenv template harus match"
        assert f[0]["confidence"] == pytest.approx(0.9, abs=0.05)
        assert f[0]["source"] == "template-dotenv-exposed"
        from keris.finding import normalize_finding
        n = normalize_finding(f[0])
        assert n["id"]
        assert n["schema_version"] == "1.0.0"