"""Tes unit untuk batch 3: wayback, dns, buckets, tls, waf, params, export, dashboard, backoff."""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import requests

from keris.core.http import KerisHTTP
from keris.modules.export import export_requests, to_burp_xml, to_curl
from keris.modules.wayback import extract_interesting
from keris.report_dashboard import build_dashboard


class TestWayback:
    def test_extract_interesting(self):
        entries = [
            {"original": "https://x.com/api/v1/users", "mimetype": "application/json"},
            {"original": "https://x.com/home", "mimetype": "text/html"},
            {"original": "https://x.com/static/app.js", "mimetype": "text/javascript"},
        ]
        interesting = extract_interesting(entries)
        assert "https://x.com/api/v1/users" in interesting
        assert "https://x.com/static/app.js" in interesting
        assert "https://x.com/home" not in interesting

    def test_extract_deduplicates(self):
        entries = [
            {"original": "https://x.com/admin", "mimetype": ""},
            {"original": "https://x.com/admin", "mimetype": ""},
        ]
        assert len(extract_interesting(entries)) == 1


class TestExport:
    def test_to_curl(self):
        c = to_curl("GET", "https://x.com/a", headers={"X-K": "1"})
        assert c.startswith("curl")
        assert "-X GET" in c
        assert "https://x.com/a" in c
        assert "X-K: 1" in c

    def test_to_burp_xml(self):
        x = to_burp_xml("GET", "https://x.com/a", headers={"UA": "k"})
        assert "<item>" in x
        assert "base64" in x
        assert "https://x.com/a" in x

    def test_export_curl_uses_endpoints(self):
        findings = [
            {"endpoint": "https://x.com/api", "severity": "HIGH", "title": "t"},
            {"endpoint": "https://x.com/ssrf", "severity": "HIGH", "title": "t"},
        ]
        out = export_requests(findings, "curl", "x")
        assert "https://x.com/api" in out
        assert "https://x.com/ssrf" in out

    def test_export_empty(self):
        assert "Tidak ada endpoint" in export_requests([], "curl", "x")


class TestDashboard:
    def test_build_dashboard(self):
        results = [
            {"target": "https://a", "findings": [
                {"severity": "HIGH", "title": "XSS", "endpoint": "https://a/x",
                 "detail": "reflected"},
            ]},
        ]
        out = "test_dashboard.html"
        build_dashboard(results, out)
        with open(out, encoding="utf-8") as f:
            html = f.read()
        os.remove(out)
        assert "Keris Security Dashboard" in html
        assert "XSS" in html
        assert "1" in html  # count


class TestAdaptiveBackoff:
    def test_429_increases_backoff(self):
        client = KerisHTTP()
        resp = requests.Response()
        resp.status_code = 429
        resp._content = b"Too Many Requests"
        client._update_backoff(resp)
        assert client._backoff > 0
        assert client._consecutive_blocks == 1

    def test_normal_decreases_backoff(self):
        client = KerisHTTP()
        client._backoff = 4.0
        client._consecutive_blocks = 1
        resp = requests.Response()
        resp.status_code = 200
        resp._content = b"ok"
        client._update_backoff(resp)
        assert client._backoff < 4.0
        assert client._consecutive_blocks == 0

    def test_disabled_no_effect(self):
        client = KerisHTTP(adaptive_backoff=False)
        resp = requests.Response()
        resp.status_code = 429
        client._update_backoff(resp)
        assert client._backoff == 0.0


class TestParamsImport:
    def test_hidden_params_wordlist(self):
        from keris.payloads import HIDDEN_PARAMS

        assert "debug" in HIDDEN_PARAMS
        assert "callback" in HIDDEN_PARAMS
        assert len(HIDDEN_PARAMS) > 10
