"""Tes v0.14.0: HAR/Postman import, reverse engineering JS, backdoor detection."""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import pytest


def _write(tmp_path, name, data):
    p = tmp_path / name
    p.write_text(json.dumps(data), encoding="utf-8")
    return str(p)


HAR = {
    "log": {
        "version": "1.2",
        "creator": {"name": "t"},
        "entries": [
            {"request": {
                "method": "GET",
                "url": "https://example.com/api/users",
                "headers": [{"name": "Authorization", "value": "Bearer abc"}],
                "cookies": [{"name": "session", "value": "s1"}],
                "postData": {},
            }},
            {"request": {
                "method": "POST",
                "url": "https://example.com/api/login",
                "headers": [],
                "cookies": [],
                "postData": {"mimeType": "application/json",
                             "text": '{"user":"admin"}'},
            }},
        ],
    }
}

POSTMAN = {
    "info": {"name": "x", "_postman_id": "abc"},
    "item": [
        {"request": {"method": "GET", "url": {"raw": "https://example.com/a",
                                              "host": ["example.com"], "path": ["a"]},
                     "header": [{"key": "X-K", "value": "v"}], "body": {}}},
        {"item": [
            {"request": {"method": "POST",
                         "url": "https://example.com/submit",
                         "header": [],
                         "body": {"mode": "urlencoded",
                                  "urlencoded": [{"key": "q", "value": "1"}]}}},
        ]},
    ],
}


class TestHarImport:
    def test_parse_har(self, tmp_path):
        from keris.har import parse_har

        p = _write(tmp_path, "s.har", HAR)
        reqs = parse_har(p)
        assert len(reqs) == 2
        assert reqs[0].method == "GET"
        assert reqs[0].url == "https://example.com/api/users"
        assert reqs[0].cookies == {"session": "s1"}
        assert reqs[0].headers.get("Authorization") == "Bearer abc"
        assert "admin" in reqs[1].data

    def test_parse_postman_flatten(self, tmp_path):
        from keris.har import parse_postman

        p = _write(tmp_path, "c.json", POSTMAN)
        reqs = parse_postman(p)
        assert len(reqs) == 2
        assert reqs[0].url == "https://example.com/a"
        assert reqs[0].headers.get("X-K") == "v"
        assert reqs[1].data == "q=1"

    def test_auto_detect_har(self, tmp_path):
        from keris.har import requests_from_file

        p = _write(tmp_path, "s.har", HAR)
        reqs = requests_from_file(p)
        assert len(reqs) == 2

    def test_auto_detect_postman(self, tmp_path):
        from keris.har import requests_from_file

        p = _write(tmp_path, "c.json", POSTMAN)
        reqs = requests_from_file(p)
        assert len(reqs) == 2

    def test_auto_detect_rejects_junk(self, tmp_path):
        from keris.har import requests_from_file

        p = tmp_path / "bad.json"
        p.write_text('{"foo": 1}', encoding="utf-8")
        with pytest.raises(ValueError):
            requests_from_file(str(p))


class TestRecorder:
    def test_recorder_to_har(self):
        from keris.har import RequestsRecorder

        rec = RequestsRecorder()
        rec.record("POST", "https://x.test/api", {"A": "1"}, {"c": "v"}, '{"q":1}')
        har = rec.to_har()
        assert har["log"]["entries"][0]["request"]["method"] == "POST"
        assert har["log"]["entries"][0]["request"]["postData"]["text"] == '{"q":1}'

    def test_recorder_save_roundtrip(self, tmp_path):
        from keris.har import RequestsRecorder, parse_har

        rec = RequestsRecorder()
        rec.record("GET", "https://x.test/", {}, {}, "")
        out = str(tmp_path / "r.har")
        rec.save(out)
        assert len(parse_har(out)) == 1


class TestReverse:
    def test_deobfuscate_eval_atob(self):
        from keris.modules.reverse import deobfuscate_js

        import base64

        enc = base64.b64encode(b"alert(1)").decode()
        out = deobfuscate_js(f"eval(atob('{enc}'))")
        assert "alert(1)" in out

    def test_deobfuscate_hex_unicode(self):
        from keris.modules.reverse import deobfuscate_js

        out = deobfuscate_js(r"var a = '\x61\x62\x63' + '\u0064';")
        assert "abc" in out and "d" in out

    def test_deobfuscate_concat(self):
        from keris.modules.reverse import deobfuscate_js

        out = deobfuscate_js("'a' + 'b'")
        assert "ab" in out or "'a''b'" in out

    def test_extract_endpoints(self):
        from keris.modules.reverse import extract_endpoints

        text = 'fetch("/api/admin"); axios.post("/internal/users"); "https://x.test/private?q=1"'
        eps = extract_endpoints(text, "https://x.test")
        assert any(e.startswith("/api/admin") for e in eps)
        assert any(e.startswith("/internal/users") for e in eps)
        assert any(e.startswith("/private") for e in eps)

    def test_extract_secrets(self):
        from keris.modules.reverse import extract_secrets

        text = 'apiKey = "sk_live_1234567890abcdef"; AKIAABCDEFGHIJKLMNOP'
        sec = extract_secrets(text)
        types = {s["type"] for s in sec}
        assert "api_key" in types
        assert "AWS Access Key" in types or "aws" in types
        # no duplicated match strings
        matches = [s["match"] for s in sec]
        assert len(matches) == len(set(matches))

    def test_stats_obfuscation(self):
        from keris.modules.reverse import stats

        s = stats('var a=1;var b=2;var c=3;' * 40)
        assert s["short_identifiers"] >= 3
        assert s["obfuscation_signals"] >= 0

    def test_stats_detect_obfuscated(self):
        from keris.modules.reverse import stats

        s = stats("var x=1;var y=2;var z=3;var w=4;var v=5;var u=6;" * 30)
        assert s["obfuscation_signals"] >= 1


class TestBackdoor:
    def test_suspicious_script_ip(self):
        from keris.modules.backdoor import scan_page

        html = '<script src="http://185.199.10.10/x.js"></script>'
        fs = scan_page(html, "https://example.com", "https://example.com")
        assert any("Script eksternal" in f.title for f in fs)

    def test_trusted_cdn_not_flagged(self):
        from keris.modules.backdoor import scan_page

        html = '<script src="https://cdnjs.cloudflare.com/ajax/libs/x.js"></script>'
        fs = scan_page(html, "https://example.com", "https://example.com")
        assert not any("Script eksternal" in f.title for f in fs)

    def test_suspicious_tld_iframe(self):
        from keris.modules.backdoor import scan_page

        html = '<iframe src="http://pixel.top/t.gif"></iframe>'
        fs = scan_page(html, "https://example.com", "https://example.com")
        assert any("iframe" in f.title for f in fs)

    def test_webshell_signature(self):
        from keris.modules.backdoor import scan_page

        html = "eval(gzinflate(base64_decode('AAAA')));"
        fs = scan_page(html, "https://example.com", "https://example.com")
        assert any("backdoor" in f.title.lower() for f in fs)

    def test_encoded_url_to_suspicious(self):
        from keris.modules.backdoor import scan_page

        import base64

        enc = base64.b64encode(b"http://evil.top/x").decode()
        html = f"atob('{enc}')"
        fs = scan_page(html, "https://example.com", "https://example.com")
        assert any("ter-encode" in f.title for f in fs)

    def test_no_false_positive_clean_page(self):
        from keris.modules.backdoor import scan_page

        html = ("<html><script src='https://cdnjs.cloudflare.com/x.js'></script>"
                "<link href='/style.css' rel='stylesheet'>"
                "<a href='/page2'>ok</a></html>")
        fs = scan_page(html, "https://example.com", "https://example.com")
        assert fs == []

    def test_private_ip_not_flagged(self):
        from keris.modules.backdoor import _is_suspicious_host

        bad, reason = _is_suspicious_host("192.168.1.10")
        assert not bad
        bad, reason = _is_suspicious_host("10.0.0.5")
        assert not bad
        bad, reason = _is_suspicious_host("172.16.5.5")
        assert not bad
        bad, reason = _is_suspicious_host("127.0.0.1")
        assert not bad

    def test_public_ip_flagged(self):
        from keris.modules.backdoor import _is_suspicious_host

        bad, reason = _is_suspicious_host("8.8.8.8")
        assert bad
        bad, reason = _is_suspicious_host("185.199.10.10")
        assert bad

    def test_private_ip_script_from_other_host_flagged(self):
        from keris.modules.backdoor import scan_page

        # script dari IP privat BEDA host (mis. target di VPS, script dari intranet)
        html = '<script src="http://192.168.1.20/x.js"></script>'
        fs = scan_page(html, "https://example.com", "https://example.com")
        assert any("Script eksternal" in f.title for f in fs)


class TestReverseEndpointExtract:
    def test_fetch_and_axios(self):
        from keris.modules.reverse import extract_endpoints

        text = 'fetch("/api/users?page=2"); axios.post("/v1/items");'
        eps = extract_endpoints(text, "https://x.test")
        assert "/api/users" in eps
        assert "/v1/items" in eps

    def test_dedupe_secrets(self):
        from keris.modules.reverse import extract_secrets

        text = "AKIAABCDEFGHIJKLMNOP AKIAABCDEFGHIJKLMNOP"
        sec = extract_secrets(text)
        assert len({s["match"] for s in sec}) == len([s for s in sec])
        assert len(sec) >= 1

    def test_payload_secret_slack(self):
        from keris.modules.reverse import extract_secrets

        fake_slack = "xox" + "b-" + "1234567890-abcdefghijklmnopqrst"
        sec = extract_secrets('token = "' + fake_slack + '"')
        assert any(s["type"] == "Slack Token" for s in sec)


class TestRecorderCookie:
    def test_wrap_captures_cookie(self):
        from keris.har import RequestsRecorder

        rec = RequestsRecorder()

        class FakeClient:
            session = type("S", (), {"headers": {"Cookie": "a=1; b=2"}})()

            def request(self, method, url, **kwargs):
                return None

        rec.wrap(FakeClient()).request("GET", "https://x.test/")
        entry = rec.entries[0]
        cookies = {c["name"]: c["value"] for c in entry["request"]["cookies"]}
        assert cookies == {"a": "1", "b": "2"}