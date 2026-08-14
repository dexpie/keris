import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from keris.modules.ssrf import (
    _callback_host, _inject, _param_names, _fetch_through,
    exploit_metadata, scan_internal_ports, INTERNAL_PORTS,
)
from keris.modules.waf import _signature_hits, PROBE_PAYLOADS


class FakeResp:
    def __init__(self, headers=None, text=""):
        self.headers = headers or {}
        self.text = text
        self.status_code = 200


class TestSsrfinject:
    def test_param_names(self):
        assert _param_names("http://x/api?url=http://y") == ["url"]
        assert _param_names("http://x/a?b=1&c=2") == ["b", "c"]
        assert _param_names("http://x/noquery") == []

    def test_inject(self):
        out = _inject("http://x/api?url=http://y", "url", "http://cb/c")
        assert "url=http%3A%2F%2Fcb%2Fc" in out

    def test_callback_host_loopback(self):
        assert _callback_host("http://127.0.0.1:8099/") == "127.0.0.1"
        assert _callback_host("http://localhost/") == "127.0.0.1"
        assert _callback_host("http://192.168.1.5/") == "127.0.0.1"

    def test_callback_host_remote(self):
        host = _callback_host("http://example.com/")
        # remote -> bukan loopback (IP LAN mesin atau 127.0.0.1 fallback)
        assert host


class TestWafSignatures:
    def test_cloudflare_header(self):
        resp = FakeResp(headers={"Cf-Ray": "abc123"})
        hits = _signature_hits(resp, "hello")
        assert "Cloudflare" in hits

    def test_modsecurity_body(self):
        resp = FakeResp(headers={})
        hits = _signature_hits(resp, "ModSecurity: Access denied")
        assert "ModSecurity / OWASP CRS" in hits

    def test_no_sig(self):
        resp = FakeResp(headers={"Server": "nginx"})
        assert _signature_hits(resp, "<html>ok</html>") == []

    def test_probe_payloads_nonempty(self):
        assert len(PROBE_PAYLOADS) >= 5


class TestSsrfExploit:
    def test_fetch_through_returns(self):
        class FakeClient:
            def get(self, url, timeout=None):
                class R:
                    status_code = 200
                    text = "fetched:" + url
                return R()
        code, body = _fetch_through("http://x/", FakeClient(),
                                    "http://x/api?u=1", "u", "http://169.254.169.254/latest/meta-data/")
        assert code == 200 and "169.254.169.254" in body

    def test_fetch_through_error(self):
        class FakeClient:
            def get(self, url, timeout=None):
                raise Exception("boom")
        code, body = _fetch_through("http://x/", FakeClient(),
                                    "http://x/api?u=1", "u", "http://y/")
        assert code is None and body == ""

    def test_exploit_metadata_detects_aws(self):
        class FakeClient:
            def get(self, url, timeout=None):
                if "security-credentials" in url:
                    class R:
                        status_code = 200
                        text = '{"AccessKeyId":"AKIA...","Token":"x"}'
                else:
                    class R:
                        status_code = 404
                        text = "not found"
                return R()
        fs = exploit_metadata("http://x/", FakeClient(),
                              "http://x/api?u=1", "u")
        assert fs and fs[0]["severity"] == "CRITICAL"
        assert "AWS" in fs[0]["title"]

    def test_exploit_metadata_no_hit(self):
        class FakeClient:
            def get(self, url, timeout=None):
                class R:
                    status_code = 404
                    text = "nothing"
                return R()
        assert exploit_metadata("http://x/", FakeClient(),
                                "http://x/api?u=1", "u") == []

    def test_scan_ports_filters_gateway_error(self):
        class FakeClient:
            def get(self, url, timeout=None):
                class R:
                    status_code = 502 if "%3A443%2F" in url else 200
                    text = "" if "%3A443%2F" in url else "banner"
                return R()
        fs = scan_internal_ports("http://x/", FakeClient(),
                                 "http://x/api?u=1", "u", timeout=1)
        assert fs and "443" not in fs[0]["evidence"]

    def test_internal_ports_list(self):
        assert (3306, "MySQL") in INTERNAL_PORTS
        assert (6379, "Redis") in INTERNAL_PORTS