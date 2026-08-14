import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from keris.modules.ssrf import _callback_host, _inject, _param_names
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