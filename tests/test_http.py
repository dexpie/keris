"""Tests untuk keris HTTP mass-scan (keris/modules/http.py)."""

from keris.modules import http as httpmod


def test_title_extraction():
    assert httpmod._title("<html><title>Hello World</title></html>") == "Hello World"
    assert httpmod._title("<html></html>") == ""


def test_tech_detection():
    headers = {"Server": "nginx/1.24.0", "X-Powered-By": "PHP/8.2"}
    tech = httpmod._tech(headers)
    assert "nginx" in tech
    assert "PHP/8.2" in tech
    assert httpmod._tech({}) == []


def test_probe_error():
    class _C:
        def get(self, url, timeout=8, allow_redirects=True):
            raise RuntimeError("boom")

    res = httpmod._probe("http://x.test", _C(), 8.0, False)
    assert res["status"] == 0
    assert "boom" in res["error"]


def test_scan_urls_empty():
    assert httpmod.scan_urls([], workers=2, timeout=1) == []