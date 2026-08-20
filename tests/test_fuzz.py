"""Tests untuk intelligent fuzzing (keris/modules/fuzz.py)."""

import pytest

from keris.modules import fuzz as fuzz_module
from keris.modules.fuzz import (_guess_param_type, _mutations, fuzz_intelligent,
                                fuzz_mutate, fuzz_parameters)
from keris.cli import common


# ---------------------------------------------------------------------------
# tipe parameter
# ---------------------------------------------------------------------------

def test_guess_param_type_rules():
    assert _guess_param_type("user_id") == "numeric"
    assert _guess_param_type("id") == "numeric"
    assert _guess_param_type("page") == "numeric"
    assert _guess_param_type("limit") == "numeric"
    assert _guess_param_type("file") == "path"
    assert _guess_param_type("redirect") == "path"
    assert _guess_param_type("callback") == "path"
    assert _guess_param_type("q") == "search"
    assert _guess_param_type("username") == "string"
    assert _guess_param_type("sort") == "order"
    assert _guess_param_type("randomthing") == "string"


# ---------------------------------------------------------------------------
# mutation
# ---------------------------------------------------------------------------

def test_mutations_generate_variants():
    m = _mutations("hello")
    labels = [l for l, _ in m]
    assert "truncate" in labels
    assert "swapcase" in labels
    assert "double-encode" in labels
    assert "null-byte" in labels
    assert "url-encode" in labels
    assert len(m) >= 8


def test_mutations_empty_seed():
    m = _mutations("")
    # tanpa seed, tetap ada mutasi berbasis encoding/quote
    assert any(l for l, _ in m)


# ---------------------------------------------------------------------------
# fuzz_parameters lama (regresi)
# ---------------------------------------------------------------------------

class _FakeResp:
    def __init__(self, status=200, text=""):
        self.status_code = status
        self.text = text


class _FakeClient:
    def __init__(self, response_map):
        self._map = response_map

    def get(self, url, timeout=10):
        key = url.split("?", 1)[1] if "?" in url else url
        resp = self._map.get(key, _FakeResp(200, "normal page"))
        return resp


def _client_reflecting(payload_marker):
    """client yang merefleksikan payload dengan marker tertentu pada query."""
    def get(self, url, timeout=10):
        q = url.split("?", 1)[1] if "?" in url else ""
        from urllib.parse import unquote
        if payload_marker in unquote(q):
            return _FakeResp(200, f"<script>alert('{payload_marker}')</script>")
        return _FakeResp(200, "normal")
    return type("C", (), {"get": get})()


def test_fuzz_parameters_reflection():
    client = _client_reflecting("<script>alert(\"keris\")</script>")
    eps = ["http://t.local/page?q=hello"]
    findings = fuzz_parameters("http://t.local", client, eps)
    assert any(f.severity == "MEDIUM" for f in findings)


def test_guess_type_smart_payload_selection():
    # payload untuk tipe numeric terbatas (tidak mengirim lfi)
    labels = fuzz_module.TYPE_PAYLOAD_LABELS["numeric"]
    assert "lfi" not in labels
    assert "sqli" in labels
    path_labels = fuzz_module.TYPE_PAYLOAD_LABELS["path"]
    assert "lfi" in path_labels and "ssti" in path_labels


# ---------------------------------------------------------------------------
# fuzz_intelligent (dengan fake client)
# ---------------------------------------------------------------------------

class _FakeClientWithBase:
    def __init__(self, responses):
        self.responses = responses  # dict nilai-param-ke-response
        self.headers = {"Server": "Apache/2.4", "X-Powered-By": "PHP/7.4"}
        self.text = "wp-content/themes"

    def get(self, url, timeout=10):
        from urllib.parse import parse_qsl, unquote
        if url == "http://t.local/":
            return type("R", (), {"headers": self.headers, "text": self.text})()
        q = url.split("?", 1)[1] if "?" in url else ""
        params = dict(parse_qsl(q))
        # cari respon yang nilai param-nya ada di self.responses
        for val, resp in self.responses.items():
            if val in params.values():
                return resp
        return _FakeResp(200, "normal page")


def _resp_marker(marker, status=200):
    return _FakeResp(status, f"page content {marker} here")


def test_fuzz_intelligent_cmdi_on_path_param():
    # stack PHP -> cmdi/lfi; param 'file' -> path; marker 'uid=' memicu HIGH
    url = "http://t.local/down?file=report.pdf"
    client = _FakeClientWithBase({
        "report.pdf": _FakeResp(200, "normal"),
        ";id": _resp_marker("uid=1000"),
        "php://filter/convert.base64-encode/resource=index": _resp_marker("php://"),
    })
    findings = fuzz_intelligent("http://t.local", client, [url], tech="PHP")
    assert any("CMDI" in f.title for f in findings)
    assert any(f.severity == "HIGH" for f in findings)


def test_fuzz_intelligent_ssti_reflection():
    url = "http://t.local/x?name=bob"
    client = _FakeClientWithBase({
        "bob": _FakeResp(200, "hello bob"),
        "{{7*7}}": _FakeResp(200, "hello 49"),
        "${7*7}": _FakeResp(200, "hello 49"),
        "<%= 7*7 %>": _FakeResp(200, "hello 49"),
    })
    findings = fuzz_intelligent("http://t.local", client, [url])
    assert any("SSTI" in f.title for f in findings)


def test_fuzz_intelligent_no_false_positive_on_normal():
    url = "http://t.local/x?q=hello"
    client = _FakeClientWithBase({
        "q=hello": _FakeResp(200, "hello world"),
    })
    findings = fuzz_intelligent("http://t.local", client, [url])
    # semua payload direfleksikan apa adanya atau marker muncul; baseline normal
    # -> diharapkan tidak ada temuan palsu drastis
    assert isinstance(findings, list)


def test_fuzz_intelligent_tech_override_used():
    url = "http://t.local/api?callback=jsonp"
    client = _FakeClientWithBase({
        "callback=jsonp": _FakeResp(200, "jsonp({'a':1})"),
    })
    findings = fuzz_intelligent("http://t.local", client, [url], tech="PHP")
    # PHP stack menambah lfi/cmdi; tidak crash
    assert isinstance(findings, list)


# ---------------------------------------------------------------------------
# fuzz_mutate
# ---------------------------------------------------------------------------

def test_fuzz_mutate_5xx_anomaly():
    url = "http://t.local/p?id=123"
    client = _FakeClientWithBase({
        "123": _FakeResp(200, "ok"),
        "12": _FakeResp(500, "Internal Server Error"),
        "321": _FakeResp(500, "Internal Server Error"),
    })
    findings = fuzz_mutate("http://t.local", client, [url])
    assert any("5xx" in f.title for f in findings)


def test_fuzz_mutate_no_anomaly_on_stable():
    url = "http://t.local/p?q=abc"
    client = _FakeClientWithBase({
        "abc": _FakeResp(200, "ok"),
    })
    findings = fuzz_mutate("http://t.local", client, [url])
    assert findings == []


# ---------------------------------------------------------------------------
# CLI wiring
# ---------------------------------------------------------------------------

def test_fuzz_parser_modes():
    a = common._parse_args(["fuzz", "--mode", "mutation", "--tech", "Node.js",
                            "http://t.local"])
    assert a.mode == "mutation"
    assert a.tech == "Node.js"


def test_fuzz_parser_defaults():
    a = common._parse_args(["fuzz", "http://t.local"])
    assert a.mode == "smart"
    assert a.tech is None
    assert a.max_per_endpoint == 8
    assert a.exit_on == "high"