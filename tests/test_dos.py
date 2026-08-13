"""Tes unit untuk modul DoS resilience tester (non-destruktif, tanpa beban nyata)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from keris.core.http import KerisHTTP
from keris.modules.dos import build_slowloris_request, run_dos_test, _Stats


class TestDosHelpers:
    def test_slowloris_request_is_partial(self):
        req = build_slowloris_request("example.com", "/admin")
        assert b"GET /admin HTTP/1.1\r\n" in req
        assert b"Host: example.com" in req
        # header menggantung (tidak ada \r\n\r\n)
        assert req.endswith(b"X-Keep-Alive: ")
        assert b"\r\n\r\n" not in req

    def test_stats_threadsafe(self):
        s = _Stats()
        s.inc_sent()
        s.inc_ok()
        s.enter()
        s.enter()
        s.leave()
        snap = s.snapshot()
        assert snap["sent"] == 1
        assert snap["ok"] == 1
        assert snap["max_concurrent"] == 2
        assert snap["errors"] == 0


class TestDosSafety:
    def test_requires_confirmed(self):
        client = KerisHTTP()
        try:
            findings = run_dos_test("http://127.0.0.1:1", client, confirmed=False)
        finally:
            client.close()
        assert len(findings) == 1
        assert findings[0].severity == "INFO"
        assert "dry-run" in findings[0].title.lower()

    def test_cli_requires_yes(self):
        from keris.__main__ import main

        code = main(["dos", "http://127.0.0.1:1"])
        assert code == 2  # EXIT_ERROR tanpa --yes