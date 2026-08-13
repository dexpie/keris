"""Tes unit untuk fitur baru: JWT, project self-audit, utils tambahan."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from keris.core.utils import set_query_param
from keris.modules.jwt import analyze_jwt, decode_jwt, extract_jwts
from keris.modules.project import _scan_file, PATTERNS


class TestSetQueryParam:
    def test_param_named_url(self):
        out = set_query_param("http://x/fetch?url=a", "url", "http://127.0.0.1/")
        assert "url=http%3A%2F%2F127.0.0.1%2F" in out

    def test_normal_param(self):
        out = set_query_param("http://x/s?id=1", "id", "2")
        assert "id=2" in out


class TestJwt:
    def test_decode_valid(self):
        tok = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
               ".eyJzdWIiOiIxMjM0NTY3ODkwIn0"
               ".signature")
        d = decode_jwt(tok)
        assert d is not None
        assert d["header"]["alg"] == "HS256"

    def test_decode_invalid(self):
        assert decode_jwt("not-a-jwt") is None

    def test_missing_exp(self):
        tok = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
               ".eyJzdWIiOiIxMjM0NTY3ODkwIn0"
               ".signature")
        findings = analyze_jwt(tok)
        assert any("exp" in f.detail for f in findings)

    def test_weak_secret(self):
        # token valid dengan secret "secret" (HS256)
        import base64
        import hashlib
        import hmac
        import json

        h = base64.urlsafe_b64encode(
            json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).rstrip(b"=").decode()
        p = base64.urlsafe_b64encode(
            json.dumps({"sub": "1"}).encode()).rstrip(b"=").decode()
        sig = base64.urlsafe_b64encode(
            hmac.new(b"secret", f"{h}.{p}".encode(), hashlib.sha256).digest()
        ).rstrip(b"=").decode()
        tok = f"{h}.{p}.{sig}"
        findings = analyze_jwt(tok)
        assert any(f.severity == "HIGH" and "secret" in f.detail for f in findings)

    def test_extract_jwts(self):
        tok = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
               ".eyJzdWIiOiIxMjM0NTY3ODkwIn0"
               ".signature")
        toks = extract_jwts(f'bearer "{tok}"')
        assert tok in toks


class TestProjectAudit:
    def test_sql_injection_detected(self):
        # skrip yang sengaja rawan
        script = (
            'import sqlite3\n'
            'def get(ident):\n'
            '    cur.execute("SELECT * FROM users WHERE id = " + ident)\n'
        )
        os.makedirs("_tmp_audit", exist_ok=True)
        path = os.path.join("_tmp_audit", "vuln.py")
        with open(path, "w", encoding="utf-8") as f:
            f.write(script)
        findings = _scan_file(path, "_tmp_audit")
        os.remove(path)
        os.rmdir("_tmp_audit")
        assert any(f["severity"] == "HIGH" and "SQL" in f["rule"] for f in findings)

    def test_hardcoded_secret_detected(self):
        script = 'password = "hunter2hunter2"\n'
        os.makedirs("_tmp_audit", exist_ok=True)
        path = os.path.join("_tmp_audit", "app.py")
        with open(path, "w", encoding="utf-8") as f:
            f.write(script)
        findings = _scan_file(path, "_tmp_audit")
        os.remove(path)
        os.rmdir("_tmp_audit")
        assert any("secret" in f["rule"].lower() for f in findings)

    def test_patterns_are_valid_regex(self):
        import re

        for rule in PATTERNS:
            re.compile(rule["regex"])  # tidak boleh error