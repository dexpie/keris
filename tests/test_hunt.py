import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import json
import struct

from keris.modules.hunt import (_check_config_files, _parse_git_index, _redact,
                                _scan_secrets_in, _urls_from_scan, GIT_INDEX_HEADER,
                                SECRET_PATTERNS, SECRET_TYPES)


class TestHuntGit:
    def test_parse_git_index(self):
        entries = [(b"config/credentials.json", b"a" * 20),
                   (b"src/app/secrets.py", b"b" * 20)]
        data = b"DIRC" + struct.pack(">II", 2, len(entries))
        for name, sha in entries:
            header = struct.pack(">IIIIIIIIII", 0, 0, 0, 0, 0o100644, 0, 0, 0, 0, 0) + sha + struct.pack(">H", len(name))
            entry = header + name + b"\x00"
            pad = (8 - len(entry) % 8) % 8
            data += entry + b"\x00" * pad
        names = _parse_git_index(data)
        assert names == ["config/credentials.json", "src/app/secrets.py"]

    def test_parse_git_index_non_dirc(self):
        assert _parse_git_index(b"NOTDIRCblah") == []

    def test_redact(self):
        assert _redact("AKIAIOSFODNN7EXAMPLE") == "AKIA" + "\u2026" * 4 + "MPLE"
        assert _redact("short") == "short"


class TestHuntSecrets:
    def test_aws_key_detected(self):
        f = _scan_secrets_in("aws_access_key_id = AKIAIOSFODNN7EXAMPLE", "http://x/")
        assert any(x["title"] == "Secret bocor: aws_access_key_id" for x in f)

    def test_github_token_detected(self):
        f = _scan_secrets_in("token=ghp_" + "A" * 36, "http://x/")
        assert any(x["severity"] == "HIGH" and "github" in x["title"] for x in f)

    def test_clean_text_no_secrets(self):
        assert _scan_secrets_in("<p>hello world</p>", "http://x/") == []

    def test_more_than_50_patterns(self):
        assert len(SECRET_PATTERNS) >= 50

    def test_secret_types_sorted_unique(self):
        assert SECRET_TYPES == sorted(set(SECRET_TYPES))
        assert "aws_access_key_id" in SECRET_TYPES
        assert "private_key" in SECRET_TYPES

    def test_private_key_detected(self):
        f = _scan_secrets_in("-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----", "http://x/")
        assert any(x["severity"] == "CRITICAL" and "private_key" in x["title"] for x in f)

    def test_jwt_detected(self):
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.signature"
        f = _scan_secrets_in("token=" + jwt, "http://x/")
        assert any("jwt" in x["title"] for x in f)

    def test_slack_bot_token_detected(self):
        tok = "xoxb-" + "1234567890" + "-" + "1234567890" + "-" + "a" * 24
        f = _scan_secrets_in(tok, "http://x/")
        assert any("slack" in x["title"] for x in f)

    def test_types_filter(self):
        content = "AKIAIOSFODNN7EXAMPLE and token=ghp_" + "A" * 36
        f = _scan_secrets_in(content, "http://x/", types=["github_token"])
        titles = [x["title"] for x in f]
        assert "Secret bocor: github_token" in titles
        assert "Secret bocor: aws_access_key_id" not in titles

    def test_types_filter_multi(self):
        content = "AKIAIOSFODNN7EXAMPLE token=ghp_" + "A" * 36
        f = _scan_secrets_in(content, "http://x/",
                             types=["aws_access_key_id", "github_token"])
        assert len(f) == 2

    def test_ssh_private_key_detected(self):
        f = _scan_secrets_in("-----BEGIN OPENSSH PRIVATE KEY-----", "http://x/")
        assert any("private_key" in x["title"] for x in f)

    def test_openai_key_detected(self):
        f = _scan_secrets_in("sk-abcdef0123456789ghij", "http://x/")
        assert any("openai" in x["title"] for x in f)


class TestHuntUrlsFromScan:
    def test_urls_extracted(self, tmp_path):
        p = tmp_path / "scan.json"
        p.write_text(json.dumps({"findings": [
            {"endpoint": "http://t/1"},
            {"endpoint": "http://t/2"},
            {"not-endpoint": 1},
            "garbage",
        ]}), encoding="utf-8")
        urls = _urls_from_scan(str(p))
        assert urls == ["http://t/1", "http://t/2"]

    def test_missing_file(self):
        assert _urls_from_scan("no-such-file.json") == []


class TestHuntDeepConfig:
    class FakeClient:
        def __init__(self, hits):
            self.hits = hits

        def get(self, url, timeout=None):
            class Resp:
                status_code = 404
                text = ""

            for h in self.hits:
                if url.endswith(h):
                    Resp.status_code = 200
                    Resp.text = "DB_PASSWORD='sup3rsecret123'"
                    return Resp
            return Resp()

    def test_deep_path_probed(self):
        client = self.FakeClient(["backup/.env"])
        findings = _check_config_files(client, "http://t", deep=True)
        urls = [f["endpoint"] for f in findings]
        assert any("backup/.env" in u for u in urls)

    def test_spa_404_not_reported(self):
        class SpaClient:
            def get(self, url, timeout=None):
                class Resp:
                    status_code = 200
                    text = "<html><head><title>SPA</title></head>"
                return Resp()
        findings = _check_config_files(SpaClient(), "http://t")
        assert findings == []

    def test_types_filter_config(self):
        client = self.FakeClient([".env"])
        # password excluded from types -> tidak ada secret hit, tapi file tetap dilaporkan
        findings = _check_config_files(client, "http://t", types=["github_token"])
        envs = [f for f in findings if f["endpoint"].endswith("/.env")]
        assert envs and envs[0]["severity"] == "MEDIUM"


class TestHuntConfig:
    def test_config_file_high_when_secret(self):
        class FakeResp:
            status_code = 200
            text = "DB_PASSWORD='sup3rsecret123'"

        class FakeClient:
            def get(self, url, timeout=None):
                if url.endswith("/.env"):
                    return FakeResp()
                class _404:
                    status_code = 404
                return _404()

        findings = _check_config_files(FakeClient(), "http://t")
        envs = [f for f in findings if f["endpoint"].endswith("/.env")]
        assert envs and envs[0]["severity"] == "HIGH"