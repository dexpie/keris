import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import struct

from keris.modules.hunt import (_check_config_files, _parse_git_index, _redact,
                                _scan_secrets_in, GIT_INDEX_HEADER)


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