"""Tests untuk keris toolbox (keris/modules/toolbox.py)."""

import json
import os

import pytest

from keris.modules import toolbox as tb
from keris.cli import common


# ---------------------------------------------------------------------------
# encode / decode
# ---------------------------------------------------------------------------

def test_encode_base64():
    assert tb.encode_text("test", "base64") == "dGVzdA=="


def test_decode_base64_roundtrip():
    assert tb.decode_text(tb.encode_text("hello world", "base64"), "base64") == "hello world"


def test_encode_url():
    assert tb.encode_text("a b&c=d", "url") == "a%20b%26c%3Dd"


def test_decode_url():
    assert tb.decode_text("a%20b", "url") == "a b"


def test_encode_hex():
    assert tb.encode_text("AB", "hex") == "4142"


def test_decode_hex_roundtrip():
    assert tb.decode_text(tb.encode_text("keris", "hex"), "hex") == "keris"


def test_html_unicode_rot13():
    assert tb.encode_text("a", "html") == "&#97;"
    assert tb.encode_text("a", "unicode") == "\\u0061"
    assert tb.encode_text("hello", "rot13") == "uryyb"
    assert tb.decode_text("uryyb", "rot13") == "hello"


def test_decode_html():
    assert tb.decode_text("&#97;&#98;", "html") == "ab"


def test_unknown_encoding_raises():
    with pytest.raises(ValueError):
        tb.encode_text("x", "bogus")


# ---------------------------------------------------------------------------
# hash
# ---------------------------------------------------------------------------

def test_hash_md5():
    assert tb.hash_text("keris", "md5") == "fa0e786060068c22b85aff96b3c9e529"


def test_hash_candidates_all_algos():
    result = tb.hash_candidates("keris")
    assert "sha256" in result and "md5" in result and "sha512" in result


def test_crack_lookup_finds_plaintext():
    h = tb.hash_text("admin123", "sha256")
    found = tb.crack_lookup({"sha256": h}, ["admin", "admin123", "test"])
    assert found and found[0]["plaintext"] == "admin123"


# ---------------------------------------------------------------------------
# payloads
# ---------------------------------------------------------------------------

def test_payload_groups():
    for g in ("sqli", "xss", "lfi", "ssrf", "cmd"):
        assert tb.payload_group(g)


def test_payload_unknown_group():
    with pytest.raises(ValueError):
        tb.payload_group("nope")


def test_payload_mutation_url():
    out = tb.payload_mutation("' OR 1=1--", ["url"])
    assert "' OR 1=1--" in out
    assert any("%27" in m and "OR" in m for m in out)


def test_payload_mutation_dedup():
    out = tb.payload_mutation("ABC", ["lower", "lower"])
    assert out.count("abc") == 1


# ---------------------------------------------------------------------------
# shell
# ---------------------------------------------------------------------------

def test_reverse_shell_bash():
    s = tb.reverse_shell("bash", "10.0.0.1", 4444)
    assert "/dev/tcp/10.0.0.1/4444" in s


def test_reverse_shell_python():
    s = tb.reverse_shell("python", "10.0.0.1", 4444)
    assert "10.0.0.1" in s and "4444" in s


def test_reverse_shell_powershell():
    s = tb.reverse_shell("powershell", "10.0.0.1", 4444)
    assert "TCPClient" in s


def test_reverse_shell_unknown():
    with pytest.raises(ValueError):
        tb.reverse_shell("cobol", "1", 1)


# ---------------------------------------------------------------------------
# wordlist
# ---------------------------------------------------------------------------

def test_wordlist_passwords_seed_variants():
    w = tb.wordlist_passwords("secret")
    assert "secret" in w
    assert "secret123" in w
    assert "Secret" in w


def test_wordlist_passwords_no_dup():
    w = tb.wordlist_passwords()
    assert len(w) == len(set(w))


def test_wordlist_usernames_seed():
    u = tb.wordlist_usernames("acme")
    assert "acme" in u and "adminacme" in u


def test_wordlist_permute():
    out = tb.wordlist_permute("ab", 1, 2, cap=100)
    assert "a" in out and "b" in out and "ab" in out and "ba" in out
    assert len(out) <= 100


# ---------------------------------------------------------------------------
# ports / dns / jwt
# ---------------------------------------------------------------------------

def test_port_service():
    assert tb.port_service(22) == "SSH"
    assert tb.port_service(3306) == "MySQL"
    assert tb.port_service(99999) == "unknown"


def test_common_ports_list():
    assert 80 in tb.common_ports() and 443 in tb.common_ports()


def test_jwt_decode():
    token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.e30."
    d = tb.jwt_decode(token)
    assert d.get("header", {}).get("alg") == "none"


def test_jwt_decode_invalid():
    assert tb.jwt_decode("not.a.jwt") == {}


def test_jwt_analyze_returns_list():
    token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.e30."
    findings = tb.jwt_analyze(token)
    assert isinstance(findings, list)


# ---------------------------------------------------------------------------
# gzip/zlib
# ---------------------------------------------------------------------------

def test_gzip_roundtrip():
    assert tb.gzip_decode(tb.gzip_encode("keris toolbox")) == "keris toolbox"


def test_zlib_roundtrip():
    assert tb.zlib_decode(tb.zlib_encode("keris")) == "keris"


# ---------------------------------------------------------------------------
# CLI wiring
# ---------------------------------------------------------------------------

def test_toolbox_parser_registered():
    a = common._parse_args(["toolbox", "--tool", "encode", "--value", "test"])
    assert a.command == "toolbox"
    assert a.tool == "encode"
    assert a.value == "test"


def test_toolbox_default_tool_list():
    a = common._parse_args(["toolbox"])
    assert a.tool == "list"


def test_toolbox_invalid_tool_rejected():
    with pytest.raises(SystemExit):
        common._parse_args(["toolbox", "--tool", "bogus"])


def test_toolbox_handler_encode(capsys):
    import argparse
    from keris.cli.scan import _cmd_toolbox

    args = argparse.Namespace(tool="encode", value="test", enc="base64",
                              json_output=None)
    rc = _cmd_toolbox(args, None, None)
    out = capsys.readouterr().out
    assert rc == 0
    assert "dGVzdA==" in out


def test_toolbox_handler_hash(capsys):
    import argparse
    from keris.cli.scan import _cmd_toolbox

    args = argparse.Namespace(tool="hash", value="keris", json_output=None)
    rc = _cmd_toolbox(args, None, None)
    out = capsys.readouterr().out
    assert rc == 0
    assert "sha256" in out


def test_toolbox_handler_json_output(tmp_path, capsys):
    import argparse
    from keris.cli.scan import _cmd_toolbox

    out_path = str(tmp_path / "out.json")
    args = argparse.Namespace(tool="hash", value="keris",
                              json_output=out_path)
    rc = _cmd_toolbox(args, None, None)
    assert rc == 0
    with open(out_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert data["tool"] == "hash"