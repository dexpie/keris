"""Tes unit untuk utilitas inti Keris."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from keris.core.utils import (
    normalize_url,
    host_from_url,
    add_query,
    extract_urls,
    extract_api_paths,
    extract_js_assets,
    domain_from_host,
)


class TestNormalizeUrl:
    def test_adds_https(self):
        assert normalize_url("example.com").startswith("https://example.com")

    def test_preserves_scheme(self):
        assert normalize_url("http://example.com").startswith("http://")

    def test_strips_trailing_slash(self):
        assert normalize_url("https://example.com/path/") == "https://example.com/path"

    def test_root_keeps_slash(self):
        assert normalize_url("https://example.com/") == "https://example.com/"

    def test_lowercases_host(self):
        assert normalize_url("https://EXAMPLE.com/A") == "https://example.com/A"


class TestHostFromUrl:
    def test_host(self):
        assert host_from_url("https://example.com/path") == "example.com"


class TestAddQuery:
    def test_adds_param(self):
        assert "a=1" in add_query("https://example.com/api", a="1")

    def test_updates_param(self):
        out = add_query("https://example.com/api?x=1", x="2")
        assert "x=2" in out and "x=1" not in out


class TestExtractUrls:
    def test_absolute(self):
        urls = extract_urls('var x = "https://api.example.com/v1/users?id=1";')
        assert any("https://api.example.com" in u for u in urls)

    def test_api_path(self):
        urls = extract_urls('fetch("/api/auth/login")')
        assert "/api/auth/login" in urls


class TestExtractApiPaths:
    def test_paths(self):
        paths = extract_api_paths('fetch(`/api/users/${id}`, {method:"POST"})')
        assert any("/api/users/" in p for p in paths)


class TestExtractJsAssets:
    def test_assets(self):
        html = '<script src="/_next/static/chunks/app.js"></script>'
        assets = extract_js_assets(html, "https://example.com")
        assert "https://example.com/_next/static/chunks/app.js" in assets


class TestDomainFromHost:
    def test_subdomain(self):
        assert domain_from_host("api.example.com") == "example.com"

    def test_cctld(self):
        assert domain_from_host("sub.example.co.id") == "example.co.id"

    def test_plain(self):
        assert domain_from_host("example.com") == "example.com"
