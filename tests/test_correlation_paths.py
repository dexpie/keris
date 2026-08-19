"""Tes v0.15.0: Attack Path Generator + Prioritization + Graphviz DOT."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))


def _f(sev, title, endpoint, detail=""):
    return {"severity": sev, "title": title, "endpoint": endpoint,
            "detail": detail, "evidence": ""}


class TestPathGenerator:
    def test_build_paths_empty(self):
        from keris.modules.correlation import build_paths

        assert build_paths([]) == []

    def test_build_paths_chain_formed(self):
        from keris.modules.correlation import build_paths

        findings = [
            _f("HIGH", ".git/config terekspos", "http://x/.git/config",
               "git source tree dapat diunduh"),
            _f("CRITICAL", "AWS key ditemukan di .git", "http://x/.git/config",
               "aws access key bocor, secret aws"),
            _f("CRITICAL", "AWS key live terverifikasi", "http://x/",
               "GetAccessKeyLastUsed mengembalikan kredensial aktif"),
        ]
        paths = build_paths(findings, path_depth=3)
        assert paths, "harus ada attack path"

    def test_paths_have_score_and_impact(self):
        from keris.modules.correlation import build_paths

        findings = [
            _f("HIGH", ".git config bocor", "http://x/.git/config", "source"),
            _f("CRITICAL", "secret aws ditemukan", "http://x/", "token"),
        ]
        paths = build_paths(findings)
        assert paths
        p = paths[0]
        assert p["score"] > 0
        assert p["severity"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
        assert p["impact"]

    def test_criticality_score_weight(self):
        from keris.modules.correlation import criticality_score

        low = criticality_score([{"severity": "LOW"}, {"severity": "LOW"}])
        high = criticality_score([{"severity": "CRITICAL"}, {"severity": "CRITICAL"}])
        assert high > low

    def test_short_path_scored_higher_than_long(self):
        from keris.modules.correlation import criticality_score

        short = criticality_score([{"severity": "HIGH"}, {"severity": "CRITICAL"}])
        long = criticality_score([{"severity": "HIGH"}, {"severity": "MEDIUM"},
                                  {"severity": "MEDIUM"}, {"severity": "CRITICAL"}])
        assert short > long

    def test_path_depth_respected(self):
        from keris.modules.correlation import build_paths

        findings = [
            _f("HIGH", "listing terbuka", "http://x/upload", "directory listing"),
            _f("HIGH", "backup terekspos", "http://x/upload/db.sql", "backup"),
            _f("HIGH", "sql dump berisi data", "http://x/", "database sqlite leak"),
            _f("CRITICAL", "kredensial admin di dump", "http://x/", "secret token"),
        ]
        deep = build_paths(findings, path_depth=4)
        shallow = build_paths(findings, path_depth=2)
        assert len(deep) >= len(shallow)


class TestDotRender:
    def test_render_dot_structure(self):
        from keris.modules.correlation import build_paths, render_dot

        findings = [
            _f("HIGH", ".git exposure", "http://x/.git/config", "git"),
            _f("CRITICAL", "aws key leaked", "http://x/", "token"),
        ]
        paths = build_paths(findings)
        dot = render_dot(paths, "http://x")
        assert dot.startswith("digraph")
        assert '->' in dot

    def test_save_dot(self, tmp_path):
        from keris.modules.correlation import build_paths, save_dot

        findings = [
            _f("HIGH", ".git exposure", "http://x/.git/config", "git"),
            _f("CRITICAL", "aws key leaked", "http://x/", "token"),
        ]
        paths = build_paths(findings)
        out = str(tmp_path / "ap.dot")
        saved = save_dot(paths, out, "http://x")
        assert saved == out
        assert os.path.exists(out)


class TestMarkdown:
    def test_paths_markdown_renders_steps(self):
        from keris.modules.correlation import build_paths, paths_markdown

        findings = [
            _f("HIGH", "listing terbuka", "http://x/upload", "directory listing"),
            _f("HIGH", "backup db.sql", "http://x/upload/db.sql", "backup sqlite"),
            _f("CRITICAL", "sql dump kredensial", "http://x/", "database secret"),
        ]
        paths = build_paths(findings)
        md = paths_markdown(paths)
        if not paths:
            assert md == []
            return
        assert md[0] == "## Attack Paths"
        assert any("Criticality Score" in l for l in md)
        assert any(l.strip().startswith("1.") for l in md)
        assert any("Impact" in l for l in md)

    def test_paths_markdown_empty(self):
        from keris.modules.correlation import paths_markdown

        assert paths_markdown([]) == []


class TestChainsStillWork:
    def test_build_chains_unchanged(self):
        from keris.modules.correlation import build_chains

        fs = [
            _f("MEDIUM", "Cache poisoning header", "http://x/", "cache poison"),
            _f("MEDIUM", "Reflected XSS", "http://x/?q=1", "xss cross-site"),
        ]
        chains = build_chains(fs)
        assert chains
        assert chains[0]["source"] == "correlation"
        assert chains[0]["severity"] == "CRITICAL"