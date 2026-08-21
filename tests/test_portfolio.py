"""Tests untuk portfolio risk aggregation (keris/modules/portfolio.py)."""

import json

from keris.modules import portfolio as pf


def _scan(path, target, findings):
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"target": target, "findings": findings}, f)
    return path


def _f(sev, title, endpoint):
    return {"severity": sev, "title": title, "endpoint": endpoint,
            "detail": "d", "evidence": ""}


def test_build_portfolio_ranking(tmp_path):
    a = _scan(str(tmp_path / "a.json"), "http://a.test", [
        _f("CRITICAL", "RCE", "http://a.test/x"),
        _f("HIGH", "SQLi", "http://a.test/s"),
    ])
    b = _scan(str(tmp_path / "b.json"), "http://b.test", [
        _f("LOW", "Cookie flags", "http://b.test/"),
    ])
    agg = pf.build_portfolio([a, b])
    assert agg["num_targets"] == 2
    # target terburuk (skor terkecil) di urutan pertama
    assert agg["targets"][0]["target"] == "http://a.test"
    assert agg["targets"][0]["grade"] in ("C", "D", "F")
    assert agg["targets"][1]["grade"] in ("A", "B")
    # overall = gabungan semua temuan
    assert agg["overall"]["counts"]["CRITICAL"] == 1


def test_top_findings_dedup_and_order(tmp_path):
    a = _scan(str(tmp_path / "a.json"), "http://a.test", [
        _f("HIGH", "SQLi", "http://a.test/s"),
        _f("MEDIUM", "CSP", "http://a.test/"),
    ])
    b = _scan(str(tmp_path / "b.json"), "http://b.test", [
        _f("CRITICAL", "RCE", "http://b.test/x"),
        _f("HIGH", "SQLi", "http://a.test/s"),  # duplikat endpoint+title
    ])
    agg = pf.build_portfolio([a, b])
    top = agg["top_findings"]
    assert top[0]["title"] == "RCE"
    titles = [t["title"] for t in top]
    assert titles.count("SQLi") == 1


def test_common_issues_counts_across_targets(tmp_path):
    a = _scan(str(tmp_path / "a.json"), "http://a.test", [_f("LOW", "Cookie flags", "http://a.test/")])
    b = _scan(str(tmp_path / "b.json"), "http://b.test", [_f("LOW", "Cookie flags", "http://b.test/")])
    c = _scan(str(tmp_path / "c.json"), "http://c.test", [_f("LOW", "Other", "http://c.test/")])
    agg = pf.build_portfolio([a, b, c])
    common = dict(agg["common_issues"])
    assert common["Cookie flags"] == 2
    assert common["Other"] == 1


def test_render_markdown_contains_sections(tmp_path):
    a = _scan(str(tmp_path / "a.json"), "http://a.test", [_f("HIGH", "SQLi", "http://a.test/s")])
    agg = pf.build_portfolio([a])
    md = pf.render_markdown(agg)
    assert "# Portfolio Risk Report" in md
    assert "## Ringkasan per target" in md
    assert "## Temuan paling berat" in md
    assert "## Jenis masalah paling umum" in md
    assert "http://a.test" in md


def test_load_scan_multi_target_format(tmp_path):
    data = {"targets": ["http://x.test"], "results": [
        {"findings": [_f("HIGH", "SQLi", "http://x.test/s")]}]}
    p = tmp_path / "multi.json"
    p.write_text(json.dumps(data), encoding="utf-8")
    s = pf._load_scan(str(p))
    assert s["target"] == "http://x.test"
    assert len(s["findings"]) == 1