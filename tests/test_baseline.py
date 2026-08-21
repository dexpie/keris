"""Tests untuk baseline FP management (keris/modules/baseline.py)."""

import json

from keris.modules import baseline as bl


def _finding(sev, title, endpoint, detail="d", evidence="e"):
    return {"severity": sev, "title": title, "endpoint": endpoint,
            "detail": detail, "evidence": evidence}


def test_baseline_key_stable_and_evidence_independent():
    a = _finding("HIGH", "SQLi", "http://x.test/a?id=1", detail="bool", evidence="AAAA")
    b = _finding("HIGH", "SQLi", "http://x.test/a?id=1", detail="bool", evidence="BBBB")
    assert bl.baseline_key(a) == bl.baseline_key(b)


def test_baseline_key_differs_for_different_title():
    a = _finding("HIGH", "SQLi", "http://x.test/")
    b = _finding("HIGH", "XSS", "http://x.test/")
    assert bl.baseline_key(a) != bl.baseline_key(b)


def test_apply_baseline_marks_known_only(tmp_path):
    f1 = _finding("HIGH", "SQLi", "http://x.test/a")
    f2 = _finding("MEDIUM", "CSP", "http://x.test/")
    payload = {"version": 1, "keys": [bl.baseline_key(f1)]}
    p = tmp_path / "b.json"
    p.write_text(json.dumps(payload), encoding="utf-8")
    keys = bl.load_baseline(str(p))
    out, marked = bl.apply_baseline([f1, f2], keys)
    assert marked == 1
    assert out[0]["baseline"] is True
    assert out[1]["baseline"] is False


def test_create_from_scan_min_severity(tmp_path):
    findings = [
        _finding("LOW", "L", "http://x/"),
        _finding("HIGH", "H", "http://x/"),
    ]
    scan = tmp_path / "scan.json"
    scan.write_text(json.dumps({"findings": findings}), encoding="utf-8")
    full = bl.create_from_scan(str(scan))
    assert full["count"] == 2
    high_only = bl.create_from_scan(str(scan), min_severity="HIGH")
    assert high_only["count"] == 1


def test_load_baseline_plain_list(tmp_path):
    p = tmp_path / "b.json"
    p.write_text(json.dumps(["aaa", "bbb"]), encoding="utf-8")
    assert bl.load_baseline(str(p)) == {"aaa", "bbb"}
