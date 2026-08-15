"""Test Standard Finding Schema, Confidence engine, dan SARIF output (v0.12.0)."""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))


def _sample():
    return {
        "severity": "HIGH",
        "title": "SQL Injection terkonfirmasi pada parameter id",
        "endpoint": "http://x/search?id=1",
        "detail": "Payload menghasilkan error database",
        "evidence": "MySQL error: syntax near '1' at line 1 (status_code 500)",
        "cwe": "CWE-89",
        "source": "exploit",
    }


class TestFindingSchema:
    def test_normalize_standard_fields(self):
        from keris.finding import normalize_finding
        f = normalize_finding(_sample())
        assert f["id"]
        assert f["schema_version"] == "1.0.0"
        assert f["severity"] == "HIGH"
        assert f["confidence"] >= 0.0
        assert set(("severity", "title", "endpoint", "detail", "evidence")) <= set(f)

    def test_invalid_severity_normalized(self):
        from keris.finding import normalize_finding
        f = normalize_finding({"severity": "weird", "title": "x", "endpoint": "e",
                               "detail": "d", "evidence": ""})
        assert f["severity"] == "INFO"

    def test_fingerprint_deterministic(self):
        from keris.finding import normalize_finding
        a = normalize_finding(_sample())
        b = normalize_finding(_sample())
        assert a["id"] == b["id"]

    def test_summary(self):
        from keris.finding import normalize_findings, summary
        fs = normalize_findings([_sample(), {"severity": "LOW", "title": "t", "endpoint": "e",
                                             "detail": "d", "evidence": ""}])
        s = summary(fs)
        assert s["total"] == 2
        assert s["by_severity"]["HIGH"] == 1
        assert s["by_severity"]["LOW"] == 1


class TestConfidenceEngine:
    def test_source_high_base(self):
        from keris.confidence import score_finding
        f = score_finding({"source": "exploit", "severity": "HIGH", "title": "RCE",
                           "endpoint": "e", "detail": "d", "evidence": "executed cmd"})
        assert f["confidence"] >= 0.7
        assert f["confidence_label"] in ("high", "confirmed")

    def test_weak_signal_lower(self):
        from keris.confidence import score_finding
        low = score_finding({"source": "fuzz", "severity": "MEDIUM",
                             "title": "Sinyal refleksi potensial", "endpoint": "e",
                             "detail": "mungkin", "evidence": ""})
        assert low["confidence"] < 0.4
        assert low["confidence_label"] == "low"

    def test_default_without_source(self):
        from keris.confidence import score_finding
        f = score_finding({"severity": "INFO", "title": "header", "endpoint": "e",
                           "detail": "d", "evidence": ""})
        assert 0.05 <= f["confidence"] <= 0.99

    def test_aggregate(self):
        from keris.confidence import assign_confidence, aggregate_confidence
        fs = assign_confidence([
            {"source": "exploit", "title": "RCE", "endpoint": "e", "detail": "d", "evidence": "x"},
            {"source": "fuzz", "title": "potensial refleksi", "endpoint": "e", "detail": "mungkin", "evidence": ""},
        ])
        agg = aggregate_confidence(fs)
        assert agg["avg"] > 0.4
        assert agg["verify_first"], "harus ada temuan low confidence"
        assert agg["verify_first"][0]["confidence"] < 0.4


class TestSarif:
    def test_build_sarif_structure(self):
        from keris.report_sarif import build_sarif
        doc = build_sarif([_sample()], "http://x")
        assert doc["version"] == "2.1.0"
        run = doc["runs"][0]
        assert run["tool"]["driver"]["name"] == "Keris"
        assert len(run["results"]) == 1
        res = run["results"][0]
        assert res["level"] == "error"  # HIGH -> error
        assert res["properties"]["severity"] == "HIGH"
        assert res["properties"]["confidence"] >= 0.5
        assert res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "http://x/search?id=1"

    def test_severity_mapping(self):
        from keris.report_sarif import build_sarif
        cases = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning",
                 "LOW": "note", "INFO": "none"}
        for sev, level in cases.items():
            doc = build_sarif([{"severity": sev, "title": "t", "endpoint": "e",
                                "detail": "d", "evidence": ""}], "http://x")
            assert doc["runs"][0]["results"][0]["level"] == level, sev

    def test_cwe_rule_id(self):
        from keris.report_sarif import build_sarif
        doc = build_sarif([_sample()], "http://x")
        assert doc["runs"][0]["results"][0]["ruleId"] == "CWE-89"

    def test_write_sarif(self):
        import tempfile
        from keris.report_sarif import write_sarif
        with tempfile.NamedTemporaryFile(suffix=".sarif", delete=False) as tmp:
            path = tmp.name
        try:
            write_sarif([_sample()], "http://x", path)
            with open(path, "r", encoding="utf-8") as f:
                doc = json.load(f)
            assert doc["version"] == "2.1.0"
        finally:
            os.unlink(path)