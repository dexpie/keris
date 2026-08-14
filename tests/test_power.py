import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from keris.modules.correlation import build_chains, _tag_finding
from keris.modules.triage import (executive_summary, recommendation_for,
                                  _rule_based_triage, triage_findings)


def _f(sev, title, endpoint="/", detail="", evidence=""):
    return {"severity": sev, "title": title, "endpoint": endpoint,
            "detail": detail, "evidence": evidence}


class TestCorrelation:
    def test_chain_cache_poison_xss(self):
        findings = [
            _f("HIGH", "Web cache poisoning", "/landing", "X-Forwarded-Host direfleksikan", "Age: 0"),
            _f("MEDIUM", "Reflected XSS", "/search?q=", "Input direfleksikan", "<script>"),
        ]
        chains = build_chains(findings)
        assert any(c["title"] == "Cache poisoning + reflected XSS" for c in chains)
        assert chains[0]["severity"] == "CRITICAL"
        assert chains[0]["source"] == "correlation"

    def test_chain_requires_both(self):
        findings = [_f("HIGH", "Web cache poisoning", "/landing")]
        assert build_chains(findings) == []

    def test_tagging(self):
        assert "xss" in _tag_finding(_f("LOW", "Reflected XSS detected"))
        assert "cache-poison" in _tag_finding(_f("LOW", "cache poisoning", "/x"))
        assert "cors" in _tag_finding(_f("LOW", "CORS misconfig", "/api"))

    def test_no_findings(self):
        assert build_chains([]) == []


class TestTriage:
    def test_rule_based_demote_demo(self):
        f = _f("HIGH", "Demo endpoint exposed", "/sample")
        v = _rule_based_triage(f)
        assert v["status"] == "demoted"

    def test_rule_based_keep(self):
        f = _f("HIGH", "SQL injection", "/search")
        v = _rule_based_triage(f)
        assert v["status"] == "kept"

    def test_triage_no_llm_key(self, monkeypatch):
        monkeypatch.delenv("KERIS_LLM_API_KEY", raising=False)
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        findings = [_f("CRITICAL", "SQL injection", "/search")]
        annotated, raw = triage_findings(findings, {})
        assert raw is None
        assert annotated[0]["triage"]["status"] in ("kept", "demoted")

    def test_executive_summary(self):
        findings = [_f("CRITICAL", "Auth bypass", "/admin"),
                    _f("HIGH", "XSS", "/search")]
        s = executive_summary(findings, "http://x.test/")
        assert "2 temuan" in s or "2 temuan asli" in s
        assert "CRITICAL" in s

    def test_recommendation(self):
        assert "parameterized" in recommendation_for("SQL injection detected").lower()
        assert recommendation_for("random thing") != ""