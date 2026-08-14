import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import json

from keris.modules.browser import _scan_dom
from keris.modules.ticketing import create_tickets
from keris.modules.watch import _diff, _load_report, watch


class TestBrowser:
    def test_dom_xss_sink_detected(self):
        findings = _scan_dom("function go() { el.innerHTML = userInput; }")
        assert any("innerHTML" in f["title"] for f in findings)
        assert findings[0]["source"] == "browser"

    def test_secret_leak_detected(self):
        findings = _scan_dom("const API_KEY = 'sk-abcdef1234567890'")
        assert any(f["severity"] == "HIGH" for f in findings)

    def test_clean_dom_no_findings(self):
        assert _scan_dom("<p>hello world</p>") == []

    def test_import_error_message(self):
        import importlib
        import pytest
        m = importlib.import_module("keris.modules.browser")
        try:
            m._import_playwright()
            pytest.skip("playwright installed")
        except ImportError as e:
            assert "playwright install chromium" in str(e)


class TestTicketing:
    def test_github_requires_config(self):
        import pytest
        with pytest.raises(ValueError):
            create_tickets([{"severity": "HIGH", "title": "x"}], kind="github", cfg={})

    def test_jira_requires_config(self):
        import pytest
        with pytest.raises(ValueError):
            create_tickets([{"severity": "HIGH", "title": "x"}], kind="jira", cfg={})

    def test_unknown_kind(self):
        import pytest
        with pytest.raises(ValueError):
            create_tickets([], kind="nope", cfg={})

    def test_filters_demoted_and_low(self, monkeypatch):
        calls = []
        monkeypatch.setattr("keris.modules.ticketing._github_issue",
                            lambda *a, **k: calls.append(a))
        findings = [
            {"severity": "CRITICAL", "title": "real critical", "endpoint": "/a",
             "detail": "", "evidence": "", "triage": {"status": "kept"}},
            {"severity": "HIGH", "title": "high one", "endpoint": "/b",
             "detail": "", "evidence": "", "triage": {"status": "kept"}},
            {"severity": "CRITICAL", "title": "fp", "endpoint": "/c",
             "detail": "", "evidence": "", "triage": {"status": "demoted"}},
            {"severity": "LOW", "title": "low", "endpoint": "/d",
             "detail": "", "evidence": "", "triage": {"status": "kept"}},
        ]
        created = create_tickets(findings, kind="github",
                                 cfg={"github": {"repo": "a/b", "token": "t"}})
        assert len(created) == 2
        assert "fp" not in created
        assert "low" not in created


class TestWatch:
    def test_load_report(self, tmp_path):
        p = tmp_path / "r.json"
        p.write_text(json.dumps({"findings": [{"title": "a"}]}), encoding="utf-8")
        assert _load_report(str(p)) == [{"title": "a"}]
        assert _load_report(str(tmp_path / "missing.json")) == []

    def test_diff(self):
        old = [{"endpoint": "/a", "title": "A"}]
        new = [{"endpoint": "/a", "title": "A"}, {"endpoint": "/b", "title": "B"}]
        d = _diff(old, new)
        assert len(d["new"]) == 1 and d["new"][0]["endpoint"] == "/b"
        assert len(d["persisting"]) == 1
        assert len(d["fixed"]) == 0

    def test_watch_first_cycle_no_previous(self, tmp_path):
        calls = []
        def run_scan(target, out):
            calls.append(target)
            with open(out, "w", encoding="utf-8") as f:
                json.dump({"findings": [{"severity": "CRITICAL", "title": "x",
                                         "endpoint": "/", "detail": "", "evidence": ""}]}, f)
            return out
        state = tmp_path / "state"
        cycle = watch("http://t/", str(state), run_scan)
        assert cycle["summary"]["new"] == 1
        assert cycle["summary"]["alertable_new"] == 1
        assert len(calls) == 1

    def test_watch_two_cycles_diff(self, tmp_path):
        payloads = [
            [{"severity": "HIGH", "title": "x", "endpoint": "/", "detail": "", "evidence": ""}],
            [{"severity": "HIGH", "title": "x", "endpoint": "/", "detail": "", "evidence": ""},
             {"severity": "CRITICAL", "title": "y", "endpoint": "/y", "detail": "", "evidence": ""}],
        ]
        def run_scan(target, out):
            with open(out, "w", encoding="utf-8") as f:
                json.dump({"findings": payloads.pop(0)}, f)
            return out
        state = tmp_path / "state"
        c1 = watch("http://t/", str(state), run_scan)
        c2 = watch("http://t/", str(state), run_scan)
        assert c1["summary"]["new"] == 1
        assert c2["summary"]["new"] == 1      # y is new
        assert c2["summary"]["persisting"] == 1  # x persists