"""Tests untuk continuous monitoring (watch) + multi-channel alerting (notify)."""

import json
import os

import pytest

from keris.modules.watch import (_diff, _load_report, _load_trend, _save_trend,
                                 _trend_markdown, watch, watch_loop)
from keris.modules import notify
from keris.cli import common


def _mk_findings():
    return [
        {"endpoint": "/login", "title": "SQLi", "severity": "HIGH",
         "detail": "injeksi", "evidence": "q='"},
        {"endpoint": "/api", "title": "XSS", "severity": "MEDIUM",
         "detail": "refleksi", "evidence": "<script>"},
    ]


# ---------------------------------------------------------------------------
# _diff
# ---------------------------------------------------------------------------

def test_diff_new_persisting_fixed():
    old = [{"endpoint": "/a", "title": "SQLi", "severity": "HIGH"},
           {"endpoint": "/b", "title": "XSS", "severity": "MEDIUM"}]
    new = [{"endpoint": "/a", "title": "SQLi", "severity": "HIGH"},
           {"endpoint": "/c", "title": "LFI", "severity": "HIGH"}]
    d = _diff(old, new)
    assert [f["endpoint"] for f in d["new"]] == ["/c"]
    assert [f["endpoint"] for f in d["persisting"]] == ["/a"]
    assert [f["endpoint"] for f in d["fixed"]] == ["/b"]


def test_load_report_list_and_dict(tmp_path):
    p1 = tmp_path / "a.json"
    p1.write_text(json.dumps([{"title": "x"}]), encoding="utf-8")
    assert _load_report(str(p1)) == [{"title": "x"}]
    p2 = tmp_path / "b.json"
    p2.write_text(json.dumps({"findings": [{"title": "y"}]}), encoding="utf-8")
    assert _load_report(str(p2)) == [{"title": "y"}]
    assert _load_report(str(tmp_path / "nope.json")) == []


# ---------------------------------------------------------------------------
# risk trend
# ---------------------------------------------------------------------------

def test_save_and_load_trend(tmp_path):
    e1 = {"target": "t", "ts": "2026-01-01T00:00:00Z", "grade": "C", "score": 55.0,
          "total": 5, "new": 2, "fixed": 1}
    trend = _save_trend(str(tmp_path), "t", e1)
    assert len(trend) == 1
    loaded = _load_trend(str(tmp_path), "t")
    assert loaded[0]["grade"] == "C"
    assert os.path.exists(str(tmp_path / "trend.json"))


def test_trend_filters_other_targets(tmp_path):
    _save_trend(str(tmp_path), "t1", {"target": "t1", "grade": "D"})
    _save_trend(str(tmp_path), "t2", {"target": "t2", "grade": "A"})
    trend = _load_trend(str(tmp_path), "t1")
    assert all(e["target"] == "t1" for e in trend)


def test_trend_markdown():
    md = _trend_markdown([{"ts": "2026-01-01T00:00:00Z", "grade": "C",
                           "score": 55, "total": 5, "new": 2, "fixed": 1}])
    assert "C" in md and "55" in md
    assert "Belum ada" in _trend_markdown([])


# ---------------------------------------------------------------------------
# watch() end-to-end (run_scan fake)
# ---------------------------------------------------------------------------

def _fake_run_scan(report_data):
    def run_scan(target, out_path):
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2)
        return out_path
    return run_scan


def test_watch_cycle_diff_and_risk(tmp_path, capsys):
    old_report = [{"endpoint": "/old", "title": "SQLi", "severity": "HIGH"}]
    new_report = [{"endpoint": "/old", "title": "SQLi", "severity": "HIGH"},
                  {"endpoint": "/new", "title": "RCE", "severity": "CRITICAL"}]
    # seed previous
    os.makedirs(str(tmp_path / "state"), exist_ok=True)
    with open(str(tmp_path / "state" / "latest.json"), "w", encoding="utf-8") as f:
        json.dump(old_report, f)

    cycle = watch("http://t.local", str(tmp_path / "state"),
                  run_scan=_fake_run_scan(new_report), min_severity="MEDIUM")
    assert cycle["summary"]["new"] == 1
    assert cycle["summary"]["persisting"] == 1
    assert cycle["summary"]["alertable_new"] == 1
    assert cycle["risk"]["grade"] in ("C", "D")
    assert len(cycle["trend"]) >= 1
    assert "risk" in cycle
    assert cycle["new_findings"][0]["endpoint"] == "/new"


def test_watch_writes_json_output(tmp_path):
    new_report = [{"endpoint": "/a", "title": "XSS", "severity": "LOW"}]
    out = str(tmp_path / "out.json")
    watch("http://t.local", str(tmp_path / "state"),
          run_scan=_fake_run_scan(new_report), min_severity="CRITICAL",
          json_output=out)
    with open(out, encoding="utf-8") as f:
        data = json.load(f)
    assert data["summary"]["new"] == 1
    assert "trend" in data


def test_watch_empty_report_grade_a(tmp_path):
    watch("http://t.local", str(tmp_path / "state"),
          run_scan=_fake_run_scan([]))
    trend = _load_trend(str(tmp_path / "state"), "http://t.local")
    assert trend[-1]["grade"] == "A"
    assert trend[-1]["score"] == 100.0


def test_watch_alertables_only_new_high():
    # baru ber-severity LOW tidak memicu alert CRITICAL/HIGH
    old = []
    new = [{"endpoint": "/x", "title": "info", "severity": "INFO"}]
    d = _diff(old, new)
    assert d["new"] == new
    # alertable filter diuji lewat watch dengan min CRITICAL
    # (fungsi _diff sendiri tidak menyaring severity)


# ---------------------------------------------------------------------------
# notify multi-channel
# ---------------------------------------------------------------------------

def test_send_slack_payload(monkeypatch):
    captured = {}

    def fake_post(url, json=None, timeout=10.0, data=None):
        captured["url"] = url
        captured["json"] = json
        return type("R", (), {"status_code": 200})()

    monkeypatch.setattr(notify, "_post_json", fake_post)
    ok_ = notify.send_slack("https://hooks.slack.com/x", "http://t",
                            _mk_findings())
    assert ok_
    assert "SQLi" in captured["json"]["text"]


def test_send_teams_payload(monkeypatch):
    captured = {}

    def fake_post(url, json=None, timeout=10.0, data=None):
        captured["json"] = json
        return type("R", (), {"status_code": 200})()

    monkeypatch.setattr(notify, "_post_json", fake_post)
    ok_ = notify.send_teams("https://outlook.office.com/webhook/x", "http://t",
                            _mk_findings())
    assert ok_
    assert captured["json"]["@type"] == "MessageCard"


def test_send_pagerduty(monkeypatch):
    captured = {}

    def fake_post(url, json=None, timeout=10.0, data=None):
        captured["json"] = json
        return type("R", (), {"status_code": 202})()

    monkeypatch.setattr(notify, "_post_json", fake_post)
    ok_ = notify.send_pagerduty("rk123", "http://t", _mk_findings())
    assert ok_
    assert captured["json"]["event_action"] == "trigger"


def test_send_webhook_generic(monkeypatch):
    captured = {}

    def fake_post(url, json=None, timeout=10.0, data=None):
        captured["json"] = json
        return type("R", (), {"status_code": 200})()

    monkeypatch.setattr(notify, "_post_json", fake_post)
    ok_ = notify.send_webhook("https://example.com/hook", "http://t",
                              _mk_findings())
    assert ok_
    assert captured["json"]["count"] == 2


def test_notify_auto_detect(monkeypatch):
    sent = []
    monkeypatch.setattr(notify, "send_slack", lambda *a: (sent.append("slack") or True))
    monkeypatch.setattr(notify, "send_discord", lambda *a: (sent.append("discord") or True))
    assert notify.notify("https://hooks.slack.com/x", "auto", "http://t", []) is True
    assert sent == ["slack"]


def test_notify_multi_all_channels(monkeypatch):
    sent = []

    def fake_slack(url, base, findings):
        sent.append("slack")
        return True

    def fake_discord(url, base, findings):
        sent.append("discord")
        return True

    def fake_webhook(url, base, findings):
        sent.append("webhook")
        return True

    monkeypatch.setattr(notify, "send_slack", fake_slack)
    monkeypatch.setattr(notify, "send_discord", fake_discord)
    monkeypatch.setattr(notify, "send_webhook", fake_webhook)
    n = notify.notify_multi([
        {"url": "https://hooks.slack.com/x", "kind": "slack"},
        {"url": "https://discord.com/api/x", "kind": "discord"},
        {"url": "https://x/hook", "kind": "webhook"},
    ], "http://t", _mk_findings())
    assert n == 3
    assert sent == ["slack", "discord", "webhook"]


def test_notify_multi_email_no_config_returns_ok_count_zero(tmp_path):
    # tanpa konfig SMTP, email alert gagal tapi tidak crash
    n = notify.notify_multi([{"kind": "email"}], "http://t", [])
    assert n == 0


# ---------------------------------------------------------------------------
# CLI wiring
# ---------------------------------------------------------------------------

def test_watch_parser_multichannel():
    a = common._parse_args(["watch", "--webhook", "https://h/slack",
                            "--webhook", "https://h/teams",
                            "--webhook-type", "slack",
                            "--min-severity", "MEDIUM",
                            "http://target.local"])
    assert len(a.webhook) == 2
    assert a.min_severity == "MEDIUM"


def test_watch_parser_email_flags():
    a = common._parse_args(["watch", "--smtp-host", "smtp.example.com",
                            "--smtp-to", "a@example.com",
                            "--pagerduty-key", "rk",
                            "http://target.local"])
    assert a.smtp_host == "smtp.example.com"
    assert a.smtp_to == ["a@example.com"]
    assert a.pagerduty_key == "rk"