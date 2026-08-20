"""Tests untuk Multi-Agent Pentesting Framework (keris/agents/)."""

import json
import os

import pytest

from keris.agents.memory import SharedMemory
from keris.agents.recon_agent import ReconAgent
from keris.agents.scanner_agent import ScannerAgent
from keris.agents.validator_agent import ValidatorAgent
from keris.agents.exploiter_agent import ExploiterAgent
from keris.agents.reporter_agent import ReporterAgent
from keris.agents.orchestrator import PentestOrchestrator, run_agent_squad

TARGET = "http://127.0.0.1:8099"


# ---------------------------------------------------------------------------
# SharedMemory
# ---------------------------------------------------------------------------

def test_memory_set_get():
    m = SharedMemory(target=TARGET, goal="recon")
    m.set("x", 1)
    assert m.get("x") == 1
    assert m.get("nope", "d") == "d"


def test_memory_append_extend_note_status():
    m = SharedMemory()
    m.append("endpoints", "a")
    m.extend("endpoints", ["b", "c"])
    assert m.get("endpoints") == ["a", "b", "c"]
    m.note("recon", "mulai")
    m.status("recon", "running")
    assert m.get("notes")[0]["agent"] == "recon"
    assert m.get("status")["recon"] == "running"


def test_memory_save_load(tmp_path):
    p = str(tmp_path / "state.json")
    m = SharedMemory(target=TARGET)
    m.set("findings", [{"title": "x"}])
    m.save(p)
    m2 = SharedMemory()
    m2.load(p)
    assert m2.get("target") == TARGET
    assert m2.get("findings") == [{"title": "x"}]


def test_memory_to_dict_serializable():
    m = SharedMemory()
    m.set("weird", object())
    d = m.to_dict()
    assert isinstance(d, dict)


# ---------------------------------------------------------------------------
# ReconAgent
# ---------------------------------------------------------------------------

def test_recon_hooks():
    m = SharedMemory(target=TARGET)
    a = ReconAgent(memory=m, hooks={
        "fingerprint": lambda t: {"host": "127.0.0.1", "stack": ["Flask"]},
        "discover": lambda t: ["http://127.0.0.1:8099/", "http://127.0.0.1:8099/api"],
    })
    res = a.run()
    assert res["agent"] == "recon"
    assert m.get("recon")["stack"] == ["Flask"]
    assert len(m.get("endpoints")) == 2
    assert m.get("status")["recon"] == "done"


def test_recon_dedup_endpoints():
    m = SharedMemory(target=TARGET)
    m.set("endpoints", ["http://127.0.0.1:8099/"])
    a = ReconAgent(memory=m, hooks={
        "fingerprint": lambda t: {},
        "discover": lambda t: ["http://127.0.0.1:8099/", "http://127.0.0.1:8099/x"],
    })
    a.run()
    assert len(m.get("endpoints")) == 2


def test_recon_no_network_default():
    m = SharedMemory(target=TARGET)
    a = ReconAgent(memory=m)
    res = a.run()
    assert res["endpoints"] == []
    assert m.get("recon", {}).get("host") == "127.0.0.1:8099"


# ---------------------------------------------------------------------------
# ScannerAgent
# ---------------------------------------------------------------------------

def test_scanner_uses_hook():
    m = SharedMemory(target=TARGET)
    m.set("endpoints", ["/a", "/b"])
    a = ScannerAgent(memory=m, hooks={
        "scan_endpoint": lambda ep: [{"title": f"vuln {ep}", "endpoint": ep,
                                      "severity": "HIGH"}],
    })
    res = a.run()
    assert len(res["findings"]) == 2
    assert len(m.get("findings")) == 2


def test_scanner_default_no_network():
    m = SharedMemory(target=TARGET)
    m.set("endpoints", ["/a"])
    a = ScannerAgent(memory=m)
    assert a.run()["findings"] == []


# ---------------------------------------------------------------------------
# ValidatorAgent
# ---------------------------------------------------------------------------

def test_validator_dedupe_and_sort():
    m = SharedMemory(target=TARGET)
    m.set("findings", [
        {"title": "SQLi", "endpoint": "/x", "severity": "high"},
        {"title": "SQLi", "endpoint": "/x", "severity": "high"},  # duplikat
        {"title": "Info leak", "endpoint": "/y", "severity": "low"},
        {"title": "XSS", "endpoint": "/z", "severity": "critical"},
    ])
    a = ValidatorAgent(memory=m)
    res = a.run()
    assert res["input"] == 4
    assert res["output"] == 3
    sevs = [f["severity"] for f in m.get("validated")]
    assert sevs[0] == "CRITICAL"
    assert "HIGH" in sevs
    assert all(f.get("confidence") for f in m.get("validated"))


def test_validator_verify_hook():
    m = SharedMemory(target=TARGET)
    m.set("findings", [{"title": "t", "endpoint": "/x", "severity": "low"}])
    a = ValidatorAgent(memory=m, hooks={
        "verify": lambda f: dict(f, severity="HIGH", confidence=0.5),
    })
    a.run()
    assert m.get("validated")[0]["severity"] == "HIGH"
    assert m.get("validated")[0]["confidence"] == 0.5


def test_validator_skips_non_dict():
    m = SharedMemory(target=TARGET)
    m.set("findings", [{"title": "ok", "endpoint": "/x", "severity": "low"},
                       "not-a-dict"])
    a = ValidatorAgent(memory=m)
    a.run()
    assert len(m.get("validated")) == 1


# ---------------------------------------------------------------------------
# ExploiterAgent
# ---------------------------------------------------------------------------

def test_exploiter_requires_authorized():
    m = SharedMemory(target=TARGET)
    m.set("validated", [{"title": "x", "severity": "HIGH"}])
    a = ExploiterAgent(memory=m, authorized=False)
    res = a.run()
    assert res["skipped"] is True
    assert m.get("status")["exploiter"] == "skipped"


def test_exploiter_authorized_hook():
    m = SharedMemory(target=TARGET)
    m.set("validated", [{"title": "SQLi", "severity": "HIGH"}])
    a = ExploiterAgent(memory=m, authorized=True, hooks={
        "exploit": lambda fs: [dict(f, exploited=True) for f in fs],
    })
    res = a.run()
    assert len(res["exploited"]) == 1
    assert m.get("exploited")[0]["exploited"] is True


# ---------------------------------------------------------------------------
# ReporterAgent
# ---------------------------------------------------------------------------

def test_reporter_writes_files(tmp_path):
    m = SharedMemory(target=TARGET)
    m.set("validated", [{"title": "SQLi", "endpoint": "/x", "severity": "HIGH"}])
    m.set("recon", {"host": "127.0.0.1"})
    m.note("recon", "selesai")
    rp = str(tmp_path / "agent-report.md")
    fp = str(tmp_path / "agent-findings.json")
    a = ReporterAgent(memory=m, hooks={"report_path": rp, "findings_path": fp})
    a.run()
    assert os.path.exists(rp)
    assert os.path.exists(fp)
    with open(rp, "r", encoding="utf-8") as f:
        md = f.read()
    assert "Agent Report" in md
    assert "SQLi" in md
    with open(fp, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert data["findings"][0]["title"] == "SQLi"


def test_reporter_render_hook(tmp_path):
    m = SharedMemory(target=TARGET)
    m.set("validated", [])
    rp = str(tmp_path / "r.md")
    fp = str(tmp_path / "f.json")
    a = ReporterAgent(memory=m, hooks={
        "report_path": rp, "findings_path": fp,
        "render": lambda f, r, n: "CUSTOM REPORT",
    })
    a.run()
    with open(rp, "r", encoding="utf-8") as f:
        assert f.read() == "CUSTOM REPORT"


# ---------------------------------------------------------------------------
# Orchestrator / run_agent_squad
# ---------------------------------------------------------------------------

def test_orchestrator_recon_goal(tmp_path):
    hooks = {
        "fingerprint": lambda t: {"host": "127.0.0.1"},
        "discover": lambda t: [TARGET],
    }
    summary = run_agent_squad(
        TARGET, goal="recon", hooks=hooks,
        state_file=str(tmp_path / "agent-state.json"),
        report_file=str(tmp_path / "agent-report.md"),
        findings_file=str(tmp_path / "agent-findings.json"),
    )
    assert summary["goal"] == "recon"
    assert summary["endpoints"] == 1
    assert os.path.exists(str(tmp_path / "agent-report.md"))
    assert os.path.exists(str(tmp_path / "agent-state.json"))


def test_orchestrator_full_pentest(tmp_path):
    hooks = {
        "fingerprint": lambda t: {"host": "127.0.0.1"},
        "discover": lambda t: [TARGET],
        "scan_endpoint": lambda ep: [{"title": "SQLi", "endpoint": ep,
                                      "severity": "HIGH"}],
    }
    summary = run_agent_squad(
        TARGET, goal="full-pentest", hooks=hooks,
        state_file=str(tmp_path / "agent-state.json"),
        report_file=str(tmp_path / "agent-report.md"),
        findings_file=str(tmp_path / "agent-findings.json"),
    )
    assert summary["validated_findings"] == 1
    assert summary["exploited_findings"] == 0  # tanpa --authorized
    assert summary["status"]["validator"] == "done"


def test_orchestrator_full_pentest_authorized(tmp_path):
    hooks = {
        "fingerprint": lambda t: {},
        "discover": lambda t: [TARGET],
        "scan_endpoint": lambda ep: [{"title": "RCE", "endpoint": ep,
                                      "severity": "CRITICAL"}],
        "exploit": lambda fs: [dict(f, exploited=True) for f in fs],
    }
    summary = run_agent_squad(
        TARGET, goal="full-pentest", authorized=True, hooks=hooks,
        state_file=str(tmp_path / "agent-state.json"),
        report_file=str(tmp_path / "agent-report.md"),
        findings_file=str(tmp_path / "agent-findings.json"),
    )
    assert summary["validated_findings"] == 1
    assert summary["exploited_findings"] == 1


def test_orchestrator_exploit_goal_from_findings_file(tmp_path):
    fp = str(tmp_path / "agent-findings.json")
    with open(fp, "w", encoding="utf-8") as f:
        json.dump({"findings": [{"title": "SQLi", "endpoint": "/x",
                                 "severity": "HIGH"}]}, f)
    summary = run_agent_squad(
        TARGET, goal="exploit", authorized=True,
        hooks={"exploit": lambda fs: [dict(f, exploited=True) for f in fs]},
        state_file=str(tmp_path / "agent-state.json"),
        report_file=str(tmp_path / "agent-report.md"),
        findings_file=fp,
    )
    assert summary["exploited_findings"] == 1


def test_orchestrator_resume(tmp_path):
    hooks = {
        "fingerprint": lambda t: {"host": "127.0.0.1"},
        "discover": lambda t: [TARGET],
        "scan_endpoint": lambda ep: [{"title": "t", "endpoint": ep,
                                      "severity": "LOW"}],
    }
    state = str(tmp_path / "agent-state.json")
    run_agent_squad(TARGET, goal="full-pentest", hooks=hooks,
                    state_file=state,
                    report_file=str(tmp_path / "agent-report.md"),
                    findings_file=str(tmp_path / "agent-findings.json"))
    # resume harus tetap berjalan tanpa error
    summary = run_agent_squad(TARGET, goal="full-pentest", resume=True,
                              hooks=hooks, state_file=state,
                              report_file=str(tmp_path / "r2.md"),
                              findings_file=str(tmp_path / "f2.json"))
    assert summary["goal"] == "full-pentest"


def test_orchestrator_invalid_goal():
    with pytest.raises(ValueError):
        PentestOrchestrator(TARGET, goal="bogus")


def test_orchestrator_parallel_workers(tmp_path):
    hooks = {
        "fingerprint": lambda t: {},
        "discover": lambda t: [TARGET, TARGET + "/a", TARGET + "/b"],
        "scan_endpoint": lambda ep: [{"title": "x", "endpoint": ep,
                                      "severity": "LOW"}],
    }
    orch = PentestOrchestrator(TARGET, max_workers=3, hooks=hooks,
                               state_file=str(tmp_path / "s.json"),
                               report_file=str(tmp_path / "r.md"),
                               findings_file=str(tmp_path / "f.json"))
    summary = orch.run()
    assert summary["validated_findings"] == 3


def test_squad_summary_shape(tmp_path):
    summary = run_agent_squad(
        TARGET, goal="recon", hooks={"fingerprint": lambda t: {}, "discover": lambda t: []},
        state_file=str(tmp_path / "s.json"),
        report_file=str(tmp_path / "r.md"),
        findings_file=str(tmp_path / "f.json"),
    )
    for key in ("target", "goal", "status", "total_findings",
                "validated_findings", "exploited_findings"):
        assert key in summary