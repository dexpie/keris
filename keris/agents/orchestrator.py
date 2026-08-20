"""PentestOrchestrator: koordinasi multi-agent untuk satu misi pentest.

Fase (goal=full-pentest): recon -> scanner -> validator -> exploiter -> reporter
Fase (goal=recon):      recon -> reporter
Fase (goal=exploit):    (pakai state tersimpan) validator -> exploiter -> reporter

Mendukung:
- Eksekusi paralel (ThreadPoolExecutor) pada fase yang independen.
- Resume dari file state (agent-state.json).
- Injeksi hooks untuk testing tanpa network.
"""

import json
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional

from keris.agents.base import BaseAgent
from keris.agents.exploiter_agent import ExploiterAgent
from keris.agents.memory import SharedMemory
from keris.agents.recon_agent import ReconAgent
from keris.agents.reporter_agent import ReporterAgent
from keris.agents.scanner_agent import ScannerAgent
from keris.agents.validator_agent import ValidatorAgent
from keris.core.logger import debug, info, ok, warn

STATE_FILE = "agent-state.json"
FINDINGS_FILE = "agent-findings.json"
REPORT_FILE = "agent-report.md"

GOALS = ("full-pentest", "recon", "exploit")


def _make_agent(agent_cls: type, memory: SharedMemory, hooks: Dict[str, Any],
                authorized: bool, verbose: bool) -> BaseAgent:
    return agent_cls(memory=memory, hooks=hooks, authorized=authorized, verbose=verbose)


class PentestOrchestrator:
    """Mengatur urutan & paralelisme agent pada satu target."""

    def __init__(self, target: str, goal: str = "full-pentest",
                 authorized: bool = False, verbose: bool = False,
hooks: Optional[Dict[str, Any]] = None,
                 state_file: str = STATE_FILE,
                 report_file: str = REPORT_FILE,
                 findings_file: str = FINDINGS_FILE,
                 max_workers: int = 2):
        if goal not in GOALS:
            raise ValueError(f"goal harus salah satu dari {GOALS}")
        self.goal = goal
        self.authorized = authorized
        self.verbose = verbose
        self.hooks = hooks or {}
        self.state_file = state_file
        self.report_file = report_file
        self.findings_file = findings_file
        self.max_workers = max_workers
        self.memory = SharedMemory(target=target, goal=goal)
        self.memory.set("started", int(time.time()))

    # -- pembangunan agent --------------------------------------------------
    def _build(self, cls: type) -> BaseAgent:
        return _make_agent(cls, self.memory, self.hooks, self.authorized,
                           self.verbose)

    # -- fase tunggal -------------------------------------------------------
    def _run_sequential(self, cls: type) -> Dict[str, Any]:
        agent = self._build(cls)
        info(f"[orchestrator] fase {cls.__name__}")
        return agent.run()

    # -- fase paralel -------------------------------------------------------
    def _run_parallel(self, classes: List[type]) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {pool.submit(self._run_sequential, c): c for c in classes}
            for fut in as_completed(futures):
                try:
                    results.append(fut.result())
                except Exception as e:  # noqa: BLE001
                    warn(f"fase gagal: {e}")
        return results

    # -- pipeline utama -----------------------------------------------------
    def run(self, resume: bool = False) -> Dict[str, Any]:
        if resume and os.path.exists(self.state_file):
            self.memory.load(self.state_file)
            info("Resume dari state file")
        else:
            self.memory = SharedMemory(target=self.memory.get("target", ""),
                                       goal=self.goal)
            self.memory.set("started", int(time.time()))

        if self.goal == "recon":
            self._run_sequential(ReconAgent)
        elif self.goal == "exploit":
            # state diharapkan berisi findings; isi dari findings file jika ada
            if not self.memory.get("findings") and os.path.exists(self.findings_file):
                self._load_findings_file()
            self._run_sequential(ValidatorAgent)
            if self.authorized:
                self._run_sequential(ExploiterAgent)
        else:  # full-pentest
            self._run_sequential(ReconAgent)
            self._run_sequential(ScannerAgent)
            self._run_sequential(ValidatorAgent)
            if self.authorized:
                self._run_sequential(ExploiterAgent)

        # reporter selalu terakhir
        rep = self._build(ReporterAgent)
        rep.hooks["report_path"] = self.report_file
        rep.hooks["findings_path"] = self.findings_file
        rep.run()

        self.memory.set("done", True)
        self.memory.save(self.state_file)
        return self.summary()

    def _load_findings_file(self) -> None:
        try:
            with open(self.findings_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                self.memory.set("findings", data.get("findings", []))
        except (OSError, json.JSONDecodeError):
            warn("Gagal memuat findings file")

    def summary(self) -> Dict[str, Any]:
        findings = self.memory.get("validated", [])
        exploited = self.memory.get("exploited", [])
        return {
            "target": self.memory.get("target", ""),
            "goal": self.goal,
            "authorized": self.authorized,
            "status": self.memory.get("status", {}),
            "recon": self.memory.get("recon", {}),
            "endpoints": len(self.memory.get("endpoints", [])),
            "total_findings": len(self.memory.get("findings", [])),
            "validated_findings": len(findings),
            "exploited_findings": len(exploited),
            "state_file": self.state_file,
            "report_file": self.report_file,
            "findings_file": self.findings_file,
        }


def run_agent_squad(target: str, goal: str = "full-pentest",
                    authorized: bool = False, verbose: bool = False,
                    resume: bool = False, hooks: Optional[Dict[str, Any]] = None,
                    state_file: str = STATE_FILE,
                    report_file: str = REPORT_FILE,
                    findings_file: str = FINDINGS_FILE,
                    max_workers: int = 2) -> Dict[str, Any]:
    """Jalankan misi multi-agent; return ringkasan dict."""
    orch = PentestOrchestrator(target=target, goal=goal, authorized=authorized,
                               verbose=verbose, hooks=hooks,
                               state_file=state_file, report_file=report_file,
                               findings_file=findings_file, max_workers=max_workers)
    return orch.run(resume=resume)