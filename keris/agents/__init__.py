"""Multi-Agent Pentesting Framework (v0.20.0).

Framework agent yang berkolaborasi pada satu misi pentest:

- **ReconAgent** - mengumpulkan intelijen target (DNS, header, stack, endpoint).
- **ScannerAgent** - memindai endpoint untuk kerentanan (SQLi, XSS, CORS, ...).
- **ExploiterAgent** - mengonfirmasi & mengeksploitasi temuan (wajib --authorized).
- **ValidatorAgent** - membersihkan, dedupe, dan menilai konfidensi temuan.
- **ReporterAgent** - menghasilkan agent-report.md, agent-findings.json, agent-state.json.
- **PentestOrchestrator** - menjalankan fase agent (paralel via ThreadPoolExecutor)
  dengan SharedMemory sebagai state bersama + resume dari checkpoint.

Zero dependency tambahan: hanya stdlib + modul keris yang sudah ada.
"""

from keris.agents.base import BaseAgent
from keris.agents.memory import SharedMemory
from keris.agents.orchestrator import PentestOrchestrator, run_agent_squad
from keris.agents.recon_agent import ReconAgent
from keris.agents.reporter_agent import ReporterAgent
from keris.agents.scanner_agent import ScannerAgent
from keris.agents.validator_agent import ValidatorAgent
from keris.agents.exploiter_agent import ExploiterAgent

__all__ = [
    "BaseAgent",
    "SharedMemory",
    "PentestOrchestrator",
    "run_agent_squad",
    "ReconAgent",
    "ScannerAgent",
    "ExploiterAgent",
    "ValidatorAgent",
    "ReporterAgent",
]