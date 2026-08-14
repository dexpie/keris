"""Minimal terminal UI (TUI) for scanning with live progress.

Pure-stdlib ANSI rendering (no curses dependency), works on Windows Terminal
and modern Linux/macOS terminals. Clears the screen, renders a live dashboard
of the scan, then prints the findings table.
"""

import subprocess
import sys
import time
from datetime import datetime
from typing import Dict, List, Optional

_CLEAR = "\x1b[2J\x1b[H"
_UL = "\x1b[1m"      # bold
_RESET = "\x1b[0m"
_BRASS = "\x1b[33m"  # yellow-ish for accents
_RED = "\x1b[31m"
_GREEN = "\x1b[32m"

STAGES = [("PASSIVE RECON", 8), ("AUTO LOGIN", 12), ("RECON", 20),
          ("DISCOVERY", 40), ("SCANNER", 75), ("PLUGINS", 88)]


def _guess_stage(line: str):
    up = line.upper()
    if "===" in up:
        for name, pct in STAGES:
            if name in up:
                return name, pct
    return None


def _sev_color(sev: str) -> str:
    return {"CRITICAL": _RED, "HIGH": _RED, "MEDIUM": _BRASS}.get(sev.upper(), _RESET)


def _render(stage: str, pct: float, elapsed: float, log: List[str]) -> str:
    bar_w = 40
    filled = int(bar_w * pct / 100)
    bar = "█" * filled + "░" * (bar_w - filled)
    parts = [_CLEAR]
    parts.append(f"{_BRASS}  ▄▄▄▄▄  KERIS {_RESET}{_UL}terminal scan{_RESET}  {datetime.now().strftime('%H:%M:%S')}\n")
    parts.append(f"  {_BRASS}▶{_RESET} {stage}  {pct:5.1f}%   [{bar}]  {elapsed:.0f}s\n")
    parts.append("  " + "─" * 60 + "\n")
    body = log[-12:]
    for line in body:
        parts.append(f"  {line}\n")
    return "".join(parts)


def run_tui(target: str, scan_cmd: List[str]) -> int:
    """Runs scan_cmd with live ANSI dashboard. Returns process return code."""
    proc = subprocess.Popen(
        scan_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, encoding="utf-8", errors="replace",
    )
    stage, pct = "MENYIAPKAN", 0.0
    started = time.time()
    log: List[str] = []
    for raw in proc.stdout:
        line = raw.rstrip()
        if line.strip():
            log.append(line)
            g = _guess_stage(line)
            if g:
                stage, pct = g
    elapsed = time.time() - started
    sys.stdout.write(_render(stage, 100.0, elapsed, log + ["[selesai]"]))
    sys.stdout.flush()
    rc = proc.wait()
    return rc