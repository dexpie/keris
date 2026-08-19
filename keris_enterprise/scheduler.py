"""Scheduler cron-based untuk keris-enterprise.

Menjalankan `keris scan <target> --json-output ... --quiet` pada jadwal
project. Format jadwal sederhana: `hourly`, `daily`, `weekly`, atau
`*/5m` (interval menit). Berjalan di thread background (daemon).
"""

import os
import re
import subprocess
import sys
import threading
import time
from typing import Callable, Dict, List, Optional

from keris.core.logger import info, ok, warn
from keris_enterprise.projects import ProjectStore


def parse_schedule(schedule: str) -> Optional[float]:
    """Terjemahkan jadwal menjadi interval detik; None bila tidak valid."""
    s = (schedule or "").strip().lower()
    if not s:
        return None
    if s == "hourly":
        return 3600.0
    if s == "daily":
        return 86400.0
    if s == "weekly":
        return 604800.0
    m = re.match(r"\*/(\d+)m$", s)
    if m:
        return float(m.group(1)) * 60.0
    return None


class Scheduler:
    """Loop background yang menjalankan scan terjadwal per project."""

    def __init__(self, projects: ProjectStore,
                 runner: Optional[Callable] = None,
                 authorized: bool = False):
        self.projects = projects
        self._runner = runner
        self.authorized = authorized
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.last_run: Dict[str, float] = {}

    def start(self) -> "Scheduler":
        if self._thread and self._thread.is_alive():
            return self
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)

    def _loop(self) -> None:
        while not self._stop.is_set():
            self.tick()
            self._stop.wait(10.0)

    def tick(self) -> List[Dict]:
        ran = []
        now = time.time()
        for proj in self.projects.list_projects():
            interval = parse_schedule(proj.get("schedule", ""))
            if interval is None:
                continue
            last = self.last_run.get(proj["id"], 0)
            if now - last < interval:
                continue
            self.last_run[proj["id"]] = now
            for target in proj.get("targets", []):
                ran.append(self._run_one(proj, target))
        return ran

    def _run_one(self, proj: Dict, target: str) -> Dict:
        info(f"SCHEDULER: scan {target} (project {proj['id']})")
        try:
            if self._runner is not None:
                result = self._runner(proj, target)
            else:
                result = self._subprocess_scan(target)
            self.projects.save_result(proj["id"], target, result)
            findings = result.get("findings", []) if isinstance(result, dict) else []
            ok(f"  -> {len(findings)} temuan")
            return {"project": proj["id"], "target": target,
                    "findings": len(findings)}
        except Exception as e:
            warn(f"  -> gagal: {e}")
            return {"project": proj["id"], "target": target, "error": str(e)}

    def _subprocess_scan(self, target: str) -> Dict:
        out = "enterprise-scan.json"
        if os.path.exists(out):
            try:
                os.remove(out)
            except OSError:
                pass
        cmd = [sys.executable, "-m", "keris", "scan", target,
               "--json-output", out, "--quiet"]
        if self.authorized:
            cmd.append("--authorized")
        try:
            r = subprocess.run(cmd, capture_output=True, timeout=3600)
        except subprocess.TimeoutExpired:
            return {"ok": False, "error": "timeout"}
        except OSError as e:
            return {"ok": False, "error": str(e)}
        result = {}
        if os.path.exists(out):
            try:
                with open(out, "r", encoding="utf-8") as f:
                    result = json_load(f)
            except Exception:
                pass
            finally:
                try:
                    os.remove(out)
                except OSError:
                    pass
        result["ok"] = r.returncode in (0, 1)
        return result


def json_load(f):
    import json

    return json.load(f)