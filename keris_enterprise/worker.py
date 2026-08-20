"""Worker & queue untuk keris-enterprise (v0.27.0).

`ScanWorker` memproses antrean scan di thread background: scan yang
ber-status `queued` diambil satu per satu, dijalankan via subprocess keris,
lalu hasilnya disimpan dan status di-set `done`/`failed`.

Digunakan API (`/api/worker/*`) dan scheduler. Berbeda dari scheduler yang
memicu scan *terjadwal* per project, worker memproses scan yang *diminta*
(user / API) lewat antrean.

Zero-dependency: subprocess + threading (stdlib).
"""

import os
import subprocess
import sys
import threading
import time
from typing import Callable, Dict, List, Optional

from keris.core.logger import info, ok, warn
from keris_enterprise.projects import ProjectStore


class ScanWorker:
    """Worker background: proses antrean scan satu per satu (serial)."""

    def __init__(self, projects: ProjectStore,
                 runner: Optional[Callable] = None,
                 authorized: bool = False,
                 concurrency: int = 1):
        self.projects = projects
        self._runner = runner
        self.authorized = authorized
        self.concurrency = max(1, concurrency)
        self._stop = threading.Event()
        self._threads: List[threading.Thread] = []
        self._active = 0
        self._lock = threading.Lock()
        self.stats = {"processed": 0, "failed": 0, "active": 0}

    # --- lifecycle ---
    def start(self) -> "ScanWorker":
        if self._threads and any(t.is_alive() for t in self._threads):
            return self
        self._stop.clear()
        for _ in range(self.concurrency):
            t = threading.Thread(target=self._loop, daemon=True)
            t.start()
            self._threads.append(t)
        ok(f"ScanWorker aktif (concurrency={self.concurrency})")
        return self

    def stop(self) -> None:
        self._stop.set()
        for t in self._threads:
            t.join(timeout=5)

    # --- queue management ---
    def enqueue(self, project_id: str, target: str) -> Dict:
        """Tambahkan scan ke antrean (status=queued)."""
        meta = self.projects.save_result(project_id, target, {}, status="queued")
        info(f"Scan diantrekan: {target} (project {project_id})")
        return meta

    def queue_length(self) -> int:
        return len(self.projects.pending_results())

    # --- processing ---
    def _loop(self) -> None:
        while not self._stop.is_set():
            job = self._next_job()
            if job is None:
                self._stop.wait(2.0)
                continue
            try:
                self._process(job)
            except Exception as e:
                warn(f"Worker error pada {job.get('target')}: {e}")
                self.projects.update_result_status(job["id"], "failed")
                with self._lock:
                    self.stats["failed"] += 1
            finally:
                with self._lock:
                    self._active -= 1
                    self.stats["active"] = self._active

    def _next_job(self) -> Optional[Dict]:
        jobs = self.projects.pending_results()
        if not jobs:
            return None
        with self._lock:
            if self._active >= self.concurrency:
                return None
            self._active += 1
            self.stats["active"] = self._active
        job = jobs[0]
        self.projects.update_result_status(job["id"], "running")
        return job

    def _process(self, job: Dict) -> None:
        target = job.get("target", "")
        info(f"WORKER: scan {target}")
        if self._runner is not None:
            result = self._runner({"id": job.get("project_id")}, target)
        else:
            result = self._subprocess_scan(target)
        self.projects.db.execute(
            "UPDATE scan_results SET result=?, status=?, created_at=? WHERE id=?",
            (__import__("json").dumps(result, default=str),
             "done", time.time(), job["id"]))
        findings = result.get("findings", []) if isinstance(result, dict) else []
        with self._lock:
            self.stats["processed"] += 1
        ok(f"  -> {len(findings)} temuan ({target})")

    def _subprocess_scan(self, target: str) -> Dict:
        out = "enterprise-worker-scan.json"
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
        result: Dict = {}
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