"""Worker node untuk distributed scan farm.

Worker:
1. register ke master (mendapat JWT)
2. poll `/api/claim` untuk mengambil job (load balancing)
3. jalankan `keris scan <target> --json-output ... --quiet` secara lokal
4. kirim hasil (JSON) ke master `/api/jobs/<id>/result`
5. bila gagal, laporkan `/api/jobs/<id>/fail` agar job di-reassign
"""

import json
import os
import subprocess
import sys
import time
from typing import Dict, Optional

import requests

from keris.core.logger import info, ok, warn


class WorkerLoop:
    def __init__(self, master_url: str, name: str = "worker",
                 capacity: int = 1, poll_interval: float = 5.0,
                 runner=None, authorized: bool = False):
        self.master_url = master_url.rstrip("/")
        self.name = name
        self.capacity = max(1, int(capacity or 1))
        self.poll_interval = poll_interval
        self.token = ""
        self.worker_id = ""
        self._runner = runner  # testing hook
        self.authorized = authorized

    # --- API helpers ---
    def _headers(self) -> Dict[str, str]:
        return {"Authorization": f"Bearer {self.token}"}

    def register(self) -> bool:
        try:
            r = requests.post(f"{self.master_url}/api/register",
                              json={"name": self.name, "capacity": self.capacity},
                              timeout=15)
            r.raise_for_status()
            data = r.json()
            self.worker_id = data["worker_id"]
            self.token = data["token"]
            ok(f"Worker terdaftar: {self.worker_id}")
            return True
        except Exception as e:
            warn(f"Register gagal: {e}")
            return False

    def claim(self) -> Optional[Dict]:
        try:
            r = requests.post(f"{self.master_url}/api/claim",
                              headers=self._headers(), json={}, timeout=30)
            r.raise_for_status()
            return r.json().get("job")
        except Exception:
            return None

    def submit_result(self, jid: str, result: Dict) -> bool:
        try:
            r = requests.post(f"{self.master_url}/api/jobs/{jid}/result",
                              headers=self._headers(),
                              json={"result": result}, timeout=30)
            r.raise_for_status()
            return True
        except Exception as e:
            warn(f"Kirim hasil {jid} gagal: {e}")
            return False

    def submit_fail(self, jid: str, err: str) -> bool:
        try:
            r = requests.post(f"{self.master_url}/api/jobs/{jid}/fail",
                              headers=self._headers(),
                              json={"error": err}, timeout=30)
            r.raise_for_status()
            return True
        except Exception:
            return False

    # --- scan execution ---
    def run_scan(self, target: str, config: Dict) -> Dict:
        if self._runner is not None:
            return self._runner(target, config)
        out = os.path.join(os.getcwd(), "farm-step.json")
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
            r = subprocess.run(cmd, capture_output=True, timeout=1800)
        except subprocess.TimeoutExpired:
            return {"ok": False, "error": "timeout"}
        except OSError as e:
            return {"ok": False, "error": str(e)}
        result = {}
        if os.path.exists(out):
            try:
                with open(out, "r", encoding="utf-8") as f:
                    result = json.load(f)
            except (OSError, json.JSONDecodeError):
                pass
            finally:
                try:
                    os.remove(out)
                except OSError:
                    pass
        result["ok"] = r.returncode in (0, 1)
        return result

    # --- main loop ---
    def run_forever(self, iterations: int = 0) -> int:
        """Loop worker; `iterations=0` = tanpa batas. Return jumlah job diproses."""
        if not self.register():
            warn("Tidak bisa mendaftar ke master; coba lagi.")
            return 0
        processed = 0
        while True:
            job = self.claim()
            if job:
                processed += 1
                info(f"Job {job['id']}: scan {job['target']}")
                try:
                    config = json.loads(job.get("config") or "{}")
                except json.JSONDecodeError:
                    config = {}
                result = self.run_scan(job["target"], config)
                if result.get("ok", False):
                    findings = result.get("findings", []) if isinstance(result, dict) else []
                    if self.submit_result(job["id"],
                                          {"findings": findings,
                                           "summary": result.get("risk_score", {})}):
                        ok(f"Job {job['id']} selesai: {len(findings)} temuan")
                    else:
                        self.submit_fail(job["id"], "gagal kirim hasil")
                else:
                    warn(f"Job {job['id']} gagal: {result.get('error')}")
                    self.submit_fail(job["id"], str(result.get("error", "unknown")))
            else:
                time.sleep(self.poll_interval)
            if iterations and processed >= iterations:
                break
        return processed