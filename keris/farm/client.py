"""Klien API untuk farm master: submit, status, stop, report."""

import json
import os
from typing import Dict, List, Optional

import requests


class FarmClient:
    def __init__(self, master_url: str, token: str = "",
                 timeout: float = 30.0):
        self.master_url = master_url.rstrip("/")
        self.token = token
        self.timeout = timeout

    def _headers(self) -> Dict[str, str]:
        h = {}
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        return h

    def submit(self, targets: List[str], config: Optional[Dict] = None) -> Dict:
        r = requests.post(f"{self.master_url}/api/jobs",
                          headers=self._headers(),
                          json={"targets": targets, "config": config or {}},
                          timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    def status(self) -> Dict:
        r = requests.get(f"{self.master_url}/api/status", timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    def stop(self, admin_token: str) -> bool:
        r = requests.post(f"{self.master_url}/api/shutdown",
                          headers={"Authorization": f"Bearer {admin_token}"},
                          json={}, timeout=self.timeout)
        return r.status_code == 200

    def report(self, out_path: str = "farm-report.md") -> str:
        r = requests.get(f"{self.master_url}/api/report", timeout=self.timeout)
        r.raise_for_status()
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(r.text)
        return out_path


def submit_jobs(master_url: str, targets: List[str],
                config: Optional[Dict] = None, token: str = "") -> Dict:
    return FarmClient(master_url, token).submit(targets, config)


def farm_status(master_url: str) -> Dict:
    return FarmClient(master_url).status()


def farm_stop(master_url: str, admin_token: str = "") -> bool:
    if not admin_token:
        from keris.farm.auth import create_token, read_secret

        admin_token = create_token({"sub": "admin", "role": "admin"},
                                   read_secret(), ttl=300)
    return FarmClient(master_url, admin_token).stop(admin_token)


def read_targets(path: str) -> List[str]:
    """Baca daftar target dari file (satu per baris)."""
    if not os.path.exists(path):
        raise FileNotFoundError(f"File target tidak ditemukan: {path}")
    with open(path, "r", encoding="utf-8") as f:
        return [line.strip() for line in f
                if line.strip() and not line.startswith("#")]


def read_config(path: str) -> Dict:
    """Baca config scan dari file JSON."""
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)