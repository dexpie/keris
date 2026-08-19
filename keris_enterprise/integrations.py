"""Integrasi keris-enterprise: DefectDojo, Splunk/ELK, GitHub/GitLab ticket."""

import json
import os
from typing import Dict, List, Optional

import requests

from keris.core.logger import info, warn


def _req(url: str, headers: Dict, payload: Dict, timeout: float = 20.0) -> bool:
    try:
        r = requests.post(url, headers=headers, json=payload, timeout=timeout)
        return r.status_code < 400
    except requests.RequestException as e:
        warn(f"Integrasi {url} gagal: {e}")
        return False


# --- DefectDojo sync ---
def defectdojo_import(dojo_url: str, api_key: str, product_id: int,
                      findings: List[Dict], engagement_name: str = "") -> bool:
    """Kirim findings ke DefectDojo import endpoint."""
    # DefectDojo v2 API: POST /api/v2/import-scan/ (multipart). Di sini versi
    # sederhana via /api/v2/findings/ untuk tiap finding.
    headers = {"Authorization": f"Token {api_key}"}
    ok_all = True
    for f in findings[:50]:
        payload = {
            "product": product_id,
            "title": f.get("title", ""),
            "severity": f.get("severity", "Info").lower(),
            "description": f.get("detail", ""),
            "endpoint": f.get("endpoint", ""),
        }
        ok_all = _req(f"{dojo_url.rstrip('/')}/api/v2/findings/",
                      headers, payload) and ok_all
    return ok_all


# --- Splunk / ELK log forwarding ---
def forward_logs(endpoint: str, token: str, index: str, source: str,
                 findings: List[Dict]) -> bool:
    """Kirim findings sebagai log ke Splunk HEC atau ELK."""
    try:
        if "splunk" in endpoint.lower() or "/services/collector" in endpoint:
            payload = {"event": {"findings": findings}, "index": index,
                       "source": source}
            headers = {"Authorization": f"Splunk {token}"}
        else:  # ELK / generic
            payload = {"source": source, "index": index, "findings": findings}
            headers = {"Authorization": f"Bearer {token}"}
        r = requests.post(endpoint, headers=headers, json=payload, timeout=20)
        return r.status_code < 400
    except requests.RequestException as e:
        warn(f"Forward log gagal: {e}")
        return False


# --- GitHub auto-ticket ---
def github_ticket(repo: str, token: str, title: str, body: str) -> bool:
    """Buat issue GitHub untuk temuan."""
    url = f"https://api.github.com/repos/{repo}/issues"
    headers = {"Authorization": f"Bearer {token}",
               "Accept": "application/vnd.github+json"}
    return _req(url, headers, {"title": title, "body": body})


# --- GitLab auto-ticket ---
def gitlab_ticket(project_id, token, gitlab_url, title, body) -> bool:
    """Buat issue GitLab untuk temuan."""
    url = f"{gitlab_url.rstrip('/')}/api/v4/projects/{project_id}/issues"
    headers = {"PRIVATE-TOKEN": token}
    return _req(url, headers, {"title": title, "description": body})


class IntegrationHub:
    """Mengelola semua integrasi terkonfigurasi."""

    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}

    def sync(self, findings: List[Dict], project: str = "") -> Dict:
        results = {}
        dd = self.config.get("defectdojo")
        if dd and dd.get("url") and dd.get("api_key"):
            results["defectdojo"] = defectdojo_import(
                dd["url"], dd["api_key"], int(dd.get("product_id", 0)),
                findings, project)
        log = self.config.get("log_forwarding")
        if log and log.get("endpoint"):
            results["log_forwarding"] = forward_logs(
                log["endpoint"], log.get("token", ""), log.get("index", "keris"),
                project, findings)
        gh = self.config.get("github")
        if gh and gh.get("repo") and gh.get("token") and findings:
            top = findings[0]
            results["github"] = github_ticket(
                gh["repo"], gh["token"],
                f"[Keris] {top.get('title', 'temuan')}",
                f"Target: {project}\n\n{top.get('detail', '')}")
        gl = self.config.get("gitlab")
        if gl and gl.get("project_id") and gl.get("token") and findings:
            top = findings[0]
            results["gitlab"] = gitlab_ticket(
                gl["project_id"], gl["token"], gl.get("url", "https://gitlab.com"),
                f"[Keris] {top.get('title', 'temuan')}", top.get("detail", ""))
        return results