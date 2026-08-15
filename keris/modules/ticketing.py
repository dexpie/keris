"""Auto-ticketing: findings -> GitHub Issues or Jira issues.

GitHub: uses GITHUB_TOKEN (or config github.token) + github repo slug
(KERIS_GITHUB_REPO or --ticket-repo).
Jira: uses JIRA_BASE_URL, JIRA_EMAIL, JIRA_API_TOKEN (or config).
"""

import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional

import requests

from keris.modules.triage import recommendation_for


def _github_issue(repo: str, token: str, title: str, body: str) -> int:
    r = requests.post(
        f"https://api.github.com/repos/{repo}/issues",
        headers={"Authorization": f"Bearer {token}",
                 "Accept": "application/vnd.github+json"},
        json={"title": title, "body": body},
        timeout=30,
    )
    r.raise_for_status()
    return r.status_code


def _jira_issue(base: str, email: str, token: str, project: str,
                title: str, body: str) -> int:
    r = requests.post(
        base.rstrip("/") + "/rest/api/2/issue",
        auth=(email, token),
        json={
            "fields": {
                "project": {"key": project},
                "summary": title[:255],
                "description": body,
                "issuetype": {"name": "Bug"},
            }
        },
        timeout=30,
    )
    r.raise_for_status()
    return r.status_code


def _create_ticket(kind: str, f: Dict, params: Dict) -> None:
    """Buat satu tiket (dipakai di thread pool)."""
    if kind == "github":
        body = (
            f"**Severity:** {f.get('severity')}\n\n"
            f"**Endpoint:** {f.get('endpoint')}\n\n"
            f"{f.get('detail')}\n\n"
            f"**Evidence:**\n```\n{f.get('evidence', '')}\n```\n\n"
            f"**Rekomendasi:** {recommendation_for(f.get('title', ''))}"
        )
        _github_issue(params["repo"], params["token"], f"[keris] {f.get('title')}", body)
    elif kind == "jira":
        body = (
            f"Severity: {f.get('severity')}\n"
            f"Endpoint: {f.get('endpoint')}\n\n"
            f"{f.get('detail')}\n\n"
            f"Evidence:\n{{code}}{f.get('evidence', '')}{{code}}"
        )
        _jira_issue(params["base"], params["email"], params["token"],
                    params["project"], f"[keris] {f.get('title')}", body)


def create_tickets(findings: List[Dict], kind: str = "github",
                   cfg: Optional[Dict] = None, repo: Optional[str] = None,
                   project: Optional[str] = None,
                   min_severity: str = "HIGH") -> List[Dict]:
    """Creates one ticket per finding at/above min_severity. Returns created titles.

    Pembuatan tiket dijalankan paralel agar target dengan banyak temuan tidak
    membuat seluruh pipeline menunggu satu per satu.
    """
    cfg = cfg or {}
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    if kind not in ("github", "jira"):
        raise ValueError(f"Unknown ticketing kind: {kind}")
    target = [f for f in findings
              if order.get(str(f.get("severity", "INFO")).upper(), 5) <= order.get(min_severity.upper(), 1)
              and f.get("triage", {}).get("status") != "demoted"]
    created: List[str] = []
    if not target:
        return created

    if kind == "github":
        repo = repo or os.environ.get("KERIS_GITHUB_REPO") or cfg.get("github", {}).get("repo")
        token = os.environ.get("GITHUB_TOKEN") or cfg.get("github", {}).get("token")
        if not repo or not token:
            raise ValueError("Auto-ticketing GitHub butuh repo (KERIS_GITHUB_REPO) dan GITHUB_TOKEN")
        params = {"repo": repo, "token": token}
    elif kind == "jira":
        project = project or os.environ.get("JIRA_PROJECT") or cfg.get("jira", {}).get("project")
        base = os.environ.get("JIRA_BASE_URL") or cfg.get("jira", {}).get("base_url")
        email = os.environ.get("JIRA_EMAIL") or cfg.get("jira", {}).get("email")
        token = os.environ.get("JIRA_API_TOKEN") or cfg.get("jira", {}).get("api_token")
        if not (base and email and token and project):
            raise ValueError(
                "Auto-ticketing Jira butuh JIRA_BASE_URL, JIRA_EMAIL, JIRA_API_TOKEN, JIRA_PROJECT")
        params = {"base": base, "email": email, "token": token, "project": project}
    else:
        raise ValueError(f"Unknown ticketing kind: {kind}")  # unreachable; didefinisikan di atas

    with ThreadPoolExecutor(max_workers=min(6, max(1, len(target)))) as pool:
        futures = {pool.submit(_create_ticket, kind, f, params): f for f in target}
        for fut in as_completed(futures):
            f = futures[fut]
            try:
                fut.result()
                created.append(f.get("title"))
            except Exception:
                continue
    return created