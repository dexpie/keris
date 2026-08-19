"""Alerting untuk keris-enterprise: email, Slack, Teams, webhook + escalation.

Escalation policy: bila temuan CRITICAL muncul berulang pada project yang
sama, notifikasi dinaikkan level (dikirim ke channel yang lebih tinggi).
"""

import smtplib
import time
from email.mime.text import MIMEText
from typing import Dict, List, Optional

import requests

from keris.core.logger import info, ok, warn


def _post(url: str, payload: Dict, timeout: float = 10.0) -> bool:
    try:
        r = requests.post(url, json=payload, timeout=timeout)
        return r.status_code < 400
    except requests.RequestException:
        return False


def send_slack(webhook: str, base: str, findings: List[Dict],
               project: str = "") -> bool:
    text = f"Keris alert: {project or base} ({len(findings)} temuan)\n"
    for f in findings[:10]:
        text += f"[{f.get('severity', 'INFO')}] {f.get('title', '')} @ {f.get('endpoint', '')}\n"
    return _post(webhook, {"text": text})


def send_teams(webhook: str, base: str, findings: List[Dict],
               project: str = "") -> bool:
    facts = [{"name": f"[{f.get('severity','INFO')}] {f.get('title','')}",
              "value": f.get("endpoint", "")} for f in findings[:10]]
    payload = {"@type": "MessageCard", "@context": "http://schema.org/extensions",
               "summary": "Keris alert", "title": f"Keris alert: {project or base}",
               "sections": [{"facts": facts or [{"name": "OK", "value": "none"}]}]}
    return _post(webhook, payload)


def send_email(smtp_host: str, smtp_port: int, username: str, password: str,
               from_addr: str, to_addrs: List[str], subject: str, body: str,
               use_tls: bool = True) -> bool:
    try:
        msg = MIMEText(body, "plain", "utf-8")
        msg["Subject"] = subject
        msg["From"] = from_addr
        msg["To"] = ", ".join(to_addrs)
        with smtplib.SMTP(smtp_host, smtp_port, timeout=15) as s:
            if use_tls:
                s.starttls()
            if username:
                s.login(username, password)
            s.sendmail(from_addr, to_addrs, msg.as_string())
        return True
    except Exception as e:
        warn(f"Email gagal: {e}")
        return False


class AlertManager:
    """Mengelola kanal alert + escalation policy per project."""

    ESCALATION_STEPS = {
        1: "ke channel default",
        2: "ke channel TINGGI (criteria CRITICAL berulang)",
        3: "ke semua channel",
    }

    def __init__(self, config: Optional[Dict] = None):
        # config: {"slack": {"webhook":...}, "teams": {...},
        #          "email": {"smtp_host":..., "smtp_port":..., ...},
        #          "escalate_after_repeats": 2}
        self.config = config or {}
        self._repeat: Dict[str, int] = {}

    def register_repeat(self, project_id: str) -> int:
        n = self._repeat.get(project_id, 0) + 1
        self._repeat[project_id] = n
        return n

    def escalation_level(self, project_id: str,
                         findings: List[Dict]) -> int:
        """Level escalation: 1..3 berdasar kemunculan CRITICAL berulang."""
        has_critical = any(
            str(f.get("severity", "")).upper() == "CRITICAL" for f in findings)
        if not has_critical:
            return 1
        threshold = int(self.config.get("escalate_after_repeats", 2) or 2)
        if self._repeat.get(project_id, 0) >= threshold * 2:
            return 3
        if self._repeat.get(project_id, 0) >= threshold:
            return 2
        return 1

    def send(self, project_id: str, project_name: str, target: str,
             findings: List[Dict]) -> List[bool]:
        """Kirim alert ke semua kanal yang dikonfigurasi."""
        level = self.escalation_level(project_id, findings)
        results = []
        base = target or project_name
        if self.config.get("slack"):
            results.append(send_slack(self.config["slack"]["webhook"], base,
                                      findings, project_name))
        if self.config.get("teams"):
            results.append(send_teams(self.config["teams"]["webhook"], base,
                                      findings, project_name))
        email_cfg = self.config.get("email")
        if email_cfg and email_cfg.get("to"):
            subject = f"[{level}] Keris alert: {project_name} - {len(findings)} temuan"
            body = "\n".join(
                f"[{f.get('severity','INFO')}] {f.get('title','')} @ {f.get('endpoint','')}"
                for f in findings[:30])
            results.append(send_email(email_cfg.get("smtp_host", ""),
                                      int(email_cfg.get("smtp_port", 587)),
                                      email_cfg.get("username", ""),
                                      email_cfg.get("password", ""),
                                      email_cfg.get("from", email_cfg.get("username", "")),
                                      email_cfg.get("to", []),
                                      subject, body,
                                      bool(email_cfg.get("use_tls", True))))
        info(f"Alert dikirim (level {level}): {len(results)} kanal")
        return results