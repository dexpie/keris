"""keris watch: continuous monitoring of a target with diff + alerting.

Runs a scan, diffs against the previous report, reports new/persisting
CRITICAL/HIGH findings, and alerts via webhook. Designed to run under cron.
"""

import json
import os
import time
from datetime import datetime
from typing import Dict, List, Optional

from keris.core.logger import info, ok, warn


def _load_report(path: str) -> List[Dict]:
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return []
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        return data.get("findings", []) or []
    return []


def _key(f: Dict) -> tuple:
    return (f.get("endpoint", ""), f.get("title", ""))


def _severity(f: Dict) -> str:
    return str(f.get("severity", "INFO")).upper()


def _diff(old: List[Dict], new: List[Dict]) -> Dict:
    old_map = {_key(f): f for f in old}
    new_map = {_key(f): f for f in new}
    new_f = [new_map[k] for k in new_map if k not in old_map]
    persisting = [new_map[k] for k in old_map if k in new_map]
    fixed = [old_map[k] for k in old_map if k not in new_map]
    return {"new": new_f, "persisting": persisting, "fixed": fixed}


_ALERT_SEV = ("CRITICAL", "HIGH")


def _alert_webhook(url: str, wtype: str, target: str, findings: List[Dict]) -> None:
    import requests
    text = (f"keris watch: {len(findings)} temuan baru pada {target}\n"
            + "\n".join(f"- [{f.get('severity')}] {f.get('title')} @ {f.get('endpoint')}"
                        for f in findings[:15]))
    if wtype == "discord":
        r = requests.post(url, json={"content": text}, timeout=20)
    elif wtype == "telegram":
        r = requests.post(url, data={"text": text}, timeout=20)
    else:  # slack / auto
        r = requests.post(url, json={"text": text}, timeout=20)
    r.raise_for_status()


def watch(target: str, state_dir: str, run_scan, webhook: Optional[str] = None,
          webhook_type: str = "auto", min_severity: str = "HIGH",
          json_output: Optional[str] = None) -> Dict:
    """One watch cycle. run_scan(target, out_path) must produce a keris JSON report."""
    os.makedirs(state_dir, exist_ok=True)
    latest = os.path.join(state_dir, "latest.json")
    previous = os.path.join(state_dir, "previous.json")

    if os.path.exists(latest):
        os.replace(latest, previous)

    run_scan(target, latest)

    new_findings = _load_report(latest)
    old_findings = _load_report(previous) if os.path.exists(previous) else []

    diff = _diff(old_findings, new_findings)

    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    threshold = order.get(min_severity.upper(), 1)
    alertables = [f for f in diff["new"]
                  if order.get(_severity(f), 4) <= threshold]

    if webhook and alertables:
        try:
            _alert_webhook(webhook, webhook_type, target, alertables)
            info(f"Webhook alert: {len(alertables)} temuan baru")
        except Exception as e:
            warn(f"Webhook alert gagal: {e}")

    cycle = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "target": target,
        "summary": {
            "new": len(diff["new"]),
            "fixed": len(diff["fixed"]),
            "persisting": len(diff["persisting"]),
            "alertable_new": len(alertables),
        },
        "new_findings": diff["new"],
        "fixed_findings": diff["fixed"],
    }
    ok(f"Watch cycle: {len(diff['new'])} baru, {len(diff['fixed'])} fixed, "
       f"{len(diff['persisting'])} persisting")
    if json_output:
        with open(json_output, "w", encoding="utf-8") as f:
            json.dump(cycle, f, indent=2, default=str)
    return cycle


def watch_loop(target: str, state_dir: str, run_scan, interval: int = 3600,
               runs: Optional[int] = None, webhook: Optional[str] = None,
               webhook_type: str = "auto", min_severity: str = "HIGH",
               json_output: Optional[str] = None) -> int:
    """Runs watch() repeatedly. Blocking. Returns number of alertable cycles."""
    count = 0
    i = 0
    while runs is None or i < runs:
        i += 1
        info(f"Watch cycle {i} ({target})")
        try:
            cycle = watch(target, state_dir, run_scan, webhook, webhook_type,
                          min_severity, json_output)
            if cycle["summary"]["alertable_new"]:
                count += 1
        except Exception as e:
            warn(f"Watch cycle error: {e}")
        if runs is not None and i >= runs:
            break
        info(f"Menunggu {interval}s sebelum cycle berikutnya (Ctrl+C untuk berhenti)")
        try:
            time.sleep(interval)
        except KeyboardInterrupt:
            info("Dihentikan oleh user")
            break
    return count