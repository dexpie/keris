"""keris watch: continuous monitoring of a target with diff, risk trending,
dan alerting multi-channel.

Runs a scan, diffs against the previous report, tracks a risk trend across
cycles, reports new/persisting CRITICAL/HIGH findings, and alerts via
Slack/Discord/Telegram/Teams/email/PagerDuty/generic webhook. Designed to run
under cron.
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


def _load_trend(state_dir: str, target: str) -> List[Dict]:
    try:
        with open(os.path.join(state_dir, "trend.json"), encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, list):
            return []
        return [e for e in data if e.get("target") == target]
    except Exception:
        return []


def _save_trend(state_dir: str, target: str, entry: Dict) -> List[Dict]:
    os.makedirs(state_dir, exist_ok=True)
    trend = _load_trend(state_dir, target)[-99:]
    trend.append(entry)
    # simpan semua entry target lain juga agar file trend tidak menimpa target lain
    others = []
    try:
        with open(os.path.join(state_dir, "trend.json"), encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            others = [e for e in data if e.get("target") != target]
    except Exception:
        others = []
    merged = (others + trend)[-500:]
    with open(os.path.join(state_dir, "trend.json"), "w", encoding="utf-8") as f:
        json.dump(merged, f, indent=2, default=str)
    return trend


def _risk_grade(findings: List[Dict]) -> Dict:
    try:
        from keris.modules.riskscore import risk_score

        return risk_score(findings)
    except Exception:
        return {"grade": "?", "score": 0.0}


def _trend_markdown(trend: List[Dict]) -> str:
    rows = []
    for e in trend:
        ts = str(e.get("ts", ""))[:16]
        rows.append(f"- `{ts}` grade **{e.get('grade', '?')}** "
                    f"skor {e.get('score', 0)} | total {e.get('total', 0)} "
                    f"temuan (baru {e.get('new', 0)}, fixed {e.get('fixed', 0)})")
    if not rows:
        return "_Belum ada data tren._"
    return "\n".join(rows)


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
          json_output: Optional[str] = None,
          channels: Optional[List[Dict]] = None) -> Dict:
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

    risk = _risk_grade(new_findings)
    ts = datetime.utcnow().isoformat() + "Z"
    trend = _save_trend(state_dir, target, {
        "target": target,
        "ts": ts,
        "grade": risk.get("grade"),
        "score": risk.get("score"),
        "counts": risk.get("counts", {}),
        "total": risk.get("total", len(new_findings)),
        "new": len(diff["new"]),
        "fixed": len(diff["fixed"]),
        "persisting": len(diff["persisting"]),
    })

    alert_sent = 0
    if alertables:
        if channels:
            from keris.modules.notify import notify_multi

            try:
                alert_sent = notify_multi(channels, target, alertables)
                info(f"Alert multi-channel: {alert_sent}/{len(channels)} kanal terkirim")
            except Exception as e:
                warn(f"Alert multi-channel gagal: {e}")
        elif webhook:
            try:
                _alert_webhook(webhook, webhook_type, target, alertables)
                info(f"Webhook alert: {len(alertables)} temuan baru")
            except Exception as e:
                warn(f"Webhook alert gagal: {e}")

    cycle = {
        "timestamp": ts,
        "target": target,
        "risk": {"grade": risk.get("grade"), "score": risk.get("score"),
                 "counts": risk.get("counts", {})},
        "trend": trend[-10:],
        "summary": {
            "new": len(diff["new"]),
            "fixed": len(diff["fixed"]),
            "persisting": len(diff["persisting"]),
            "alertable_new": len(alertables),
            "alert_sent": alert_sent,
        },
        "new_findings": diff["new"],
        "fixed_findings": diff["fixed"],
    }
    ok(f"Watch cycle: {len(diff['new'])} baru, {len(diff['fixed'])} fixed, "
       f"{len(diff['persisting'])} persisting | "
       f"risk {risk.get('grade')} ({risk.get('score')}/100)")
    info("Risk trend (10 cycle terakhir):\n" + _trend_markdown(trend[-10:]))
    if json_output:
        with open(json_output, "w", encoding="utf-8") as f:
            json.dump(cycle, f, indent=2, default=str)
    return cycle


def watch_loop(target: str, state_dir: str, run_scan, interval: int = 3600,
               runs: Optional[int] = None, webhook: Optional[str] = None,
               webhook_type: str = "auto", min_severity: str = "HIGH",
               json_output: Optional[str] = None,
               channels: Optional[List[Dict]] = None) -> int:
    """Runs watch() repeatedly. Blocking. Returns number of alertable cycles."""
    count = 0
    i = 0
    while runs is None or i < runs:
        i += 1
        info(f"Watch cycle {i} ({target})")
        try:
            cycle = watch(target, state_dir, run_scan, webhook, webhook_type,
                          min_severity, json_output, channels)
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