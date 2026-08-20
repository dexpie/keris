"""Webhook notifikasi: kirim ringkasan temuan ke Slack/Discord/Telegram/Teams/
email/PagerDuty/generic webhook, termasuk fan-out multi-channel."""

import json
import os
import smtplib
from email.mime.text import MIMEText
from typing import Dict, List, Optional
from urllib.parse import urlencode

import requests

from keris.core.logger import debug, info, ok, warn


def _post_json(url: str, payload: Dict, timeout: float = 10.0) -> bool:
    try:
        r = requests.post(url, json=payload, timeout=timeout)
        return r.status_code < 400
    except requests.RequestException:
        return False


def _risk_note(findings: List[dict]) -> str:
    try:
        from keris.modules.riskscore import risk_score

        rs = risk_score(findings)
        return f" | Risk: {rs['grade']} ({rs['score']}/100)"
    except Exception:
        return ""


def send_slack(webhook: str, base: str, findings: List[dict]) -> bool:
    text = f"*Keris scan: {base}* ({len(findings)} temuan{_risk_note(findings)})\n"
    for f in findings[:15]:
        sev = f.get("severity", "INFO")
        text += f"\n• *[{sev}]* {f.get('title', '')} — {f.get('endpoint', '')}"
    return _post_json(webhook, {"text": text})


def send_discord(webhook: str, base: str, findings: List[dict]) -> bool:
    color_map = {"CRITICAL": 15548997, "HIGH": 15158332, "MEDIUM": 15844367,
                 "LOW": 15844367, "INFO": 5814783}
    color = color_map.get(max((f.get("severity", "INFO") for f in findings),
                              key=lambda s: list(color_map).index(s) if s in color_map else 4), 0)
    fields = []
    for f in findings[:25]:
        fields.append({
            "name": f"[{f.get('severity', 'INFO')}] {f.get('title', '')}",
            "value": f"{f.get('endpoint', '')}\n{f.get('detail', '')[:120]}",
            "inline": False,
        })
    embed = {
        "title": f"Keris scan: {base}{_risk_note(findings)}",
        "color": color,
        "fields": fields or [{"name": "OK", "value": "Tidak ada temuan."}],
    }
    return _post_json(webhook, {"embeds": [embed]})


def send_telegram(bot_token: str, chat_id: str, base: str, findings: List[dict]) -> bool:
    lines = [f"Keris scan: {base} ({len(findings)} temuan{_risk_note(findings)})"]
    for f in findings[:15]:
        lines.append(f"[{f.get('severity', 'INFO')}] {f.get('title', '')} — {f.get('endpoint', '')}")
    text = "\n".join(lines)
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    return _post_json(url, {"chat_id": chat_id, "text": text[:4000]})


def send_teams(webhook: str, base: str, findings: List[dict]) -> bool:
    """Microsoft Teams (Incoming Webhook / Workflows): payload MessageCard."""
    color_map = {"CRITICAL": "ff0000", "HIGH": "ff9900", "MEDIUM": "ffff00",
                 "LOW": "7d7d7d", "INFO": "1a7dd8"}
    lines = [f"**[{f.get('severity', 'INFO')}]** {f.get('title', '')} — "
             f"{f.get('endpoint', '')}" for f in findings[:15]]
    text = f"Keris scan: {base} ({len(findings)} temuan{_risk_note(findings)})"
    if lines:
        text += "\n\n" + "\n\n".join(lines)
    color = "00cc66" if not findings else color_map.get(
        max((f.get("severity", "INFO") for f in findings),
            key=lambda s: list(color_map).index(s) if s in color_map else 4), "1a7dd8")
    payload = {
        "@type": "MessageCard",
        "@context": "https://schema.org/extensions",
        "summary": f"Keris scan: {base}",
        "themeColor": color,
        "title": f"Keris scan: {base} ({len(findings)} temuan)",
        "text": text,
    }
    return _post_json(webhook, payload)


def send_email(smtp_host: str, smtp_port: int, smtp_user: str, smtp_pass: str,
               smtp_to: str, base: str, findings: List[dict]) -> bool:
    """Kirim email lewat SMTP (STARTTLS). Semua param opsional dari env
    KERIS_SMTP_*. Standar library, tanpa dependency tambahan."""
    host = smtp_host or os.environ.get("KERIS_SMTP_HOST", "")
    port = smtp_port or int(os.environ.get("KERIS_SMTP_PORT", "587"))
    user = smtp_user or os.environ.get("KERIS_SMTP_USER", "")
    pw = smtp_pass or os.environ.get("KERIS_SMTP_PASS", "")
    to = smtp_to or os.environ.get("KERIS_SMTP_TO", "")
    if not (host and to):
        warn("Email alert butuh --smtp-host / --smtp-to (atau env KERIS_SMTP_*)")
        return False
    lines = [f"Keris scan: {base} ({len(findings)} temuan{_risk_note(findings)})"]
    for f in findings[:20]:
        lines.append(f"[{f.get('severity', 'INFO')}] {f.get('title', '')} — "
                     f"{f.get('endpoint', '')}")
    msg = MIMEText("\n".join(lines), "plain", "utf-8")
    msg["Subject"] = f"[Keris] {len(findings)} temuan pada {base}"
    msg["From"] = user or "keris@localhost"
    msg["To"] = to
    try:
        if port == 465:
            with smtplib.SMTP_SSL(host, port, timeout=15) as s:
                if user:
                    s.login(user, pw)
                s.sendmail(user or "keris@localhost", [to], msg.as_string())
        else:
            with smtplib.SMTP(host, port, timeout=15) as s:
                s.ehlo()
                s.starttls()
                s.ehlo()
                if user:
                    s.login(user, pw)
                s.sendmail(user or "keris@localhost", [to], msg.as_string())
        return True
    except Exception as e:
        warn(f"Email gagal: {e}")
        return False


def send_pagerduty(routing_key: str, base: str, findings: List[dict]) -> bool:
    """PagerDuty Events API v2: trigger incident bila ada temuan alertable."""
    sev = "critical" if any(f.get("severity", "") == "CRITICAL"
                            for f in findings) else "error"
    titles = "; ".join(f"{f.get('severity', '')} {f.get('title', '')}"
                       for f in findings[:5])
    payload = {
        "routing_key": routing_key,
        "event_action": "trigger",
        "payload": {
            "summary": f"[Keris] {len(findings)} temuan pada {base}: {titles}",
            "source": base,
            "severity": sev,
            "dedup_key": f"keris-{base}",
        },
    }
    return _post_json("https://events.pagerduty.com/v2/enqueue", payload,
                      timeout=15.0)


def send_webhook(url: str, base: str, findings: List[dict]) -> bool:
    """Generic JSON webhook: kirim struktur temuan lengkap."""
    payload = {
        "source": "keris",
        "target": base,
        "count": len(findings),
        "severity": {s: sum(1 for f in findings if f.get("severity", "").upper() == s)
                     for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")},
        "findings": findings[:50],
    }
    return _post_json(url, payload, timeout=15.0)


def _telegram_from_url(webhook_url: str) -> Optional[tuple]:
    """Ekstrak (bot_token, chat_id) dari URL telegram:
    https://api.telegram.org/bot<TOKEN>/sendMessage?chat_id=<ID>
    """
    from urllib.parse import urlparse, parse_qs

    p = urlparse(webhook_url)
    if "telegram" not in p.netloc:
        return None
    m = p.path.split("/bot", 1)
    if len(m) < 2:
        return None
    token = m[1].split("/", 1)[0]
    qs = parse_qs(p.query)
    chat_id = qs.get("chat_id", [""])[0]
    if not token or not chat_id:
        return None
    return token, chat_id


def notify(webhook_url: str, kind: str, base: str, findings: List[dict]) -> bool:
    """Kirim notifikasi sesuai jenis webhook."""
    ok_ = False
    try:
        if kind == "slack":
            ok_ = send_slack(webhook_url, base, findings)
        elif kind == "discord":
            ok_ = send_discord(webhook_url, base, findings)
        elif kind == "teams":
            ok_ = send_teams(webhook_url, base, findings)
        elif kind == "telegram":
            tup = _telegram_from_url(webhook_url)
            if tup is None:
                warn("URL telegram harus berformat .../bot<TOKEN>/sendMessage?chat_id=<ID>")
                return False
            ok_ = send_telegram(tup[0], tup[1], base, findings)
        elif kind == "email":
            ok_ = send_email(webhook_url, 0, "", "", "", base, findings)
        elif kind == "pagerduty":
            ok_ = send_pagerduty(webhook_url, base, findings)
        elif kind == "webhook":
            ok_ = send_webhook(webhook_url, base, findings)
        else:
            # coba deteksi otomatis dari URL
            tup = _telegram_from_url(webhook_url)
            if tup is not None:
                ok_ = send_telegram(tup[0], tup[1], base, findings)
            elif "slack" in webhook_url:
                ok_ = send_slack(webhook_url, base, findings)
            elif "discord" in webhook_url or "discordapp" in webhook_url:
                ok_ = send_discord(webhook_url, base, findings)
            elif "office.com" in webhook_url or "webhook.office" in webhook_url:
                ok_ = send_teams(webhook_url, base, findings)
            else:
                ok_ = send_webhook(webhook_url, base, findings)
    except Exception as e:
        warn(f"Webhook gagal: {e}")
        return False
    if ok_:
        ok(f"Notifikasi terkirim ({kind})")
    else:
        warn(f"Gagal mengirim notifikasi ({kind})")
    return ok_


def notify_multi(channels: List[dict], base: str, findings: List[dict]) -> int:
    """Kirim ke banyak kanal. channels = [{"url": ..., "kind": ...}].
    kind "email" memakai field smtp_host/smtp_port/smtp_user/smtp_pass/smtp_to.
    Mengembalikan jumlah kanal yang berhasil."""
    sent = 0
    for ch in channels:
        kind = ch.get("kind", "auto") or "auto"
        if kind == "email":
            ok_ = send_email(ch.get("smtp_host", ""), ch.get("smtp_port", 0),
                             ch.get("smtp_user", ""), ch.get("smtp_pass", ""),
                             ch.get("smtp_to", ""), base, findings)
        elif kind == "pagerduty":
            ok_ = send_pagerduty(ch.get("url", ""), base, findings)
        else:
            ok_ = notify(ch.get("url", ""), kind, base, findings)
        if ok_:
            sent += 1
    return sent
