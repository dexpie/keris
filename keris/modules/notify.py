"""Webhook notifikasi: kirim ringkasan temuan ke Slack/Discord/Telegram."""

import json
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
        elif kind == "telegram":
            tup = _telegram_from_url(webhook_url)
            if tup is None:
                warn("URL telegram harus berformat .../bot<TOKEN>/sendMessage?chat_id=<ID>")
                return False
            ok_ = send_telegram(tup[0], tup[1], base, findings)
        else:
            # coba deteksi otomatis dari URL
            if _telegram_from_url(webhook_url):
                tup = _telegram_from_url(webhook_url)
                ok_ = send_telegram(tup[0], tup[1], base, findings)
            elif "slack" in webhook_url:
                ok_ = send_slack(webhook_url, base, findings)
            elif "discord" in webhook_url or "discordapp" in webhook_url:
                ok_ = send_discord(webhook_url, base, findings)
    except Exception as e:
        warn(f"Webhook gagal: {e}")
        return False
    if ok_:
        ok(f"Notifikasi terkirim ({kind})")
    else:
        warn(f"Gagal mengirim notifikasi ({kind})")
    return ok_
