"""Pemetaan temuan Keris ke CVSS v3.1 dan OWASP Top 10 (2021).

Setiap temuan di-scan dari keyword judul/severity lalu diberi:
- vector CVSS v3.1 (AV/AC/PR/UI/S/C/I/A) yang wajar
- kategori OWASP Top 10 2021 (A01..A10) dengan nama
- skor dasar CVSS yang dihitung dari vector

Fallback: bila tidak cocok, digunakan konfigurasi default berdasar severity
agar setiap temuan tetap punya skor.
"""

import math
from typing import Dict, List, Optional, Tuple

# (keyword, CVSS vector, OWASP code, OWASP name)
CLASSIFIERS = [
    # --- injection / code ---
    ("sql injection", "AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H", "A03", "Injection"),
    ("sqlite error", "AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H", "A03", "Injection"),
    ("sqli", "AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H", "A03", "Injection"),
    ("command injection", "AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H", "A03", "Injection"),
    ("ssti", "AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H", "A03", "Injection"),
    ("template injection", "AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H", "A03", "Injection"),
    ("xss", "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "A03", "Injection"),
    ("cross-site scripting", "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "A03", "Injection"),
    ("ldap injection", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "A03", "Injection"),
    ("xml injection", "AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", "A03", "Injection"),
    ("deserialization", "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "A08", "Software and Data Integrity Failures"),
    ("unserialize", "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "A08", "Software and Data Integrity Failures"),
    # --- authN / authZ ---
    ("auth bypass", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "A01", "Broken Access Control"),
    ("idor", "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", "A01", "Broken Access Control"),
    ("broken access", "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N", "A01", "Broken Access Control"),
    ("privilege escalation", "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", "A01", "Broken Access Control"),
    ("password reset", "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N", "A01", "Broken Access Control"),
    ("cors", "AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N", "A05", "Security Misconfiguration"),
    ("open redirect", "AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N", "A01", "Broken Access Control"),
    ("directory listing", "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "A05", "Security Misconfiguration"),
    # --- crypto / secrets / data ---
    ("jwt", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "A07", "Identification and Authentication Failures"),
    ("algorithm confusion", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "A07", "Identification and Authentication Failures"),
    ("weak secret", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "A07", "Identification and Authentication Failures"),
    ("secret", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "A05", "Security Misconfiguration"),
    ("api key", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "A05", "Security Misconfiguration"),
    ("sensitive data", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "A02", "Cryptographic Failures"),
    ("exposed", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "A05", "Security Misconfiguration"),
    ("bucket", "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N", "A05", "Security Misconfiguration"),
    # --- infrastructure / DoS ---
    ("rate limit", "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L", "A07", "Identification and Authentication Failures"),
    ("smuggling", "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "A09", "Security Logging and Monitoring Failures"),
    ("takeover", "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "A05", "Security Misconfiguration"),
    ("tls", "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N", "A02", "Cryptographic Failures"),
    ("waf", "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", "A05", "Security Misconfiguration"),
    ("header", "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "A05", "Security Misconfiguration"),
    ("cookie", "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "A05", "Security Misconfiguration"),
    ("ssrf", "AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N", "A10", "Server-Side Request Forgery"),
    ("server-side request", "AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N", "A10", "Server-Side Request Forgery"),
    ("graphql", "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L", "A05", "Security Misconfiguration"),
    ("websocket", "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N", "A05", "Security Misconfiguration"),
    ("cache", "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N", "A05", "Security Misconfiguration"),
    ("smuggling", "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "A09", "Security Logging and Monitoring Failures"),
    ("logging", "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", "A09", "Security Logging and Monitoring Failures"),
    ("monitoring", "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", "A09", "Security Logging and Monitoring Failures"),
]

# Default per severity bila tidak cocok dengan keyword
SEVERITY_FALLBACK = {
    "CRITICAL": ("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "A01", "Broken Access Control"),
    "HIGH": ("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "A01", "Broken Access Control"),
    "MEDIUM": ("AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N", "A05", "Security Misconfiguration"),
    "LOW": ("AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "A05", "Security Misconfiguration"),
    "INFO": ("AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", "A09", "Security Logging and Monitoring Failures"),
}


def _cvss_score(vector: str) -> float:
    """Hitung skor dasar CVSS v3.1 dari vector string."""
    parts = {}
    for item in vector.split("/"):
        k, _, v = item.partition(":")
        parts[k] = v

    def _g(key, default):
        return parts.get(key, default)

    av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}.get(_g("AV", "N"), 0.85)
    ac = {"L": 0.77, "H": 0.44}.get(_g("AC", "L"), 0.77)
    pr = {"N": 0.85, "L": 0.62, "H": 0.27}.get(_g("PR", "N"), 0.85)
    if _g("S", "U") == "C":  # scope changed: PR lebih berat
        pr = {"N": 0.85, "L": 0.68, "H": 0.5}.get(_g("PR", "N"), 0.85)
    ui = {"N": 0.85, "R": 0.62}.get(_g("UI", "N"), 0.85)
    c = {"H": 0.56, "L": 0.22, "N": 0.0}.get(_g("C", "N"), 0.0)
    i = {"H": 0.56, "L": 0.22, "N": 0.0}.get(_g("I", "N"), 0.0)
    a = {"H": 0.56, "L": 0.22, "N": 0.0}.get(_g("A", "N"), 0.0)

    iss = 1 - ((1 - c) * (1 - i) * (1 - a))
    if _g("S", "U") == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    exploitability = 8.22 * av * ac * pr * ui
    if impact <= 0:
        return 0.0
    if _g("S", "U") == "U":
        base = min(impact + exploitability, 10)
    else:
        base = min(1.08 * (impact + exploitability), 10)
    # CVSS v3.1 menggunakan roundup: pembulatan ke atas ke 1 desimal terdekat
    return math.ceil(base * 10) / 10


def _severity_from_score(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "INFO"


def classify(title: str, severity: str = "") -> Dict:
    """Klasifikasikan temuan ke CVSS & OWASP.

    Mengembalikan dict: {vector, score, severity, owasp_code, owasp_name}.
    """
    low = (title or "").lower()
    matched = None
    for keyword, vector, code, name in CLASSIFIERS:
        if keyword in low:
            matched = (vector, code, name)
            break
    if not matched:
        sev = (severity or "INFO").upper()
        matched = SEVERITY_FALLBACK.get(sev, SEVERITY_FALLBACK["INFO"])
    vector, code, name = matched
    score = _cvss_score(vector)
    # severity yang dilaporkan mengikuti label temuan (bukan turunan skor),
    # agar tidak ada kontradiksi antara badge temuan dan kolom CVSS.
    reported = (severity or "INFO").upper()
    if reported not in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        reported = "INFO"
    return {
        "vector": vector,
        "score": round(score, 1),
        "severity": reported,
        "owasp_code": code,
        "owasp_name": name,
    }


def map_findings(findings: List[Dict]) -> List[Dict]:
    """Salin temuan dan lampirkan kolom cvss/owasp."""
    out = []
    for f in findings:
        item = dict(f)
        item["cvss"] = classify(item.get("title", ""), item.get("severity", ""))
        out.append(item)
    return out


def owasp_summary(findings: List[Dict]) -> List[Dict]:
    """Ringkasan temuan per kategori OWASP Top 10."""
    counts = {}
    for f in findings:
        info = classify(f.get("title", ""), f.get("severity", ""))
        key = f"{info['owasp_code']} {info['owasp_name']}"
        counts.setdefault(key, 0)
        counts[key] += 1
    return [{"category": k, "count": v} for k, v in sorted(counts.items())]
