"""Confidence engine Keris.

Memberi skor keyakinan (0..1) pada setiap temuan berdasarkan:
- sumber modul: modul yang menghasilkan bukti langsung (browser rendering,
  exploit terkonfirmasi, SSRF callback, git dump) lebih tinggi daripada
  deteksi heuristik (fuzzing, header, cookie)
- kualitas evidence: respons mencerminkan payload, status code, atau bukti
  lain di evidence menaikkan skor
- bahasa temuan: kata "potensial"/"kemungkinan"/"indicated"/"possible"
  menurunkan skor; kata "terkonfirmasi"/"confirmed" menaikkan

Skor dipetakan ke label: confirmed (>=0.9), high (>=0.7), medium (>=0.4),
low (<0.4). Skor default tanpa bukti: 0.5.
"""

import re
from typing import Dict, List

# basis keyakinan per sumber modul
SOURCE_BASE = {
    "browser": 0.92,        # hasil render headless browser: DOM XSS terkonfirmasi
    "correlation": 0.85,    # chain dari temuan yang sudah ada
    "cloud-aws": 0.9,       # bucket/credential terverifikasi langsung
    "cloud-s3": 0.9,
    "cloud-gcp": 0.9,
    "cloud-azure": 0.9,
    "hunt-git": 0.95,       # .git index/config terunduh langsung
    "hunt-config": 0.85,
    "hunt-secret": 0.8,
    "ssrf": 0.85,           # callback/out-of-band terkonfirmasi
    "exploit": 0.9,         # payload ter-eksekusi (RCE/SQLi dump)
    "cve": 0.7,             # banner-matching CVE
    "jwt": 0.75,
    "tls": 0.85,            # analisis sertifikat langsung
    "wayback": 0.5,         # pasif, perlu verifikasi
    "fuzz": 0.35,           # heuristik kuat
    "plugin": 0.6,
    "correlation-chain": 0.85,
}

DEFAULT_SOURCE_BASE = 0.5

# penanda bahasa yang menurunkan keyakinan
WEAKEN = (
    "potensial", "kemungkinan", "mungkin", "indicated", "possible",
    "sinyal", "perlu verifikasi", "candidate", "suspected", "tes awal",
)

# penanda yang menaikkan keyakinan
STRENGTHEN = (
    "terkonfirmasi", "confirmed", "berhasil", "executed", "validated",
    "verified", "dump", "bocor", "exposed", "terverifikasi",
)

_EVIDENCE_STRONG = (
    "HTTP/1.1", "status_code", "Status", "response", "payload", "200",
    "Location:", "Set-Cookie", "<script", "root:", "x-amz-", "aws",
)

_TITLE_RE = re.compile(r"[^\w\s]", re.UNICODE)


def _evidence_strength(f: Dict) -> float:
    ev = str(f.get("evidence", "") or "")
    if not ev:
        return 0.0
    hits = sum(1 for m in _EVIDENCE_STRONG if m.lower() in ev.lower())
    if hits >= 4:
        return 0.2
    if hits >= 2:
        return 0.1
    if hits >= 1:
        return 0.05
    return 0.0


def score_finding(f: Dict, source: str = "") -> Dict:
    """Hitung confidence untuk satu temuan dict. Mengembalikan salinan."""
    out = dict(f)
    src = (source or str(f.get("source", "")) or "").strip().lower()
    base = SOURCE_BASE.get(src, DEFAULT_SOURCE_BASE)

    text = " ".join([str(f.get("title", "")), str(f.get("detail", ""))]).lower()
    for w in WEAKEN:
        if w in text:
            base -= 0.15
            break
    for s in STRENGTHEN:
        if s in text:
            base += 0.1
            break

    base += _evidence_strength(f)

    # severity tidak mengubah confidence secara langsung, tapi INFO/LOW
    # tanpa bukti di-cap rendah
    sev = str(f.get("severity", "INFO")).upper()
    if sev in ("INFO", "LOW") and base > 0.6 and not f.get("evidence"):
        base = min(base, 0.6)

    score = round(max(0.05, min(0.99, base)), 2)
    out["confidence"] = score
    out["confidence_label"] = _label(score)
    return out


def _label(score: float) -> str:
    if score >= 0.9:
        return "confirmed"
    if score >= 0.7:
        return "high"
    if score >= 0.4:
        return "medium"
    return "low"


def assign_confidence(findings: List[Dict], source: str = "") -> List[Dict]:
    """Berikan confidence ke semua temuan (dict). Non-destruktif."""
    return [score_finding(f, source) for f in findings]


def aggregate_confidence(findings: List[Dict]) -> Dict:
    """Agregat keyakinan seluruh temuan.

    Mengembalikan rata-rata tertimbang per label + temuan dengan skor
    terendah (kandidat untuk verifikasi manual).
    """
    if not findings:
        return {"avg": 0.0, "by_label": {}, "verify_first": []}
    scored = [float(f.get("confidence", 0.5) or 0.5) for f in findings]
    by_label = {}
    for f in findings:
        label = str(f.get("confidence_label", "")).lower() or _label(float(f.get("confidence", 0.5)))
        by_label[label] = by_label.get(label, 0) + 1
    avg = round(sum(scored) / len(scored), 2)
    verify = sorted(
        [{"id": f.get("id", ""), "title": f.get("title", ""),
          "endpoint": f.get("endpoint", ""), "confidence": float(f.get("confidence", 0.5))}
         for f in findings if float(f.get("confidence", 0.5)) < 0.4],
        key=lambda x: x["confidence"],
    )[:5]
    return {"avg": avg, "by_label": by_label, "verify_first": verify}