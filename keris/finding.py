"""Standard Finding Schema untuk Keris.

Menormalkan seluruh temuan (dari modul mana pun) ke bentuk standar dengan
skema versi. Tujuannya agar output JSON, SARIF, dan laporan konsisten serta
bisa dibaca oleh tool eksternal.

Skema v1.0.0 memuat field inti (severity, title, endpoint, detail, evidence)
ditambah metadata analitik: id deterministik, source, cwe, references,
confidence (0..1), confidence_label, cvss, owasp, tags.
"""

import hashlib
from datetime import datetime
from typing import Dict, List

SCHEMA_VERSION = "1.0.0"
FINDING_LEVELS = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")

REQUIRED_FIELDS = ("severity", "title", "endpoint", "detail", "evidence")

DEFAULT_FIELDS = {
    "severity": "INFO",
    "title": "",
    "endpoint": "",
    "detail": "",
    "evidence": "",
    "cwe": "",
    "references": "",
    "chain": "",
    "source": "",
}

CONFIDENCE_LABELS = {
    "confirmed": "Terkonfirmasi (bukti langsung)",
    "high": "Keyakinan tinggi",
    "medium": "Keyakinan sedang",
    "low": "Indikasi awal",
}


def _fingerprint(f: Dict) -> str:
    """Hash deterministik endpoint+title+evidence (tanpa timestamp)."""
    key = "|".join([
        str(f.get("endpoint", "")),
        str(f.get("title", "")),
        str(f.get("detail", "")),
        str(f.get("evidence", ""))[:300],
    ])
    return hashlib.sha1(key.encode("utf-8", "replace")).hexdigest()[:16]


def normalize_finding(f: Dict) -> Dict:
    """Normalisasi satu temuan dict ke bentuk standar."""
    out = {}
    for k, default in DEFAULT_FIELDS.items():
        out[k] = f.get(k, default) if f.get(k, default) is not None else default

    sev = str(out["severity"] or "INFO").upper()
    if sev not in FINDING_LEVELS:
        sev = "INFO"
    out["severity"] = sev

    out["id"] = _fingerprint(out)
    out["schema_version"] = SCHEMA_VERSION
    out["confidence"] = float(f.get("confidence", 0.5) or 0.5)
    out["confidence_label"] = f.get("confidence_label", "") or _label_for(out["confidence"])

    # metadata optional yang ikut tersimpan bila ada
    for opt in ("cvss", "owasp", "tags", "recommendation"):
        if opt in f and f[opt]:
            out[opt] = f[opt]
    return out


def _label_for(score: float) -> str:
    if score >= 0.9:
        return "confirmed"
    if score >= 0.7:
        return "high"
    if score >= 0.4:
        return "medium"
    return "low"


def normalize_findings(findings: List[Dict]) -> List[Dict]:
    """Normalisasi daftar temuan (dict)."""
    return [normalize_finding(f) for f in findings]


def to_standard(f: Dict) -> Dict:
    """Alias normalized: terima dict atau objek dengan to_dict()."""
    if not isinstance(f, dict) and hasattr(f, "to_dict"):
        f = f.to_dict()
    return normalize_finding(f)


def summary(findings: List[Dict]) -> Dict:
    """Ringkasan jumlah temuan per severity + label confidence."""
    counts = {s: 0 for s in FINDING_LEVELS}
    conf = {"confirmed": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        s = str(f.get("severity", "INFO")).upper()
        if s in counts:
            counts[s] += 1
        label = str(f.get("confidence_label", "")).lower()
        if label in conf:
            conf[label] += 1
    return {
        "total": len(findings),
        "by_severity": counts,
        "by_confidence": conf,
        "generated_at": datetime.utcnow().isoformat() + "Z",
    }