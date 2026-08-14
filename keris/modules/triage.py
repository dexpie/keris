"""AI triage + executive summary via an OpenAI-compatible chat API.

Optional: activated when an API key is available via env (KERIS_LLM_API_KEY
or OPENAI_API_KEY) or keris.json config `llm` block. Without a key the module
degrades gracefully to rule-based triage (no network).
"""

import json
import os
import re
from typing import Dict, List, Optional, Tuple

import requests

BASE_URL = os.environ.get("KERIS_LLM_BASE_URL", "https://api.openai.com/v1")
MODEL = os.environ.get("KERIS_LLM_MODEL", "gpt-4o-mini")

_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

_FP_PATTERNS = [
    (re.compile(r"test|example|sample|demo|placeholder|lorem", re.I), "LOW"),
    (re.compile(r"admin@example\.com|example\.org", re.I), "INFO"),
]

_RECO_DB = {
    "sql injection": "Gunakan parameterized queries / prepared statements; jangan concatenate input user ke SQL.",
    "xss": "Sanitize dan encode output di sisi server; terapkan Content-Security-Policy; validate input.",
    "csrf": "Terapkan token CSRF unik per-sesi pada semua form state-changing.",
    "open redirect": "Validasi redirect hanya ke allowlist domain internal; hindari parameter url/next/return.",
    "cors": "Batasi Access-Control-Allow-Origin ke origin spesifik; jangan refleksikan Origin.",
    "cookie": "Set Secure, HttpOnly, SameSite; pertimbangkan __Host- prefix.",
    "tls": "Nonaktifkan protokol/protokol cipher lemah; perbarui sertifikat.",
    "information disclosure": "Hapus header/internal path yang membocorkan detail versi & framework.",
    "rate limit": "Terapkan rate-limiting dan lockout per akun/IP pada endpoint auth.",
    "directory listing": "Nonaktifkan index listing; gunakan deny-by-default pada web server.",
    "backup": "Larang akses publik ke file backup/source; letakkan di luar document root.",
    "cache": "Gunakan header Cache-Control yang tepat; jangan cache respons yang bergantung header user.",
    "host header": "Validasi Host header terhadap allowlist; jangan refleksikan Host ke respons/link.",
    "jwt": "Gunakan secret kuat, verifikasi alg secara ketat, tambahkan exp/iat.",
    "sensitive": "Enkripsi data sensitif saat simpan & kirim; redact di log dan respons.",
    "auth": "Terapkan MFA, akun lockout, dan pengecekan otorisasi di sisi server untuk tiap resource.",
}


def _has_key(cfg: Dict) -> bool:
    return bool(
        os.environ.get("KERIS_LLM_API_KEY")
        or os.environ.get("OPENAI_API_KEY")
        or (cfg or {}).get("llm", {}).get("api_key")
    )


def _llm(messages: List[Dict], cfg: Dict, timeout: int = 60) -> Optional[str]:
    key = (
        os.environ.get("KERIS_LLM_API_KEY")
        or os.environ.get("OPENAI_API_KEY")
        or (cfg or {}).get("llm", {}).get("api_key")
    )
    if not key:
        return None
    base = os.environ.get("KERIS_LLM_BASE_URL", (cfg or {}).get("llm", {}).get("base_url") or BASE_URL)
    model = os.environ.get("KERIS_LLM_MODEL", (cfg or {}).get("llm", {}).get("model") or MODEL)
    try:
        r = requests.post(
            base.rstrip("/") + "/chat/completions",
            headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
            json={"model": model, "messages": messages, "temperature": 0.2},
            timeout=timeout,
        )
        r.raise_for_status()
        return r.json()["choices"][0]["message"]["content"]
    except Exception:
        return None


def _rule_based_triage(f: Dict) -> Dict:
    """Local heuristic: demote likely false positives / demo artifacts."""
    title = str(f.get("title", ""))
    endpoint = str(f.get("endpoint", ""))
    sev = str(f.get("severity", "INFO")).upper()
    for pat, demote in _FP_PATTERNS:
        if pat.search(title) or pat.search(endpoint):
            if _SEV_ORDER.get(sev, 5) < _SEV_ORDER.get(demote, 5):
                return {"status": "demoted", "reason": "Kemungkinan artefak demo/test", "severity": demote}
    return {"status": "kept", "reason": ""}


def triage_findings(findings: List[Dict], cfg: Optional[Dict] = None) -> Tuple[List[Dict], Optional[str]]:
    """Annotates findings with triage verdicts. Returns (annotated, raw LLM text).

    Every finding gets a `triage` dict: {"status", "reason", "severity"?}.
    When an LLM key is configured, the model reviews HIGH/CRITICAL findings and
    flags false positives. Without a key, rule-based triage is applied.
    """
    cfg = cfg or {}
    annotated = [dict(f) for f in findings]
    for f in annotated:
        verdict = _rule_based_triage(f)
        if _has_key(cfg) and _SEV_ORDER.get(str(f.get("severity", "INFO")).upper(), 5) <= 1:
            verdict = {"status": "pending_ai", "reason": ""}
        f["triage"] = verdict
    raw = None
    if not _has_key(cfg):
        return annotated, None
    high = [f for f in annotated if _SEV_ORDER.get(str(f.get("severity", "INFO")).upper(), 5) <= 1]
    if not high:
        return annotated, None
    prompt = (
        "Kamu adalah analis keamanan aplikasi web. Triage temuan berikut dari "
        "hasil scan otomatis. Untuk tiap temuan, putuskan apakah temuan ini "
        "false positive atau temuan asli, dan beri alasan singkat (Indonesia).\n"
        "Balas PERSIS dalam format JSON berikut tanpa teks lain:\n"
        '[{"title": "...", "verdict": "real"|"false_positive", '
        '"reason": "...", "severity": "CRITICAL"|"HIGH"|"MEDIUM"|"LOW"|"INFO"}]\n\n'
        + json.dumps([{
            "title": f.get("title", ""),
            "endpoint": f.get("endpoint", ""),
            "detail": f.get("detail", ""),
            "evidence": f.get("evidence", "")[:300],
        } for f in high], ensure_ascii=False, indent=1)
    )
    raw = _llm([{"role": "user", "content": prompt}], cfg)
    if raw:
        try:
            verdicts = json.loads(re.sub(r"```(?:json)?", "", raw).strip())
            by_title = {v.get("title"): v for v in verdicts}
            for f in annotated:
                v = by_title.get(f.get("title", ""))
                if v:
                    f["triage"] = {
                        "status": "kept" if v.get("verdict") == "real" else "demoted",
                        "reason": v.get("reason", ""),
                        "severity": v.get("severity") or f.get("severity"),
                        "ai": True,
                    }
        except Exception:
            pass
    return annotated, raw


def recommendation_for(title: str) -> str:
    low = title.lower()
    for key, rec in _RECO_DB.items():
        if key in low:
            return rec
    return "Lakukan validasi input & output, perkuat autentikasi/otorisasi, dan terapkan security headers sesuai best practice."


def executive_summary(findings: List[Dict], target: str, raw_ai: Optional[str] = None) -> str:
    """Builds an executive summary paragraph (Indonesian)."""
    kept = [f for f in findings if f.get("triage", {}).get("status") != "demoted"]
    real_crit = sum(1 for f in kept if f.get("severity", "").upper() == "CRITICAL")
    real_high = sum(1 for f in kept if f.get("severity", "").upper() == "HIGH")
    total = len(kept)
    demoted = sum(1 for f in findings if f.get("triage", {}).get("status") == "demoted")

    lines = [
        f"Scan terhadap **{target}** menemukan **{total} temuan asli** "
        f"({real_crit} CRITICAL, {real_high} HIGH).",
    ]
    if demoted:
        lines.append(f"{demoted} temuan berpotensi false positive/artefak demo telah ditandai.")
    if real_crit or real_high:
        lines.append(
            "Prioritas: segera perbaiki kerentanan kritis/high karena "
            "berisiko eksploitasi langsung oleh pihak luar."
        )
    else:
        lines.append("Tidak ada temuan kritis; fokus pada perbaikan bertahap dan penguatan hardening.")
    if raw_ai:
        lines.append(f"\n**Catatan AI:** {raw_ai[:500]}")
    return " ".join(lines)