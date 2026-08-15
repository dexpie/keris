"""Fuzzing parameter sederhana: isi nilai berbahaya ke param umum dan pantau respons.

Fuzzer ini bersifat non-destruktif dan digunakan untuk menemukan refleksi
parameter atau anomali status (500/terkonfirmasi vuln oleh payload lain).
"""

import re
from typing import List
from urllib.parse import parse_qsl, urlencode, urlparse

from keris.core.http import KerisHTTP
from keris.core.logger import debug, info, warn
from keris.modules.scanner import Finding

# Nilai uji untuk fuzz: menangkap refleksi & error
FUZZ_VALUES = {
    "reflected": '<script>alert("keris")</script>',
    "sqli": "' OR '1'='1",
    "lfi": "../../../../etc/passwd",
    "redirect": "https://evil.example.com",
    "json": '{"__proto__": {"polluted": true}}',
}

INTERESTING_PARAMS = [
    "id", "page", "user", "username", "email", "search", "q", "query", "file",
    "path", "url", "redirect", "callback", "next", "lang", "page_id",
    "product", "item", "category", "sort", "order", "limit", "offset",
]


def _interest_score(text: str, baseline: str = "") -> int:
    """Skor indikator yang MUNCUL dari payload (dibanding baseline).

    Marker yang sudah ada di respons normal (mis. tag `<script>` halaman itu
    sendiri) TIDAK dihitung, supaya halaman HTML biasa tidak meledak menjadi
    temuan.
    """
    score = 0
    if "<script" in text and "<script" not in baseline:
        score += 3
    if "alert(" in text and "alert(" not in baseline:
        score += 3
    if "OR '1'='1" in text and "OR '1'='1" not in baseline:
        score += 2
    if "/etc/passwd" in text and "/etc/passwd" not in baseline:
        score += 2
    if "evil.example.com" in text and "evil.example.com" not in baseline:
        score += 1
    if re.search(r"SQL syntax|mysql_|ORA-|PostgreSQL|syntax error", text, re.IGNORECASE) and \
            not re.search(r"SQL syntax|mysql_|ORA-|PostgreSQL|syntax error", baseline, re.IGNORECASE):
        score += 2
    if re.search(r"Fatal error|Warning:|Uncaught", text) and \
            not re.search(r"Fatal error|Warning:|Uncaught", baseline):
        score += 1
    return score


def fuzz_parameters(base: str, client: KerisHTTP, endpoints: List[str], max_per_endpoint: int = 8) -> List[Finding]:
    """Fuzz parameter pada endpoint yang memiliki query string."""
    findings = []
    # sertakan base URL sendiri jika membawa query string
    candidates = list(endpoints)
    if "?" in base:
        candidates.append(base)
    base_clean = base.rstrip("/")
    for ep in candidates:
        full = ep if ep.startswith("http") else base_clean + ep
        if "?" not in full:
            continue
        url = urlparse(full)
        params = dict(parse_qsl(url.query))
        if not params:
            continue
        for name, orig in list(params.items())[:max_per_endpoint]:
            # baseline
            try:
                r0 = client.get(full, timeout=10)
                baseline_status = r0.status_code
                baseline_text = r0.text
            except Exception:
                baseline_status = 0
                baseline_text = ""
            for label, value in FUZZ_VALUES.items():
                new_qs = dict(params)
                new_qs[name] = value
                fuzz_url = f"{url.scheme}://{url.netloc}{url.path}?{urlencode(new_qs)}"
                try:
                    r = client.get(fuzz_url, timeout=10)
                except Exception:
                    continue
                score = _interest_score(r.text, baseline_text)
                reflected = value in r.text
                # refleksi harus benar-benar baru (nilai payload tidak ada di baseline)
                reflected = reflected and value not in baseline_text
                if reflected or score >= 3 or (r.status_code == 500 and baseline_status != 500):
                    sev = "MEDIUM" if reflected and "<script" in value else "LOW"
                    findings.append(Finding(
                        sev, "Refleksi/anomali parameter (perlu verifikasi manual)",
                        full,
                        f"Parameter `{name}` dengan payload `{label}`: status {r.status_code}, "
                        f"reflected={reflected}, interest={score}.",
                        f"payload: {value[:100]}; status: {r.status_code}",
                    ))
                    debug(f"  fuzz {name}={label} -> status {r.status_code} reflected={reflected}")
                    break  # cukup satu sinyal per parameter
    return findings


def fuzz_cmdi_ssti(base: str, client: KerisHTTP, endpoints: List[str]) -> List[Finding]:
    """Fuzz command injection & SSTI pada parameter query."""
    from keris.payloads import CMDI_PAYLOADS, CMDI_OUTPUT_MARKERS, SSTI_PAYLOADS, SSTI_MARKERS

    findings = []
    base_clean = base.rstrip("/")
    candidates = list(endpoints)
    if "?" in base:
        candidates.append(base)
    for ep in candidates:
        full = ep if ep.startswith("http") else base_clean + ep
        if "?" not in full:
            continue
        url = urlparse(full)
        params = dict(parse_qsl(url.query))
        for name in list(params.keys())[:5]:
            # baseline halaman tanpa payload untuk membedakan refleksi evaluasi
            q0 = dict(params)
            q0.pop(name, None)
            try:
                r0 = client.get(f"{url.scheme}://{url.netloc}{url.path}?{urlencode(q0)}", timeout=15)
                base_body = r0.text
            except Exception:
                base_body = ""
            # CMDI: kirim payload, cek marker output OS (uid=, root:x, dll)
            for payload in CMDI_PAYLOADS[:6]:
                new_qs = dict(params)
                new_qs[name] = payload
                try:
                    r = client.get(f"{url.scheme}://{url.netloc}{url.path}?{urlencode(new_qs)}", timeout=15)
                except Exception:
                    continue
                low = r.text.lower()
                if any(m in low for m in CMDI_OUTPUT_MARKERS):
                    findings.append(Finding(
                        "HIGH", "Kemungkinan command injection",
                        full,
                        f"Parameter `{name}` dengan payload `{payload}` merefleksikan output "
                        "perintah (uid/gid). Verifikasi manual.",
                        f"payload: {payload}",
                    ))
                    debug(f"  CMDI sinyal: {name}={payload}")
                    break
            # SSTI: cek refleksi hasil evaluasi template
            for payload in SSTI_PAYLOADS[:6]:
                new_qs = dict(params)
                new_qs[name] = payload
                try:
                    r = client.get(f"{url.scheme}://{url.netloc}{url.path}?{urlencode(new_qs)}", timeout=15)
                except Exception:
                    continue
                if "7*7" in payload:
                    # hasil evaluasi 49 yang BARU (tidak ada di baseline), payload tidak mentah
                    if "49" in r.text and "49" not in base_body and payload not in r.text:
                        findings.append(Finding(
                            "HIGH", "Kemungkinan Server-Side Template Injection (SSTI)",
                            full,
                            f"Parameter `{name}` dengan payload `{payload}` tampak dievaluasi "
                            "sebagai template (refleksi 49). Verifikasi manual.",
                            f"payload: {payload}",
                        ))
                        debug(f"  SSTI sinyal: {name}={payload}")
                        break
    return findings
