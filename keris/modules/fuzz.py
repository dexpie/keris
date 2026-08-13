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


def _interest_score(text: str) -> int:
    score = 0
    if "<script" in text or "</script>" in text:
        score += 3
    if "alert(" in text:
        score += 3
    if "OR '1'='1" in text or "' OR '" in text:
        score += 2
    if "/etc/passwd" in text:
        score += 2
    if "evil.example.com" in text:
        score += 1
    if re.search(r"SQL syntax|mysql_|ORA-|PostgreSQL|syntax error", text, re.IGNORECASE):
        score += 2
    if re.search(r"Fatal error|Warning:|Uncaught", text):
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
            except Exception:
                baseline_status = 0
            for label, value in FUZZ_VALUES.items():
                new_qs = dict(params)
                new_qs[name] = value
                fuzz_url = f"{url.scheme}://{url.netloc}{url.path}?{urlencode(new_qs)}"
                try:
                    r = client.get(fuzz_url, timeout=10)
                except Exception:
                    continue
                score = _interest_score(r.text)
                reflected = value in r.text
                if reflected or score >= 2 or (r.status_code == 500 and baseline_status != 500):
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
