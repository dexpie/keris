"""Sensitive data exposure scan.

Memindai respons endpoint untuk paparan data sensitif:
- kredensial / token (API key, AWS, JWT)
- data pribadi (email, nomor telepon)
- keuangan (kartu kredit)
- file konfigurasi yang bocor (password=, secret=, db config)

Berhati-hati dengan false positive: hanya melaporkan bila pola muncul di
endpoint yang masuk akal (bukan halaman statis umum) atau dengan konteks
keyword (secret, password, key, token).
"""

import re
from typing import Dict, List, Optional

import requests

from keris.core.http import KerisHTTP
from keris.core.logger import debug, info, ok, warn
from keris.modules.scanner import Finding
from keris.payloads import SECRET_PATTERNS

# Pola data sensitif + severity
SENSITIVE_PATTERNS = [
    ("Email", r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", "LOW"),
    ("Nomor telepon", r"(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{2,4}\)?[-.\s]?)?\d{3,4}[-.\s]?\d{4,6}", "LOW"),
    ("Kartu kredit (visa)", r"\b4[0-9]{12}(?:[0-9]{3})?\b", "HIGH"),
    ("Kartu kredit (mastercard)", r"\b5[1-5][0-9]{14}\b", "HIGH"),
    ("Nomor Jaminan Sosial", r"\b\d{3}-\d{2}-\d{4}\b", "HIGH"),
]

# Keyword konteks yang menaikkan urgensi temuan
SENSITIVE_CONTEXT = ["password", "passwd", "secret", "api_key", "apikey",
                     "token", "private", "authorization", "credential", "db_"]

# Path yang TIDAK menarik untuk scan (statis/meta)
_SKIP_PATH = re.compile(r"\.(js|css|png|jpg|jpeg|gif|svg|woff2?|ico|map)$", re.I)


def _scan_body(text: str) -> List[Dict]:
    hits = []
    for name, pattern, sev in SENSITIVE_PATTERNS:
        try:
            matches = re.findall(pattern, text)
        except re.error:
            continue
        for m in matches:
            hits.append({"name": name, "severity": sev, "match": m})
    for name, pattern in SECRET_PATTERNS.items():
        for m in re.findall(pattern, text):
            hits.append({"name": name, "severity": "HIGH", "match": m})
    return hits


def check_sensitive(base: str, client: KerisHTTP,
                    endpoints: Optional[List[str]] = None) -> List[Finding]:
    """Scan paparan data sensitif pada endpoint yang diberikan."""
    findings: List[Finding] = []
    targets = endpoints or ["/"]
    if not any(t in targets for t in ["/", "/index.html"]):
        targets = targets + ["/"]

    for ep in targets[:40]:
        if _SKIP_PATH.search(ep):
            continue
        url = base.rstrip("/") + ep if ep.startswith("/") else ep
        try:
            r = client.get(url, timeout=15)
        except requests.RequestException:
            continue
        if r.status_code != 200:
            continue
        ct = r.headers.get("content-type", "").lower()
        if "json" not in ct and "html" not in ct and "text" not in ct and "xml" not in ct:
            continue
        body = r.text[:200000]
        low = body.lower()

        # context boost: hanya laporkan bila ada keyword sensitif ATAU data finansial/SSN
        has_context = any(k in low for k in SENSITIVE_CONTEXT)
        hits = _scan_body(body)

        reported = set()
        for h in hits:
            key = (h["name"], h["match"][:40])
            if key in reported:
                continue
            reported.add(key)
            is_secret = h["name"] in SECRET_PATTERNS
            sev = h["severity"]
            if not is_secret and not has_context and sev == "LOW":
                continue  # email/telepon tanpa konteks = false positive besar
            findings.append(Finding(
                sev,
                f"Data sensitif ter-expose: {h['name']}",
                url,
                f"Pola `{h['name']}` ditemukan pada respons. "
                f"{'Periksa apakah ini kredensial/secret nyata.' if is_secret else 'Kurangi paparan data pribadi (least privilege).'}",
                h["match"][:300],
            ))
            warn(f"[{sev}] {h['name']} pada {url}")

    if not findings:
        info("Tidak ada data sensitif yang terdeteksi")
    return findings
