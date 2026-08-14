"""Host header injection: manipulasi nilai Host/absolute URL.

Teknik yang diuji:
- Refleksi Host ke dalam respons (link absolut, redirect, script src).
- Absolute URL di Location saat redirect — dapat dikendalikan penyerang
  (dipakai password-reset poisoning).
- Perbedaan perilaku terhadap Host aneh (routing virtual host) — tanda
  bahwa server memproses nilai Host tanpa validasi.
"""

from typing import Dict, List, Optional

import requests

from keris.core.http import KerisHTTP
from keris.core.logger import info, ok, warn
from keris.modules.scanner import Finding

# Kandidat nilai Host uji (payload)
HOST_PAYLOADS = [
    "evil.example.com",
    "keris.hostheader.invalid",
    "127.0.0.1",
    "example.com:443",
]

# Endpoint yang relevan untuk password-reset / redirect poisoning
SENSITIVE_PATHS = [
    "/", "/login", "/forgot-password", "/reset-password", "/account",
    "/api/auth/forgot-password", "/api/auth/reset-password",
]


def _body_contains(body: str, value: str) -> bool:
    return value in body


def check_host_header(base: str, client: KerisHTTP,
                      paths: Optional[List[str]] = None) -> List[Finding]:
    """Deteksi host header injection pada target."""
    findings: List[Finding] = []
    candidates = paths or SENSITIVE_PATHS
    reflected: List[Dict] = []
    for path in candidates:
        url = base.rstrip("/") + path
        for payload in HOST_PAYLOADS:
            try:
                r = client.get(url, headers={"Host": payload}, timeout=15,
                               allow_redirects=False)
            except requests.RequestException:
                continue
            body = r.text[:20000]
            loc = r.headers.get("Location", "")
            if _body_contains(body, payload) or payload in loc:
                reflected.append({
                    "path": path,
                    "payload": payload,
                    "status": r.status_code,
                    "location": loc,
                    "in_body": payload in body,
                })
                ok(f"Refleksi Host '{payload}' pada {path} (status {r.status_code})")
                break

    if not reflected:
        warn("Tidak ada refleksi nilai Host yang terdeteksi")
        return findings

    for r in reflected:
        sev = "HIGH" if ("forgot" in r["path"] or "reset" in r["path"]) else "MEDIUM"
        detail = (
            f"Nilai `Host: {r['payload']}` direfleksikan pada `{r['path']}` "
            f"(body={r['in_body']}). "
        )
        if "forgot" in r["path"] or "reset" in r["path"]:
            detail += (
                "Endpoint password-reset yang merefleksikan host rentan terhadap "
                "**password reset poisoning**: penyerang memalsukan Host untuk "
                "mengarahkan link reset ke domainnya sendiri dan mencuri token. "
            )
        detail += (
            "Verifikasi apakah nilai tersebut dipakai untuk membangun URL absolut "
            "atau mengirim email."
        )
        findings.append(Finding(
            sev,
            "Host header injection",
            base.rstrip("/") + r["path"],
            detail,
            f"payload={r['payload']}, status={r['status']}, "
            f"location={r['location'][:200] or 'n/a'}",
        ))
        warn(f"[{sev}] Refleksi Host '{r['payload']}' pada {r['path']}")

    return findings
