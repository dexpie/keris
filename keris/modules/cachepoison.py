"""Web cache poisoning: deteksi manipulasi header untuk meracuni cache CDN/proxy.

Teknik yang diuji:
- Header host-reflection: X-Forwarded-Host / X-Host / X-Forwarded-Server / Host
  yang direfleksikan ke dalam respons (link absolut, meta tag, script src).
- Perubahan konten dengan header unik: bila respons berubah mengikuti header,
  dan halaman punya penanda cacheable (Age, X-Cache, Cache-Control), maka
  penyerang dapat mengirim payload sekali ke cache dan semua pengunjung
  menerima versi teracuni.
"""

import re
from typing import Dict, List, Optional
from urllib.parse import urlparse

import requests

from keris.core.http import KerisHTTP
from keris.core.logger import debug, info, ok, warn
from keris.modules.scanner import Finding

# Header yang sering di-refleksikan dan dijadikan basis cache
POISON_HEADERS = [
    "X-Forwarded-Host",
    "X-Host",
    "X-Forwarded-Server",
    "X-Forwarded-Proto",
    "X-Original-URL",
    "X-Rewrite-URL",
    "X-Forwarded-Port",
]

# Penanda bahwa respons di-cache (CDN/proxy)
CACHE_INDICATORS = (
    "age", "x-cache", "x-cache-status", "x-served-by", "cf-cache-status",
    "x-vercel-cache", "x-nginx-cache", "x-hs-cache", "x-fastly-cache",
    "x-qc-cache", "x-goog-cache", "x-akamai", "x-amz-cf-id", "x-cache-hits",
)

# Halaman yang umum di-cache dan membawa link absolut hasil refleksi host
CACHEABLE_PATH_HINTS = [
    "/", "/index.html", "/home", "/help", "/support", "/about", "/landing",
]

PAYLOAD = "keris-cachepoison-12345"

# Meta/HTML yang mengandung host reflect
_REFLECT_PATTERNS = [
    re.compile(r'content="http[s]?://([^"/]+)', re.I),
    re.compile(r'(?:src|href|action)="//([^"/]+)', re.I),
    re.compile(r'(?:src|href|action)="http[s]?://([^"/]+)', re.I),
]


def _is_cachable(r: requests.Response) -> bool:
    """Apakah respons tampak di-cache (header cache + tidak no-store)."""
    cc = (r.headers.get("Cache-Control") or "").lower()
    if "no-store" in cc or "no-cache" in cc:
        return False
    for h in r.headers:
        if h.lower() in CACHE_INDICATORS:
            return True
    if "public" in cc and "max-age" in cc:
        return True
    return False


def _body_reflects(body: str, value: str) -> bool:
    """Apakah nilai header muncul di body respons (potensi poison)."""
    return value in body


def _fetch(base: str, client: KerisHTTP, headers: Dict[str, str]) -> Optional[requests.Response]:
    try:
        return client.get(base, headers=headers, timeout=15)
    except requests.RequestException:
        return None


def check_cache_poisoning(base: str, client: KerisHTTP,
                          paths: Optional[List[str]] = None) -> List[Finding]:
    """Deteksi potensi web cache poisoning pada target."""
    findings: List[Finding] = []
    candidates = paths or CACHEABLE_PATH_HINTS

    # baseline: respons normal tanpa header tambahan
    baseline = None
    try:
        baseline = client.get(base, timeout=15)
    except requests.RequestException:
        warn("Tidak bisa mengambil halaman utama; lewati cache poisoning")
        return findings

    if not _is_cachable(baseline):
        info("Halaman utama tidak tampak cacheable; tetap coba subset")
        cacheable = False
    else:
        cacheable = True
        ok("Halaman utama cacheable (ada penanda CDN/cache)")

    reflected: List[Dict] = []
    for path in candidates:
        url = base.rstrip("/") + path
        for hdr in POISON_HEADERS:
            resp = _fetch(url, client, {hdr: PAYLOAD})
            if not resp:
                continue
            body = resp.text[:20000]
            if _body_reflects(body, PAYLOAD):
                reflected.append({
                    "path": path,
                    "header": hdr,
                    "status": resp.status_code,
                    "cacheable": _is_cachable(resp),
                })
                ok(f"Refleksi header {hdr} pada {path} (status {resp.status_code})")
                break  # satu header per path cukup
        else:
            continue

    if not reflected:
        warn("Tidak ada refleksi header host yang terdeteksi")
        return findings

    poisoned = [r for r in reflected if r["cacheable"] or cacheable]
    for r in reflected:
        sev = "HIGH" if (r["cacheable"] or cacheable) else "MEDIUM"
        findings.append(Finding(
            sev,
            "Web cache poisoning (refleksi header di-respons)",
            base.rstrip("/") + r["path"],
            f"Header `{r['header']}` direfleksikan ke respons pada `{r['path']}`. "
            f"Respons {'tampak cacheable' if r['cacheable'] else 'TIDAK tampak cacheable'}. "
            "Bila di-cache oleh CDN/proxy, penyerang dapat menyuntikkan payload "
            "sekali dan seluruh pengunjung menerima versi teracuni (stored XSS).",
            f"header={r['header']}, path={r['path']}, status={r['status']}, "
            f"cacheable={r['cacheable']}",
        ))
        warn(f"[{sev}] Refleksi {r['header']} pada {r['path']}")

    if not poisoned and reflected:
        info("Refleksi ada tapi tidak ada penanda cache; verifikasi manual diperlukan")
    return findings
