"""Wayback machine URL mining (pasif, tanpa menyentuh target).

Dua API:
- `fetch_wayback_urls` + `extract_interesting`: dipakai subcommand `wayback`
  (URL historis dari CDX API archive.org).
- `mine_urls` + `wayback_findings`: dipakai flag `scan --wayback` untuk
  menghasilkan temuan di dalam report.
"""

import json
from typing import Dict, List, Optional
from urllib.parse import urlencode

import requests

from keris.core.logger import debug, info, ok, warn
from keris.modules.scanner import Finding
from keris.core.utils import host_from_url

CDX_API = "https://web.archive.org/cdx/search/cdx"


# ---------------------------------------------------------------------------
# API subcommand `wayback` (versi asli)
# ---------------------------------------------------------------------------
def fetch_wayback_urls(domain: str, limit: int = 200,
                       timeout: float = 30.0) -> List[dict]:
    """Ambil daftar URL historis dari CDX API archive.org."""
    params = {
        "url": f"*.{domain}",
        "output": "json",
        "fl": "timestamp,original,statuscode,mimetype,digest",
        "filter": "statuscode:200",
        "collapse": "urlkey",
        "limit": limit,
    }
    url = f"{CDX_API}?{urlencode(params)}"
    info(f"Querying Wayback CDX untuk {domain} ...")
    try:
        r = requests.get(url, timeout=timeout, headers={
            "User-Agent": "Mozilla/5.0 (Keris security scanner)",
        })
        if r.status_code != 200:
            warn(f"Wayback CDX status {r.status_code}")
            return []
        data = r.json()
    except (requests.RequestException, ValueError, json.JSONDecodeError) as e:
        warn(f"Wayback CDX gagal: {e}")
        return []

    if not data or not isinstance(data, list) or len(data) < 2:
        warn("Tidak ada hasil dari Wayback")
        return []

    headers = data[0]
    idx = {h: i for i, h in enumerate(headers)}
    results = []
    for row in data[1:]:
        entry = {h: (row[i] if i < len(row) else "") for h, i in idx.items()}
        results.append(entry)
    ok(f"URL historis ditemukan: {len(results)}")
    return results


def extract_interesting(entries: List[dict]) -> List[str]:
    """Ekstrak URL/endpoint yang menarik: API, file sensitif, param tersembunyi."""
    interesting = []
    keywords = ("/api/", "/v1/", "/v2/", "admin", "backup", ".env", ".git",
                "config", "debug", "swagger", ".sql", ".zip", ".bak", "token",
                "secret", "password", "upload", "internal")
    for e in entries:
        original = e.get("original", "")
        mime = e.get("mimetype", "").lower()
        low = original.lower()
        if any(k in low for k in keywords) or "javascript" in mime:
            interesting.append(original)
    seen = set()
    uniq = []
    for u in interesting:
        if u not in seen:
            seen.add(u)
            uniq.append(u)
    return uniq


# ---------------------------------------------------------------------------
# API flag `scan --wayback` (menghasilkan temuan)
# ---------------------------------------------------------------------------
def _interesting(path: str) -> bool:
    low = path.lower()
    keywords = ("admin", "login", "signin", "api", "config", "backup", "bak",
                "env", "dashboard", "upload", "console", "debug", "test",
                "internal", "staging", "dev", "panel", "cpanel", "phpmyadmin",
                ".git", ".env", "swagger", "openapi", "graphql", "ws",
                "export", "dump", "restore", "private")
    return any(k in low for k in keywords)


def mine_urls(base: str, limit: int = 500, timeout: int = 30) -> Dict:
    """Mining URL historis. Kembalikan dict {urls, interesting, count}."""
    host = host_from_url(base)
    info(f"=== WAYBACK MINING ({host}) ===")
    entries = fetch_wayback_urls(host, limit=limit, timeout=timeout)
    urls = list(dict.fromkeys(e.get("original", "") for e in entries if e.get("original")))
    if not urls:
        warn("Tidak ada data Wayback untuk host ini")
        return {"urls": [], "interesting": [], "count": 0}

    interesting = [u for u in urls if _interesting(u)]
    ok(f"Wayback: {len(urls)} URL unik, {len(interesting)} menarik")
    debug("Contoh: " + ", ".join(urls[:5]))
    return {"urls": urls, "interesting": interesting, "count": len(urls)}


def wayback_findings(base: str, result: Dict) -> List[Finding]:
    """Buat temuan dari hasil mining."""
    interesting = result.get("interesting", [])
    urls = result.get("urls", [])
    if not interesting:
        return []
    return [Finding(
        "MEDIUM", "Aset historis rentan ditemukan via Wayback",
        base,
        f"Wayback machine menyimpan {len(urls)} URL target; "
        f"{len(interesting)} di antaranya menarik bagi penyerang "
        "(admin/api/backup/env/dll). Contoh: {', '.join(interesting[:6])}.",
        f"total: {len(urls)}, menarik: {len(interesting)}",
    )]