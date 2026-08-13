"""Wayback/Archive history: ambil URL historis dari CDX API archive.org.

Berguna untuk menemukan endpoint lama, file yang dihapus (bocor), parameter
tersembunyi, atau teknologi yang sudah berganti.
"""

import json
from typing import List, Optional
from urllib.parse import urlencode

import requests

from keris.core.logger import debug, info, ok, warn

CDX_API = "http://web.archive.org/cdx/search/cdx"


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
    # dedup menjaga urutan
    seen = set()
    uniq = []
    for u in interesting:
        if u not in seen:
            seen.add(u)
            uniq.append(u)
    return uniq
