"""Modul discovery: ekstraksi endpoint dari JS, secret scan, brute dir & subdomain."""

import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Set

import requests

from keris.core.http import KerisHTTP
from keris.core.logger import info, ok, warn, debug, severity
from keris.core.utils import extract_api_paths, extract_js_assets, urljoin, domain_from_host, host_from_url
from keris.payloads import SECRET_PATTERNS, SENSITIVE_PATHS

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")


def load_wordlist(name: str) -> List[str]:
    """Muat wordlist dari data/."""
    path = os.path.join(DATA_DIR, name)
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]


# Peta wordlist tambahan per stack teknologi yang terdeteksi
STACK_WORDLISTS = {
    "wordpress": ["dirs-wp.txt"],
    "laravel": ["dirs-laravel.txt"],
    "django": ["dirs-django.txt"],
    "node": ["dirs-node.txt"],
    "java": ["dirs-java.txt"],
    "spring": ["dirs-java.txt"],
    "express": ["dirs-node.txt"],
    "next": ["dirs-node.txt"],
    "react": ["dirs-node.txt"],
}


def detect_stack(recon: Dict) -> List[str]:
    """Deteksi stack teknologi dari hasil recon (headers/body/cookies)."""
    stacks = []
    hay = " ".join([
        str(recon.get("server", "")),
        str(recon.get("powered_by", "")),
        str(recon.get("generator", "")),
        " ".join(str(k) + ": " + str(v) for k, v in recon.get("headers", {}).items()),
    ]).lower()
    body = (recon.get("body", "") or "")[:4000].lower()
    if any(m in hay for m in ("wordpress", "wp-content", "wp-includes")) or "wp-content" in body:
        stacks.append("wordpress")
    if any(m in hay for m in ("laravel", "symfony", "php artisan")) or "csrf-token" in body:
        stacks.append("laravel")
    if any(m in hay for m in ("django", "csrftoken")) or "django" in body:
        stacks.append("django")
    if any(m in hay for m in ("node.js", "express", "next.js", "nuxt")):
        stacks.append("node")
    if any(m in hay for m in ("spring", "spring boot", "tomcat", "java/")) or "spring boot" in body:
        stacks.append("java")
    return stacks


def wordlists_for_stack(stacks: List[str]) -> List[str]:
    """Kumpulan nama wordlist tambahan untuk stack yang terdeteksi."""
    names = []
    for s in stacks:
        for wl in STACK_WORDLISTS.get(s, []):
            if wl not in names:
                names.append(wl)
    return names


def scan_js_for_secrets(text: str) -> List[dict]:
    """Cari pola secret di konten JS/HTML."""
    found = []
    for label, pattern in SECRET_PATTERNS.items():
        for m in re.finditer(pattern, text):
            found.append({"type": label, "match": m.group(0)[:80]})
    return found


def discover_endpoints(base: str, client: KerisHTTP, max_assets: int = 15) -> Dict:
    """Ekstrak endpoint API dan asset JS dari halaman utama + subpage."""
    info("Mengumpulkan asset JS dan endpoint API...")
    all_api: Set[str] = set()
    all_js: Set[str] = set()
    secrets: List[dict] = []

    # ambil halaman utama
    html_assets: Set[str] = set()
    try:
        r = client.get(base, timeout=25)
        html_assets = extract_js_assets(r.text, base)
        all_api.update(extract_api_paths(r.text))
        secrets.extend(scan_js_for_secrets(r.text))
        info(f"Asset JS dari halaman utama: {len(html_assets)}")
    except requests.RequestException as e:
        warn(f"Gagal ambil halaman utama: {e}")

    # tambahkan halaman umum lain (SSR/CSR)
    for path in ("/login", "/register", "/dashboard", "/admin", "/app"):
        try:
            r = client.get(base + path, timeout=15)
            if r.status_code == 200:
                html_assets.update(extract_js_assets(r.text, base))
                all_api.update(extract_api_paths(r.text))
                secrets.extend(scan_js_for_secrets(r.text))
        except requests.RequestException:
            pass

    # unduh asset JS untuk scan endpoint & secret
    downloaded = 0
    for js_url in sorted(html_assets):
        if downloaded >= max_assets:
            break
        try:
            r = client.get(js_url, timeout=20)
            if r.status_code == 200:
                all_api.update(extract_api_paths(r.text))
                secrets.extend(scan_js_for_secrets(r.text))
                all_js.add(js_url)
                downloaded += 1
        except requests.RequestException:
            continue

    # dedup secret
    unique_secrets = []
    seen = set()
    for s in secrets:
        key = (s["type"], s["match"])
        if key not in seen:
            seen.add(key)
            unique_secrets.append(s)

    ok(f"Endpoint API unik: {len(all_api)}")
    ok(f"Asset JS terunduh: {downloaded}")
    if unique_secrets:
        warn(f"Secret potensial ditemukan: {len(unique_secrets)}")
    return {
        "api_endpoints": sorted(all_api),
        "js_assets": sorted(all_js),
        "secrets": unique_secrets,
        "secret_count": len(unique_secrets),
    }


def brute_directories(base: str, client: KerisHTTP, max_workers: int = 10,
                      stacks: Optional[List[str]] = None) -> List[dict]:
    """Brute-force path sensitif. `stacks` = stack teknologi untuk wordlist pintar."""
    info("Menjalankan brute-force path sensitif...")
    wordlist = load_wordlist("dirs.txt")
    if not wordlist:
        wordlist = SENSITIVE_PATHS
    extra_names = wordlists_for_stack(stacks or [])
    for name in extra_names:
        extra = load_wordlist(name)
        if extra:
            wordlist = list(dict.fromkeys(wordlist + extra))
    if extra_names:
        ok(f"Wordlist pintar: +{sum(len(load_wordlist(n)) for n in extra_names)} path spesifik {', '.join(extra_names)}")
    found = []

    def check(path: str) -> Optional[dict]:
        # coba beberapa varian: path asli, trailing slash, dan query noise untuk mengalahkan
        # redirect root SPA (semua path mengembalikan index.html)
        candidates = [path]
        if not path.endswith("/"):
            candidates.append(path + "/")
        for cand in candidates:
            try:
                url = urljoin(base, cand if cand.startswith("/") else "/" + cand)
                r = client.get(url, allow_redirects=False, timeout=12)
                if r.status_code in (200, 301, 302, 307, 308, 401, 403):
                    # skip respons yang identik dengan halaman utama (SPA fallback)
                    try:
                        body = r.text[:500]
                    except Exception:
                        body = ""
                    return {
                        "path": cand,
                        "status": r.status_code,
                        "size": len(r.content or b""),
                        "body_snippet": body,
                    }
            except requests.RequestException:
                pass
        return None

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(check, p): p for p in wordlist}
        for fut in as_completed(futures):
            res = fut.result()
            if res:
                found.append(res)
                debug(f"{res['status']} {res['path']} ({res['size']} B)")
    ok(f"Path sensitif: {len(found)} ditemukan")
    return found


def brute_subdomains(base: str, client: KerisHTTP, max_workers: int = 10) -> List[str]:
    """Brute-force subdomain umum."""
    host = host_from_url(base)
    domain = domain_from_host(host)
    info(f"Subdomain brute pada: {domain}")
    wordlist = load_wordlist("subdomains.txt")
    if not wordlist:
        return []
    found = []
    scheme = "https"

    def check(sub: str) -> Optional[str]:
        target = f"{scheme}://{sub}.{domain}"
        try:
            r = client.get(target, allow_redirects=False, timeout=10)
            if r.status_code in (200, 301, 302, 403):
                return target
        except requests.RequestException:
            pass
        return None

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(check, s): s for s in wordlist}
        for fut in as_completed(futures):
            res = fut.result()
            if res:
                found.append(res)
                ok(f"Subdomain hidup: {res}")
    return found
