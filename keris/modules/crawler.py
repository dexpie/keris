"""Web crawler sederhana: petakan attack surface dari target.

Menjelajah halaman dalam host yang sama (dengan batas), mengekstrak:
- link/internal URLs
- form (action, method, input fields)
- parameter unik dari query string
- path API/asset yang menarik

Hasilnya menjadi peta attack surface yang bisa diumpankan ke scan.
"""

import re
from collections import deque
from typing import Dict, List, Optional
from urllib.parse import urljoin, urlparse, parse_qsl

import requests

from keris.core.http import KerisHTTP
from keris.core.logger import debug, info, ok, warn
from keris.modules.scanner import Finding

DEFAULT_MAX_PAGES = 50
FORM_RE = re.compile(r"<form[^>]*action=[\"']([^\"']*)[\"'][^>]*>", re.I)
INPUT_RE = re.compile(r"<input[^>]*name=[\"']([^\"']*)[\"'][^>]*>", re.I)
SCRIPT_SRC_RE = re.compile(r"<script[^>]+src=[\"']([^\"']+)[\"']", re.I)
LINK_HREF_RE = re.compile(r"<a[^>]+href=[\"']([^\"']+)[\"']", re.I)


def _same_host(a: str, b: str) -> bool:
    return urlparse(a).netloc == urlparse(b).netloc


def _normalize_href(href: str, base: str) -> Optional[str]:
    if not href or href.startswith(("javascript:", "mailto:", "tel:", "#")):
        return None
    return urljoin(base, href)


def crawl(base: str, client: KerisHTTP, max_pages: int = DEFAULT_MAX_PAGES,
          max_depth: int = 3) -> Dict:
    """BFS crawl dari `base`. Mengembalikan peta attack surface."""
    info(f"Crawling {base} (max {max_pages} halaman, depth {max_depth})")
    base_host = urlparse(base).netloc

    visited: List[str] = []
    seen = set()
    forms: List[dict] = []
    params: Dict[str, int] = {}
    js_assets: List[str] = []
    queue = deque([(base, 0)])

    while queue and len(visited) < max_pages:
        url, depth = queue.popleft()
        if url in seen:
            continue
        seen.add(url)
        if urlparse(url).netloc != base_host:
            continue
        if depth > max_depth:
            continue

        try:
            r = client.get(url, timeout=15)
        except requests.RequestException as e:
            debug(f"crawl skip {url}: {e}")
            continue
        if r.status_code != 200:
            continue
        body = r.text
        visited.append(url)

        # params dari query
        q = dict(parse_qsl(urlparse(url).query))
        for k in q:
            params[k] = params.get(k, 0) + 1

        # forms
        for fm in FORM_RE.finditer(body):
            action = _normalize_href(fm.group(1), url) or url
            inputs = INPUT_RE.findall(body[fm.start():fm.end() + 4000])
            forms.append({
                "action": action,
                "method": re.search(r'method=[\"\']([^\"\']+)[\"\']', body[fm.start():fm.end()], re.I)
                             .group(1) if re.search(r'method=[\"\']([^\"\']+)[\"\']', body[fm.start():fm.end()], re.I) else "GET",
                "inputs": sorted(set(inputs)),
            })

        # link internal
        for href in LINK_HREF_RE.findall(body):
            nxt = _normalize_href(href, url)
            if nxt and _same_host(base, nxt):
                queue.append((nxt, depth + 1))
        # scripts (assets, tidak di-crawl)
        for src in SCRIPT_SRC_RE.findall(body):
            js = urljoin(url, src)
            if js not in js_assets:
                js_assets.append(js)

    result = {
        "base": base,
        "pages": visited,
        "forms": forms,
        "params": dict(sorted(params.items(), key=lambda x: -x[1])),
        "js_assets": js_assets,
        "count": len(visited),
    }
    ok(f"Crawl selesai: {len(visited)} halaman, {len(forms)} form, "
       f"{len(params)} parameter unik, {len(js_assets)} JS")
    return result


def crawl_findings(result: Dict) -> List[Finding]:
    """Konversi hasil crawl menjadi temuan informasi (param unik, form, dll)."""
    findings = []
    interesting_params = [p for p in result.get("params", {})
                          if p.lower() in ("file", "path", "cmd", "exec", "url",
                                           "id", "redirect", "next", "callback")]
    if interesting_params:
        findings.append(Finding(
            "INFO", "Parameter menarik ditemukan saat crawl",
            result["base"],
            "Parameter yang sering menjadi titik injeksi/filterless: "
            + ", ".join(interesting_params),
            "params=" + ",".join(interesting_params),
        ))
    return findings