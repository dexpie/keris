"""Client-side JS analysis: cari DOM XSS sinks, endpoint tersembunyi, secret.

Mengunduh asset JavaScript yang ditemukan discovery, lalu memindai untuk:
- sink berbahaya DOM XSS: innerHTML, outerHTML, insertAdjacentHTML, document.write,
  eval, Function(), setTimeout/setInterval dengan string, location.assign/replace
  dengan input.
- endpoint API / path yang hanya ada di client (bukan di halaman statis).
- secret yang bocor di bundle (API key, token) — memakai ulang SECRET_PATTERNS.
"""

import re
from typing import Dict, List, Optional

import requests

from keris.core.http import KerisHTTP
from keris.core.logger import debug, info, ok, warn
from keris.modules.scanner import Finding
from keris.payloads import SECRET_PATTERNS

# Sink DOM XSS yang rentan
DOM_SINKS = {
    "innerHTML": "DOM XSS (innerHTML)",
    "outerHTML": "DOM XSS (outerHTML)",
    "insertAdjacentHTML": "DOM XSS (insertAdjacentHTML)",
    "document.write": "DOM XSS (document.write)",
    "document.writeln": "DOM XSS (document.writeln)",
    "eval(": "Kode dievaluasi dinamis (eval)",
    "new Function(": "Kode dievaluasi dinamis (Function)",
    "setTimeout(": "setTimeout dengan input dinamis",
    "setInterval(": "setInterval dengan input dinamis",
    "location.assign": "Redirect/assign dengan input dinamis",
    "location.replace": "Redirect/replace dengan input dinamis",
}

# Sumber input (source) yang sering mengalir ke sink
DOM_SOURCES = [
    "location.search", "location.hash", "location.href", "document.referrer",
    "document.URL", "document.documentURI", "window.name", "postMessage",
    "localStorage", "sessionStorage",
]

# Pengecualian: sink yang hanya memakai string literal (bukan input)
_SAFE_LITERAL_RE = re.compile(
    r'(?:innerHTML|outerHTML|insertAdjacentHTML|document\.write(?:ln)?|eval|setTimeout|setInterval)'
    r'\s*(?:\(\s*|=)\s*["\'`]',
)


def _scan_js(text: str, url: str) -> List[Dict]:
    """Scan satu bundle JS; kembalikan daftar hasil."""
    hits = []
    for sink, name in DOM_SINKS.items():
        for m in re.finditer(re.escape(sink), text):
            start = max(0, m.start() - 90)
            end = min(len(text), m.end() + 120)
            snippet = text[start:end]
            # abaikan sink dengan argumen literal (periksa hanya region sekitar match)
            if _SAFE_LITERAL_RE.search(text[m.start():m.start() + 60]):
                continue
            # cek kedekatan dengan source input
            has_source = any(src in snippet for src in DOM_SOURCES)
            hits.append({
                "type": "dom_sink",
                "name": name,
                "source_adjacent": has_source,
                "snippet": snippet.strip(),
            })
            break  # satu sink per file cukup untuk deteksi; jangan spam

    for pat_name, pattern in SECRET_PATTERNS.items():
        for m in re.finditer(pattern, text):
            hits.append({
                "type": "secret",
                "name": pat_name,
                "source_adjacent": False,
                "snippet": m.group(0),
            })
            break

    return hits


def _extract_endpoints(text: str, base: str) -> List[str]:
    eps = set()
    for m in re.finditer(r'["\'](/api/[^"\']{2,80})["\']', text):
        eps.add(m.group(1))
    for m in re.finditer(r'fetch\(["\']([^"\']{2,120})["\']', text):
        eps.add(m.group(1))
    for m in re.finditer(r'axios[.\w]*\(["\']([^"\']{2,120})["\']', text):
        eps.add(m.group(1))
    out = []
    for e in sorted(eps):
        if e.startswith("/"):
            out.append(e)
        elif e.startswith(("http://", "https://")) and base.rstrip("/") in e:
            out.append(e.split(base.rstrip("/"))[-1])
    return out


def analyze_js(base: str, client: KerisHTTP,
               assets: Optional[List[str]] = None,
               max_assets: int = 15) -> Dict:
    """Analisis asset JS target. Mengembalikan dict hasil.

    `assets` opsional: daftar URL JS yang sudah dikumpulkan discovery.
    Bila kosong, cari `<script src>` di halaman utama.
    """
    if not assets:
        try:
            r = client.get(base, timeout=15)
            page = r.text
        except requests.RequestException:
            page = ""
        assets = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', page)
        assets = [a if a.startswith(("http://", "https://")) else base.rstrip("/") + a
                  for a in assets]
        assets = list(dict.fromkeys(assets))

    findings: List[Finding] = []
    scanned = []
    endpoint_set = set()
    secret_count = 0
    for url in assets[:max_assets]:
        try:
            r = client.get(url, timeout=15)
        except requests.RequestException:
            continue
        if r.status_code != 200 or "text/javascript" not in r.headers.get("content-type", "") and not url.endswith(".js"):
            if not url.endswith(".js"):
                continue
        text = r.text
        scanned.append(url)
        hits = _scan_js(text, url)
        for h in hits:
            if h["type"] == "secret":
                secret_count += 1
                findings.append(Finding(
                    "HIGH", f"Secret bocor di bundle JS: {h['name']}",
                    url,
                    "Secret dikirim ke client. Segera rotasi kunci/secret.",
                    h["snippet"][:300],
                ))
            else:
                sev = "HIGH" if h["source_adjacent"] else "MEDIUM"
                findings.append(Finding(
                    sev, f"Potensi {h['name']}",
                    url,
                    f"Sink DOM XSS terdeteksi (source terhubung: "
                    f"{'ya' if h['source_adjacent'] else 'tidak langsung'}). "
                    "Audit alur data untuk mengonfirmasi exploitability.",
                    h["snippet"][:500],
                ))
        endpoint_set.update(_extract_endpoints(text, base))

    if not scanned:
        warn("Tidak ada asset JS yang dapat diunduh")
    else:
        info(f"JS dianalisis: {len(scanned)} asset, {len(findings)} temuan")

    return {
        "js_scanned": scanned,
        "endpoints": sorted(endpoint_set),
        "secret_count": secret_count,
        "findings": findings,
    }
