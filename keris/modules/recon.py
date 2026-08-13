"""Modul recon: DNS, header keamanan, deteksi stack, robots/sitemap."""

import re
import socket
from typing import Dict, List, Tuple, Optional

import requests

from keris.core.http import KerisHTTP
from keris.core.logger import info, ok, warn, debug, severity
from keris.core.utils import host_from_url, scheme_from_url, normalize_url
from keris.payloads import SECURITY_HEADERS, STACK_INDICATORS


def dns_lookup(host: str) -> List[str]:
    """Resolusi A record."""
    results = []
    try:
        infos = socket.getaddrinfo(host, 443, socket.AF_INET, socket.SOCK_STREAM)
        seen = set()
        for info in infos:
            ip = info[4][0]
            if ip not in seen:
                seen.add(ip)
                results.append(ip)
    except socket.gaierror as e:
        debug(f"DNS gagal untuk {host}: {e}")
    return results


def analyze_security_headers(headers: Dict[str, str]) -> List[dict]:
    """Nilai keberadaan dan kualitas security headers."""
    findings = []
    lower = {k.lower(): v for k, v in headers.items()}
    for hdr, (short, desc) in SECURITY_HEADERS.items():
        val = lower.get(hdr.lower())
        if not val:
            findings.append({"header": hdr, "short": short, "desc": desc, "present": False, "value": None})
        else:
            findings.append({"header": hdr, "short": short, "desc": desc, "present": True, "value": val[:120]})
    return findings


def detect_stack(headers: Dict[str, str], html: str = "") -> List[str]:
    """Deteksi stack teknologi dari header dan konten."""
    detected = set()
    lower = {k.lower(): v for k, v in headers.items()}
    for header_key, pattern, label in STACK_INDICATORS:
        val = lower.get(header_key.lower())
        if val and re.search(pattern, val, re.IGNORECASE):
            detected.add(label)
    # meta generator
    m = re.search(r'<meta\s+name=["\']generator["\']\s+content=["\']([^"\']+)["\']', html, re.IGNORECASE)
    if m:
        detected.add(m.group(1).strip())
    # framework umum dari HTML
    if "next/router" in html or "data-nextjs" in html or "_next/" in html:
        detected.add("Next.js")
    if "__NEXT_DATA__" in html:
        detected.add("Next.js (SSR)")
    if 'data-reactroot' in html or '__reactRoot' in html or 'createRoot' in html:
        detected.add("React")
    if 'ng-version' in html or 'ng-app' in html:
        detected.add("Angular")
    if 'data-vue' in html or 'Vue' in html:
        detected.add("Vue")
    if 'wp-content' in html or 'wp-includes' in html:
        detected.add("WordPress")
    return sorted(detected)


def fetch_robots(client: KerisHTTP, base: str) -> Optional[str]:
    for path in ("/robots.txt", "/sitemap.xml", "/.well-known/security.txt"):
        try:
            r = client.get(base + path, timeout=15)
            if r.status_code == 200 and len(r.text) < 20000:
                if r.text.strip():
                    info(f"{path}: {len(r.text)} byte")
                    return r.text
        except requests.RequestException:
            pass
    return None


def run_recon(base: str, client: KerisHTTP) -> Dict:
    """Jalankan recon lengkap dan kembalikan hasil."""
    info(f"Target: {base}")
    host = host_from_url(base)

    # DNS
    info("Resolving DNS...")
    ips = dns_lookup(host)
    if ips:
        ok(f"IP ({len(ips)}): {', '.join(ips)}")
    else:
        warn("Tidak dapat resolve DNS")

    # HTTP headers
    info("Mengambil header HTTP...")
    try:
        resp = client.get(base, allow_redirects=True, timeout=25)
    except requests.RequestException as e:
        severity("HIGH", f"Target tidak merespons: {e}")
        return {"error": str(e), "dns": ips}

    headers = dict(resp.headers)
    html = resp.text if resp.headers.get("Content-Type", "").startswith("text/") else ""

    # security headers
    info("Menganalisis security headers...")
    sec = analyze_security_headers(headers)
    missing = [s["short"] for s in sec if not s["present"]]
    if missing:
        warn(f"Header hilang: {', '.join(missing)}")
    else:
        ok("Semua security headers inti hadir")

    # stack
    stack = detect_stack(headers, html)
    if stack:
        ok(f"Stack terdeteksi: {', '.join(stack)}")
    else:
        debug("Stack tidak jelas")

    # robots/sitemap
    robots = fetch_robots(client, base)

    result = {
        "url": base,
        "host": host,
        "ips": ips,
        "status_code": resp.status_code,
        "server_header": headers.get("Server"),
        "headers": headers,
        "security_headers": sec,
        "stack": stack,
        "robots": robots,
        "has_redirect": len(resp.history) > 0,
        "final_url": resp.url,
    }
    return result
