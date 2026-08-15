"""Server/framework CVE checker berbasis banner & header.

Mendeteksi versi server (nginx, Apache, IIS, PHP, OpenSSL, WordPress core,
Laravel/PHP framework) dari header HTTP dan halaman generik, lalu mencocokkan
dengan database CVE offline untuk menemukan versi rentan.

Mirip dengan --js-deps tetapi untuk sisi server, bukan bundle JS klien.
"""

import re
from typing import Dict, List, Optional, Tuple

from keris.core.logger import debug, info, ok, warn
from keris.modules.scanner import Finding

# (produk, prefix_versi_rentan, severity, deskripsi)
SERVER_CVE_DB: Dict[str, List[Tuple[str, str, str]]] = {
    "nginx": [
        ("1.20.0", "HIGH", "nginx 1.20.1 prior: buffer overflow & request smuggling (CVE-2021-23017)"),
        ("1.18.0", "HIGH", "nginx 1.18.0 prior: HTTP/2 memory disclosure (CVE-2018-16843)"),
        ("1.16.0", "MEDIUM", "nginx 1.16 prior: request smuggling & null byte (CVE-2019-9511)"),
        ("1.14.0", "HIGH", "nginx 1.14 prior: HTTP/2 DoS (CVE-2018-16844)"),
    ],
    "apache": [
        ("2.4.49", "CRITICAL", "Apache 2.4.49: path traversal & RCE (CVE-2021-41773)"),
        ("2.4.50", "CRITICAL", "Apache 2.4.50: path traversal & RCE (CVE-2021-42013)"),
        ("2.4.53", "HIGH", "Apache 2.4.53 prior: mod_sed XSS & request smuggling (CVE-2022-23943)"),
        ("2.4.55", "HIGH", "Apache 2.4.55 prior: mod_proxy request smuggling (CVE-2023-25690)"),
        ("2.2.34", "HIGH", "Apache 2.2.34 prior: multiple RCE/DoS (CVE-2017-15710)"),
    ],
    "php": [
        ("8.0.30", "HIGH", "PHP 8.0 prior: multiple RCE (CVE-2023-3824)"),
        ("8.1.22", "HIGH", "PHP 8.1 prior: buffer overflow & RCE (CVE-2023-3824)"),
        ("8.2.8", "HIGH", "PHP 8.2 prior: buffer overflow & RCE (CVE-2023-3824)"),
        ("7.4.33", "CRITICAL", "PHP 7.4 EOL & prior: known RCEs (CVE-2022-31626 etc.)"),
        ("5.6.40", "CRITICAL", "PHP 5.x EOL lama: banyak CVE publik"),
    ],
    "openssl": [
        ("1.1.1", "HIGH", "OpenSSL 1.1.1 prior: buffer overflow (CVE-2022-3602)"),
        ("3.0.6", "HIGH", "OpenSSL 3.0.6 prior: X.509 email buffer overflow (CVE-2022-3602)"),
        ("1.0.2", "CRITICAL", "OpenSSL 1.0.2 EOL: Heartbleed-related legacy bugs"),
    ],
    "iis": [
        ("10.0", "MEDIUM", "IIS 10 prior: HTTP.sys DoS (CVE-2017-11763)"),
        ("8.5", "HIGH", "IIS 8.5 prior: HTTP.sys remote code execution (CVE-2015-1635)"),
    ],
    "wordpress": [
        ("6.0.3", "HIGH", "WordPress < 6.0.3: SQLi via plugin/theme upload & XSS"),
        ("6.1.1", "MEDIUM", "WordPress < 6.1.1: post by ID info disclosure"),
        ("6.4.0", "HIGH", "WordPress < 6.4.3: RCE via arbitrary file upload (CVE-2023-6989)"),
    ],
    "joomla": [("4.2.7", "MEDIUM", "Joomla < 4.2.8: SQLi (CVE-2023-23752)")],
    "drupal": [("9.4.0", "HIGH", "Drupal < 9.4.8: access bypass (CVE-2022-25277)")],
    "laravel": [
        ("8.83.26", "MEDIUM", "Laravel < 8.83.27: XSS di Blade (CVE-2023-24249)"),
        ("9.52.0", "MEDIUM", "Laravel < 9.52.0: DoS via multipart (CVE-2022-40482)"),
    ],
    "tomcat": [
        ("9.0.30", "CRITICAL", "Apache Tomcat < 9.0.31: AJP ghostcat RCE (CVE-2020-1938)"),
        ("8.5.50", "CRITICAL", "Tomcat < 8.5.51: AJP ghostcat RCE (CVE-2020-1938)"),
    ],
    "jetty": [("9.4.27", "MEDIUM", "Jetty < 9.4.28: HTTP request smuggling (CVE-2019-17638)")],
    "rails": [("6.1.4", "HIGH", "Rails < 6.1.5: content security bypass (CVE-2022-27777)")],
}


def _parse_version(ver: str) -> Tuple[int, ...]:
    m = re.match(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\.(\d+))?", ver.strip())
    if not m:
        return ()
    return tuple(int(g) for g in m.groups() if g is not None)


def _vuln_for(product: str, version: str) -> Optional[Tuple[str, str]]:
    """Kembalikan (severity, deskripsi) jika versi rentan, atau None."""
    if not version or product not in SERVER_CVE_DB:
        return None
    cur = _parse_version(version)
    # versi tidak dikenal (kosong / "0" placeholder generator) bukan bukti rentan
    if not cur or cur == (0,):
        return None
    best = None
    for limit, sev, desc in SERVER_CVE_DB[product]:
        lim = _parse_version(limit)
        if not lim or lim == (0,):
            continue
        if cur <= lim:
            score = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(sev, 9)
            if best is None or score < best[0]:
                best = (score, sev, desc)
    return (best[1], best[2]) if best else None


def _extract_banner_versions(headers: Dict[str, str]) -> List[Tuple[str, str]]:
    """Kembalikan [(product, version)] dari header Server, X-Powered-By, dll."""
    found: List[Tuple[str, str]] = []
    server = headers.get("server") or headers.get("Server") or ""
    xpb = headers.get("x-powered-by") or headers.get("X-Powered-By") or ""
    xgen = headers.get("x-generator") or headers.get("X-Generator") or ""

    for raw in (server, xpb, xgen):
        if not raw:
            continue
        low = raw.lower()
        # nginx/1.24.0
        m = re.search(r"(nginx|apache|liteSpeed|openresty|caddy|iis|jetty)\s*[/]?\s*([\d.]+)", raw, re.I)
        if m and (m.group(1).lower(), m.group(2)) not in found:
            found.append((m.group(1).lower(), m.group(2)))
        # Apache/2.4.49 (Ubuntu)
        m = re.search(r"(?:apache[/ ]?)([\d.]+)", raw, re.I)
        if m and ("apache", m.group(1)) not in found:
            found.append(("apache", m.group(1)))
        # PHP/8.1.2
        m = re.search(r"(?:php[/ ]?)([\d.]+)", raw, re.I)
        if m and ("php", m.group(1)) not in found:
            found.append(("php", m.group(1)))
        # OpenSSL/3.0.7
        m = re.search(r"(?:openssl[/ ]?)([\d.]+)", raw, re.I)
        if m and ("openssl", m.group(1)) not in found:
            found.append(("openssl", m.group(1)))
        # tomcat/9.0.30
        m = re.search(r"(?:tomcat|apache-tomcat)(?:[/ ]?)([\d.]+)", raw, re.I)
        if m and ("tomcat", m.group(1)) not in found:
            found.append(("tomcat", m.group(1)))
        # wordpress/6.4
        m = re.search(r"wordpress\s*[/]?\s*([\d.]+)", raw, re.I)
        if m and ("wordpress", m.group(1)) not in found:
            found.append(("wordpress", m.group(1)))
        # rails / ruby on rails
        m = re.search(r"rails\s*[/]?\s*([\d.]+)", raw, re.I)
        if m and ("rails", m.group(1)) not in found:
            found.append(("rails", m.group(1)))
        # express (node)
        m = re.search(r"express\s*[/]?\s*([\d.]+)", raw, re.I)
        if m and ("express", m.group(1)) not in found:
            found.append(("express", m.group(1)))
        if low.startswith("iis/"):
            m = re.search(r"iis/([\d.]+)", raw, re.I)
            if m and ("iis", m.group(1)) not in found:
                found.append(("iis", m.group(1)))
    return found


def _generator_from_html(html: str) -> List[Tuple[str, str]]:
    """Cek meta generator / komentar HTML untuk WP/Joomla/Drupal/Laravel."""
    found: List[Tuple[str, str]] = []
    meta = re.findall(r'<meta[^>]+name=["\']generator["\'][^>]*content=["\']([^"\']+)["\']', html, re.I)
    for content in meta:
        low = content.lower()
        if "wordpress" in low:
            m = re.search(r"wordpress\s*([\d.]+)", low)
            found.append(("wordpress", m.group(1) if m else "0"))
        if "joomla" in low:
            m = re.search(r"joomla\s*([\d.]+)", low)
            found.append(("joomla", m.group(1) if m else "0"))
        if "drupal" in low:
            m = re.search(r"drupal\s*([\d.]+)", low)
            found.append(("drupal", m.group(1) if m else "0"))
    return found


def scan_server_cve(base: str, headers: Dict[str, str],
                    html: str = "") -> List[Finding]:
    """Cek CVE untuk banner server & framework. Kembalikan temuan."""
    info("=== SERVER / FRAMEWORK CVE ===")
    banners = _extract_banner_versions(headers)
    banners += _generator_from_html(html or "")
    # dedup
    seen = set()
    unique = []
    for p, v in banners:
        if (p, v) not in seen:
            seen.add((p, v))
            unique.append((p, v))

    findings: List[Finding] = []
    if not unique:
        debug("Tidak ada banner dengan versi yang bisa dicocokkan")
        return findings

    for product, version in unique:
        hit = _vuln_for(product, version)
        if not hit:
            debug(f"OK {product} {version} (tidak dalam DB CVE)")
            continue
        sev, desc = hit
        findings.append(Finding(
            sev, f"{product} {version} rentan: {desc[:60]}",
            base,
            f"Deteksi banner server `{product} {version}` rentan terhadap CVE "
            f"yang diketahui: {desc}.",
            f"banner: {product} {version}",
        ))
        debug(f"{sev} {product} {version}: {desc}")
    return findings