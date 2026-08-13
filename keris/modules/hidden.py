"""Hidden endpoint discovery: cari akses ke endpoint tersembunyi/tidak terindeks.

Berbeda dengan brute path umum, modul ini fokus pada endpoint yang:
- tidak di-link dari halaman publik (admin panel, API internal, debug)
- sering ter-expose tidak sengaja (config, backup, actuator, swagger)
- merespons dengan status berbeda dari 404 (200/301/401/403/500)

Dilengkapi deteksi SPA-fallback: path yang mengembalikan HTML identik dengan
halaman utama (index.html) dianggap TIDAK ada, bukan endpoint nyata.
"""

import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional

import requests

from keris.core.http import KerisHTTP
from keris.core.logger import debug, info, ok, warn
from keris.modules.scanner import Finding

# Endpoint tersembunyi yang sering ter-expose di aplikasi web
HIDDEN_ENDPOINTS = [
    # admin / internal
    "/admin", "/admin/", "/administrator/", "/administrator", "/panel", "/panel/",
    "/manage", "/manager/", "/internal", "/internal/", "/intranet", "/staff",
    "/staff/", "/console", "/dashboard", "/control", "/controlpanel",
    # API tersembunyi
    "/api/v1/", "/api/v2/", "/api/internal", "/api/private", "/api/admin",
    "/api/debug", "/api/config", "/api/health", "/api/status", "/api/version",
    "/api/users", "/api/auth", "/v1/internal", "/private", "/restricted",
    # debug / docs / monitoring
    "/debug", "/debug/", "/trace", "/actuator", "/actuator/env", "/actuator/health",
    "/swagger", "/swagger/", "/swagger-ui/", "/swagger.json", "/api-docs",
    "/openapi.json", "/graphql", "/graphiql", "/metrics", "/status", "/health",
    "/monitor", "/phpinfo.php", "/info.php", "/test", "/test/", "/dev", "/dev/",
    # backup / config / source
    "/backup", "/backup/", "/backups/", "/backup.zip", "/backup.tar.gz",
    "/db_backup", "/database", "/database.sql", "/dump.sql", "/export",
    "/config.json", "/config.php", "/configuration", "/settings.json",
    "/.env", "/.env.bak", "/.git/config", "/.git/HEAD", "/.svn/entries",
    "/.htpasswd", "/.gitignore", "/package.json", "/server-status",
    # staging / testing
    "/staging", "/staging/", "/test/", "/demo", "/demo/", "/sandbox", "/sandbox/",
    "/preview", "/uat", "/qa", "/beta",
]

# Klasifikasi endpoint menarik (dari path)
INTERESTING_CLASS = [
    ("admin", "Admin panel", "HIGH"),
    ("console", "Admin console", "HIGH"),
    ("internal", "Endpoint internal", "HIGH"),
    ("private", "Endpoint privat", "MEDIUM"),
    ("backup", "File backup", "HIGH"),
    (".env", "File konfigurasi lingkungan", "CRITICAL"),
    (".git", "Direktori .git ter-expose", "CRITICAL"),
    (".svn", "Direktori .svn ter-expose", "HIGH"),
    (".htpasswd", "File kredensial htpasswd", "CRITICAL"),
    ("actuator", "Spring Actuator", "MEDIUM"),
    ("swagger", "Dokumentasi API", "MEDIUM"),
    ("openapi.json", "Spec OpenAPI", "MEDIUM"),
    ("graphql", "Endpoint GraphQL", "LOW"),
    ("phpinfo", "phpinfo() ter-expose", "HIGH"),
    ("server-status", "Apache server-status", "MEDIUM"),
    ("debug", "Endpoint debug", "MEDIUM"),
    ("database", "File database", "CRITICAL"),
    ("metrics", "Endpoint metrics", "LOW"),
]


def _classify(path: str) -> tuple:
    """Kembalikan (nama, severity) untuk endpoint yang diklasifikasi."""
    low = path.lower()
    for marker, name, sev in INTERESTING_CLASS:
        if marker in low:
            return name, sev
    return None, None


def find_hidden_endpoints(base: str, client: KerisHTTP,
                          endpoints: Optional[List[str]] = None,
                          max_workers: int = 10) -> List[Finding]:
    """Cari endpoint tersembunyi yang merespons non-404.

    `endpoints` opsional: daftar tambahan endpoint kustom yang dicoba.
    """
    wordlist = list(dict.fromkeys(HIDDEN_ENDPOINTS + (endpoints or [])))
    info(f"Hidden endpoint discovery: {len(wordlist)} path")

    # baseline halaman utama untuk deteksi SPA-fallback
    root_body = None
    root_status = 404
    try:
        r0 = client.get(base, timeout=15)
        root_status = r0.status_code
        root_body = re.sub(r"\s+", "", r0.text[:2000])
    except requests.RequestException:
        pass

    found: List[dict] = []

    def check(path: str) -> Optional[dict]:
        url = base.rstrip("/") + path
        try:
            r = client.get(url, allow_redirects=False, timeout=12)
        except requests.RequestException:
            return None
        # 404 = tidak ada
        if r.status_code == 404:
            return None
        # skip redirect ke halaman yang sama / root
        if r.status_code in (301, 302, 303, 307, 308):
            loc = r.headers.get("Location", "")
            if loc == "/" or loc == base.rstrip("/") + "/" or loc.rstrip("/") == base.rstrip("/"):
                return None
        # SPA-fallback: body identik dengan halaman utama
        try:
            body = r.text[:2000]
        except Exception:
            body = ""
        if root_body and root_status == 200:
            if re.sub(r"\s+", "", body) == root_body:
                return None
        return {
            "path": path,
            "status": r.status_code,
            "size": len(r.content or b""),
            "snippet": body[:300],
        }

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(check, p): p for p in wordlist}
        for fut in as_completed(futures):
            res = fut.result()
            if res:
                found.append(res)
                debug(f"{res['status']} {res['path']} ({res['size']} B)")

    found.sort(key=lambda d: d["path"])
    findings: List[Finding] = []
    for f in found:
        name, sev = _classify(f["path"])
        if sev:
            findings.append(Finding(
                sev, f"Endpoint tersembunyi ter-expose: {name}",
                base.rstrip("/") + f["path"],
                f"Endpoint {f['path']} merespons status {f['status']} "
                f"({f['size']} B) — periksa apakah akses publik disengaja.",
                f"status={f['status']}, size={f['size']}, snippet={f['snippet'][:200]}",
            ))
            ok(f"[{sev}] {name}: {f['path']} ({f['status']})")
    if not findings:
        warn("Tidak ada endpoint tersembunyi yang terdeteksi")
    return findings