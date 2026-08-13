"""Check khusus platform: WordPress, NextAuth, Supabase, Laravel, dll.

Template deklaratif sederhana: daftar path + penanda yang menandakan
instalasi platform serta isu khasnya (mis. file instalasi tersisa,
endpoint admin terbuka, versi usang).
"""

from typing import Dict, List, Optional

import requests

from keris.core.http import KerisHTTP
from keris.core.logger import debug, info, ok, warn
from keris.modules.scanner import Finding

# Template: path -> (severity, deskripsi, penanda positif, penanda negatif)
PLATFORM_CHECKS: Dict[str, List[dict]] = {
    "wordpress": [
        {"path": "/wp-login.php", "severity": "INFO", "title": "WordPress login page",
         "desc": "Halaman login WordPress terdeteksi.", "match": ["wordpress", "user_login"], "status": 200},
        {"path": "/wp-content/debug.log", "severity": "HIGH", "title": "WordPress debug.log terbuka",
         "desc": "File debug.log terekspos (bisa bocorkan stack trace & data).", "match": ["PHP"], "status": 200},
        {"path": "/wp-json/wp/v2/users", "severity": "MEDIUM", "title": "User enumeration REST API",
         "desc": "Endpoint REST WP mengekspos daftar pengguna.", "match": ["slug", "name"], "status": 200},
        {"path": "/readme.html", "severity": "LOW", "title": "readme.html terekspos",
         "desc": "File readme WordPress terbuka (bocorkan versi).", "match": ["WordPress"], "status": 200},
    ],
    "nextauth": [
        {"path": "/api/auth/providers", "severity": "INFO", "title": "NextAuth providers endpoint",
         "desc": "Endpoint providers NextAuth terbuka.", "match": ["credential", "github", "google"], "status": 200},
        {"path": "/api/auth/session", "severity": "LOW", "title": "NextAuth session endpoint",
         "desc": "Endpoint session NextAuth terbuka; cek isi sesi.", "match": ["user", "email", "expires"], "status": 200},
    ],
    "supabase": [
        {"path": "/rest/v1/", "severity": "LOW", "title": "Supabase REST API terbuka",
         "desc": "API Supabase terekspos; cek apakah anon key terbuka.", "match": ["swagger", "openapi", "OpenAPI"], "status": 200},
    ],
    "laravel": [
        {"path": "/.env", "severity": "HIGH", "title": "File .env terekspos",
         "desc": "File .env (APP_KEY, DB_PASSWORD, dll) dapat diakses.", "match": ["APP_KEY", "DB_"], "status": 200},
        {"path": "/storage/logs/laravel.log", "severity": "HIGH", "title": "Laravel log terbuka",
         "desc": "Log Laravel terekspos (stack trace, secret).", "match": ["stack trace", "production"], "status": 200},
        {"path": "/telescope", "severity": "HIGH", "title": "Laravel Telescope terbuka",
         "desc": "Debug panel Telescope terdeteksi.", "match": ["Telescope", "telescope"], "status": 200},
    ],
    "phpmyadmin": [
        {"path": "/phpmyadmin/", "severity": "HIGH", "title": "phpMyAdmin terbuka",
         "desc": "Panel phpMyAdmin terdeteksi (target brute-force umum).", "match": ["phpMyAdmin", "pma_username"], "status": 200},
    ],
    "spring": [
        {"path": "/actuator", "severity": "HIGH", "title": "Spring Actuator terbuka",
         "desc": "Endpoint actuator Spring Boot (env, health, heapdump).", "match": ["status", "UP"], "status": 200},
        {"path": "/actuator/env", "severity": "HIGH", "title": "Spring actuator/env terekspos",
         "desc": "Environment variables Spring terbuka.", "match": ["propertySources", "server"], "status": 200},
    ],
}


def check_platforms(base: str, client: KerisHTTP,
                    platforms: Optional[List[str]] = None) -> List[Finding]:
    """Jalankan check untuk platform tertentu (default: semua)."""
    findings = []
    selected = {p: PLATFORM_CHECKS[p] for p in (platforms or PLATFORM_CHECKS)
                if p in PLATFORM_CHECKS}
    for platform, checks in selected.items():
        info(f"Check platform: {platform}")
        for ch in checks:
            url = base.rstrip("/") + ch["path"]
            try:
                r = client.get(url, allow_redirects=False, timeout=12)
            except requests.RequestException:
                continue
            if r.status_code != ch["status"]:
                continue
            body = r.text[:2000].lower()
            if any(m.lower() in body for m in ch["match"]):
                findings.append(Finding(
                    ch["severity"], ch["title"], url,
                    ch["desc"], f"status: {r.status_code}, body: {r.text[:120]}",
                ))
                debug(f"  [+] {ch['path']} -> {ch['severity']}")
    return findings
