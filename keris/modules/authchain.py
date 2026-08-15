"""Auto-auth chain: kredensial valid -> auto-login -> scan area terproteksi.

Setelah kredensial diperoleh (dari credcheck / user), modul ini login otomatis
lalu menguji area yang hanya terlihat setelah autentikasi: endpoint admin,
dashboard, akun, dan API terproteksi. Mencari kontrol akses yang gagal:
- endpoint admin yang seharusnya butuh role tertentu tapi terbuka untuk user biasa
- data sensitif yang bocor ke user berlevel rendah
- IDOR / enumerasi sederhana pada area terproteksi
"""

from typing import Dict, List, Optional

import requests

from keris.core.http import KerisHTTP
from keris.core.logger import debug, info, ok, warn
from keris.modules.auth import auto_login, _extract_forms
from keris.modules.scanner import Finding
from keris.core.utils import urljoin

# Endpoint yang umum hanya ada setelah login
AUTHED_PROBES = [
    "/dashboard", "/account", "/profile", "/settings", "/admin", "/admin/",
    "/api/me", "/api/user", "/api/account", "/api/profile", "/api/dashboard",
    "/me", "/home", "/panel", "/admin/dashboard", "/admin/users", "/admin/config",
    "/api/admin", "/api/users", "/api/settings", "/api/config", "/internal",
]

# Kata kunci yang menandakan data sensitif/privasi bocor
SENSITIVE_MARKERS = [
    "password", "passwd", "api_key", "apikey", "secret", "token", "ssn",
    "nik", "bank_account", "card_number", "credit", "private_key", "aws",
    "session", "cookie", "jwt", "role", "is_admin", "created_at",
]


def _markers_hit(text: str) -> List[str]:
    low = text.lower()
    return [m for m in SENSITIVE_MARKERS if m in low]


def probe_authed_endpoints(base: str, client: KerisHTTP,
                           probes: Optional[List[str]] = None,
                           username: str = "") -> List[Finding]:
    """Probe endpoint pasca-login; temuan kontrol akses & kebocoran data."""
    findings: List[Finding] = []
    eps = probes or AUTHED_PROBES
    for p in eps:
        url = urljoin(base, p)
        try:
            r = client.get(url, allow_redirects=False, timeout=12)
        except requests.RequestException:
            continue
        # redirect ke login = endpoint memang terproteksi (bagus)
        if r.status_code in (301, 302, 307, 308) and "login" in (r.headers.get("Location", "") or "").lower():
            continue
        if r.status_code == 200:
            markers = _markers_hit((r.text or "")[:4000])
            detail = f"Endpoint {p} merespons 200 setelah login"
            if markers:
                detail += f"; mengandung marker sensitif: {', '.join(markers[:6])}"
                findings.append(Finding(
                    "HIGH", f"Data sensitif bocor ke user autentikasi: {p}",
                    p,
                    f"Endpoint terproteksi {p} menampilkan data dengan marker sensitif "
                    f"({', '.join(markers[:6])}) kepada user biasa.",
                    f"url: {url}, status: 200",
                ))
            else:
                findings.append(Finding(
                    "LOW", f"Endpoint pasca-login terbuka: {p}",
                    p,
                    f"Endpoint {p} dapat diakses user autentikasi (info umum).",
                    f"url: {url}, status: 200",
                ))
            debug(f"200 {p} {markers[:4] if markers else ''}")
        elif r.status_code == 403:
            # 403 = akses ditolak (bukan bug, tapi kadang menandakan ACL longgar)
            debug(f"403 {p} (ditolak)")
    return findings


def run_auth_chain(base: str, username: str, password: str,
                   client: KerisHTTP, login_paths: Optional[List[str]] = None,
                   probes: Optional[List[str]] = None,
                   timeout: float = 20.0) -> Dict:
    """Auto-login lalu scan area terproteksi. Kembalikan dict hasil."""
    info("=== AUTO-AUTH CHAIN ===")
    authed = auto_login(base, username, password, login_paths=login_paths, timeout=timeout)
    findings: List[Finding] = []

    # cek apakah login berhasil: coba endpoint umum terproteksi
    authed_ok = False
    for p in ("/dashboard", "/account", "/api/me", "/profile"):
        try:
            r = authed.get(urljoin(base, p), allow_redirects=False, timeout=10)
            if r.status_code == 200:
                authed_ok = True
                break
        except requests.RequestException:
            continue

    if not authed_ok:
        warn("Login tidak terkonfirmasi; area terproteksi tidak teruji penuh")
    else:
        ok(f"Login berhasil sebagai {username}; memindai area terproteksi")
        findings.extend(probe_authed_endpoints(base, authed, probes=probes, username=username))

    return {
        "authed": authed_ok,
        "username": username,
        "findings": findings,
        "client": authed,
    }