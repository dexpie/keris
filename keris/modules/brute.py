"""Brute-force kredensial lemah pada form login / basic auth.

Non-destruktif: hanya mencoba daftar kredensial kecil (bukan setiap kombinasi
besar) untuk mendeteksi password yang terlalu lemah. Gunakan hanya pada
target yang diizinkan.
"""

import base64
from typing import List, Optional

import requests
from urllib.parse import urljoin

from keris.core.http import KerisHTTP
from keris.core.logger import debug, info, ok, warn
from keris.modules.auth import _extract_forms, _pick_login_candidate, _auto_fill
from keris.modules.scanner import Finding

# Kredensial umum yang lemah (jangan ditambah tanpa alasan; tool harus tetap
# ringan dan tidak menjadi alat brute-force massal yang disalahgunakan).
COMMON_CREDENTIALS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "123456"),
    ("admin", "12345678"), ("admin", "admin123"), ("admin", "changeme"),
    ("admin", "qwerty"), ("admin", "letmein"), ("admin", "admin888"),
    ("root", "root"), ("root", "toor"), ("root", "password"),
    ("test", "test"), ("test", "test123"), ("user", "user"),
    ("user", "password"), ("guest", "guest"), ("demo", "demo"),
    ("administrator", "admin"), ("admin", "secret"), ("admin", "000000"),
]

# Cara mendeteksi "login berhasil" dari respons
SUCCESS_MARKERS = [
    b"dashboard", b"logout", b"welcome", b"berhasil", b"selamat", b"redirect",
    b"account", b"profile", b"settings",
]
FAILURE_MARKERS = [
    b"invalid", b"incorrect", b"gagal", b"salah", b"error", b"tidak valid",
    b"forbidden", b"denied", b"401", b"403",
]


def _is_success(response: requests.Response) -> bool:
    if response.status_code in (301, 302, 303, 307, 308):
        # redirect setelah login = biasanya berhasil
        return True
    if response.status_code in (200, 201, 204):
        body = response.content[:2000].lower()
        if any(m in body for m in FAILURE_MARKERS):
            return False
        if any(m in body for m in SUCCESS_MARKERS):
            return True
        return False
    return False


def brute_login_form(base: str, client: KerisHTTP,
                     credentials: Optional[List[tuple]] = None,
                     login_paths: Optional[List[str]] = None) -> List[Finding]:
    """Brute-force form login HTML."""
    if credentials is None:
        credentials = COMMON_CREDENTIALS
    findings = []
    paths = login_paths or ["/login", "/signin", "/auth", "/account/login"]

    # temukan form login & sesi CSRF
    form = None
    page = None
    for path in paths:
        url = urljoin(base, path)
        try:
            r = client.get(url, timeout=15)
        except requests.RequestException:
            continue
        if r.status_code != 200:
            continue
        cand = _pick_login_candidate(_extract_forms(r.text))
        if cand:
            form, page = cand, url
            break
    if not form:
        warn("Form login tidak ditemukan; lewati brute-force form")
        return findings

    target = urljoin(page, form["action"]) if form["action"] else page
    method = form["method"]
    info(f"Brute-force login pada {target} ({len(credentials)} kredensial)")

    for uname, pwd in credentials:
        data = _auto_fill(form, uname, pwd)
        try:
            if method == "post":
                r = client.post(target, data=data, allow_redirects=False, timeout=15)
            else:
                r = client.get(target, params=data, allow_redirects=False, timeout=15)
        except requests.RequestException:
            continue
        if _is_success(r):
            findings.append(Finding(
                "HIGH", "Kredensial login lemah",
                target, f"Login berhasil dengan `{uname}` / `{pwd}`.",
                f"status: {r.status_code}, location: {r.headers.get('Location', '')}",
            ))
            ok(f"Login berhasil: {uname} / {pwd}")
            break  # cukup satu; serangan sudah terkonfirmasi
    if not findings:
        warn("Tidak ada kredensial lemah yang berhasil")
    return findings


def brute_login_basic(base: str, client: KerisHTTP,
                      credentials: Optional[List[tuple]] = None) -> List[Finding]:
    """Brute-force basic auth."""
    if credentials is None:
        credentials = COMMON_CREDENTIALS
    findings = []
    info(f"Brute-force basic auth pada {base} ({len(credentials)} kredensial)")
    for uname, pwd in credentials:
        auth = (uname, pwd)
        try:
            r = client.get(base, auth=auth, allow_redirects=False, timeout=15)
        except requests.RequestException:
            continue
        if r.status_code not in (401, 403):
            findings.append(Finding(
                "HIGH", "Basic auth kredensial lemah",
                base, f"Akses diberikan untuk `{uname}` / `{pwd}`.",
                f"status: {r.status_code}",
            ))
            ok(f"Basic auth berhasil: {uname} / {pwd}")
            break
    if not findings:
        warn("Tidak ada kredensial lemah yang berhasil")
    return findings
