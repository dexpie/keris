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


def _is_success(response: requests.Response, login_url: str = "") -> bool:
    if response.status_code in (301, 302, 303, 307, 308):
        # redirect setelah login: hanya dianggap berhasil bila tidak menuju
        # kembali ke halaman login (banyak aplikasi redirect ke /login saat gagal)
        loc = response.headers.get("Location", "").split("?")[0].lower()
        if not loc:
            return False
        if login_url and loc.rstrip("/") == login_url.rstrip("/").lower():
            return False
        if any(m in loc for m in ("/login", "/signin", "/auth", "error")):
            return False
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
        if _is_success(r, page):
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


# --- brute-force diperluas (--brute-extended) ---

# Wordlist lebih besar; tetap dibatasi agar tidak menjadi alat spam massal.
EXTENDED_CREDENTIALS = COMMON_CREDENTIALS + [
    ("admin", "1234"), ("admin", "admin1"), ("admin", "administrator"),
    ("admin", "password1"), ("admin", "password123"), ("admin", "root"),
    ("admin", "toor"), ("admin", "12345"), ("admin", "123456789"),
    ("admin", "welcome"), ("admin", "welcome1"), ("admin", "letmein1"),
    ("admin", "Passw0rd"), ("admin", "P@ssw0rd"), ("admin", "s3cret"),
    ("admin", "hunter2"), ("admin", "default"), ("admin", "temp"),
    ("admin", "temporary"), ("admin", "root123"), ("admin", "0000"),
    ("administrator", "admin"), ("administrator", "administrator"),
    ("administrator", "password"), ("root", "admin"), ("root", "123456"),
    ("root", "root123"), ("root", "toor"), ("root", "changeme"),
    ("manager", "manager"), ("manager", "password"), ("manager", "123456"),
    ("support", "support"), ("support", "password"), ("support", "123456"),
    ("operator", "operator"), ("operator", "password"), ("operator", "123456"),
    ("webmaster", "webmaster"), ("webmaster", "password"), ("webmaster", "123456"),
    ("superadmin", "admin"), ("superadmin", "password"), ("superadmin", "123456"),
    ("backup", "backup"), ("backup", "password"), ("backup", "123456"),
    ("dev", "dev"), ("dev", "developer"), ("dev", "password"),
    ("test", "password"), ("test", "1234"), ("test", "admin"),
    ("user", "123456"), ("user", "user1"), ("user", "password1"),
    ("admin", "admin@123"), ("admin", "admin123!"), ("admin", "abc123"),
    ("admin", "qwerty123"), ("admin", "123qwe"), ("admin", "zaq12wsx"),
    ("admin", "1qaz2wsx"), ("admin", "Passw0rd!"), ("admin", "Welcome1"),
    ("admin", "changeme1"), ("admin", "letmein123"),
]

# Username umum untuk enumerasi
USERNAME_WORDS = [
    "admin", "administrator", "root", "test", "user", "guest", "demo",
    "manager", "support", "webmaster", "superadmin", "operator", "backup",
    "dev", "sysadmin", "info", "postmaster", "helpdesk", "service",
]

# Marker yang membedakan "username valid tapi password salah" dari "user tidak ada"
ENUM_VALID_MARKERS = [
    b"password", b"incorrect password", b"wrong password", b"pass salah",
    b"salah kata sandi", b"credentials", b"kredensial", b"reset",
]
ENUM_INVALID_MARKERS = [
    b"user not found", b"username not found", b"akun tidak ditemukan",
    b"no account", b"doesn't exist", b"tidak terdaftar", b"invalid username",
]


def enumerate_usernames(base: str, client: KerisHTTP,
                        login_paths: Optional[List[str]] = None,
                        usernames: Optional[List[str]] = None) -> List[Finding]:
    """Deteksi enumerasi username dari perbedaan respons login form.

    Respons berbeda untuk username valid vs tidak valid (marker khusus)
    menandakan endpoint membocorkan keberadaan akun.
    """
    usernames = usernames or USERNAME_WORDS
    findings = []
    paths = login_paths or ["/login", "/signin", "/auth", "/account/login"]
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
        warn("Form login tidak ditemukan; lewati enumerasi username")
        return findings

    target = urljoin(page, form["action"]) if form["action"] else page
    method = form["method"]
    info(f"Enumerasi username pada {target} ({len(usernames)} nama)")

    # baseline dengan username jelas-tidak-ada
    base_resp = None
    probe = "zzzzznonexistentuser12345"
    data = _auto_fill(form, probe, "WrongPass123!")
    try:
        base_resp = client.post(target, data=data, allow_redirects=False, timeout=15) if method == "post" \
            else client.get(target, params=data, allow_redirects=False, timeout=15)
    except requests.RequestException:
        base_resp = None

    for uname in usernames:
        data = _auto_fill(form, uname, "WrongPass123!")
        try:
            r = client.post(target, data=data, allow_redirects=False, timeout=15) if method == "post" \
                else client.get(target, params=data, allow_redirects=False, timeout=15)
        except requests.RequestException:
            continue
        body = r.content[:2000]
        if base_resp is not None and (r.status_code != base_resp.status_code or
                                      abs(len(body) - len((base_resp.content or b"")[:2000])) > 60):
            findings.append(Finding(
                "MEDIUM", "Username enumeration",
                target, f"Respons berbeda untuk username `{uname}` — endpoint "
                        "membocorkan keberadaan akun.",
                f"status: {base_resp.status_code}->{r.status_code}, "
                f"len: {len((base_resp.content or b'')[:2000])}->{len(body)}",
            ))
            debug(f"  enum: {uname} berbeda")
        elif any(m in body for m in ENUM_VALID_MARKERS):
            findings.append(Finding(
                "MEDIUM", "Username enumeration (marker valid)",
                target, f"Username `{uname}` memicu marker 'password salah' — "
                        "akun kemungkinan valid.",
                f"uname={uname}",
            ))
            debug(f"  enum marker: {uname}")
    return findings


def brute_extended(base: str, client: KerisHTTP,
                   credentials: Optional[List[tuple]] = None,
                   login_paths: Optional[List[str]] = None,
                   throttle: float = 0.1) -> List[Finding]:
    """Brute-force dengan wordlist lebih besar + throttle.

    Serangan aktif, hanya untuk target berizin. Throttle default 0.1s tetap
    menjaga kesopanan; dengan `--authorized` di CLI throttle bisa 0.
    """
    credentials = credentials or EXTENDED_CREDENTIALS
    findings = []
    paths = login_paths or ["/login", "/signin", "/auth", "/account/login"]
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
        warn("Form login tidak ditemukan; lewati brute-force extended")
        return findings

    target = urljoin(page, form["action"]) if form["action"] else page
    method = form["method"]
    info(f"Brute-force extended pada {target} ({len(credentials)} kredensial, "
         f"throttle {throttle}s)")

    import time as _time

    for uname, pwd in credentials:
        data = _auto_fill(form, uname, pwd)
        try:
            if method == "post":
                r = client.post(target, data=data, allow_redirects=False, timeout=15)
            else:
                r = client.get(target, params=data, allow_redirects=False, timeout=15)
        except requests.RequestException:
            continue
        if _is_success(r, page):
            findings.append(Finding(
                "HIGH", "Kredensial login lemah (brute-force extended)",
                target, f"Login berhasil dengan `{uname}` / `{pwd}`.",
                f"status: {r.status_code}, location: {r.headers.get('Location', '')}",
            ))
            ok(f"Login berhasil: {uname} / {pwd}")
            break
        if throttle > 0:
            _time.sleep(throttle)
    if not findings:
        warn("Tidak ada kredensial lemah dari wordlist extended")
    return findings
