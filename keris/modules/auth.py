"""Helper auth: membangun header/sesi + auto-login form."""

import re
from typing import Dict, List, Optional, Tuple

import requests
from urllib.parse import urljoin

from keris.core.http import KerisHTTP
from keris.core.logger import debug, info, warn, ok


def build_client(
    token: Optional[str] = None,
    cookie: Optional[str] = None,
    username: Optional[str] = None,
    password: Optional[str] = None,
    proxy: Optional[str] = None,
    insecure: bool = False,
    timeout: float = 20.0,
) -> KerisHTTP:
    """Bangun KerisHTTP dengan auth yang diberikan."""
    basic = (username, password) if username and password else None
    return KerisHTTP(
        token=token,
        cookie=cookie,
        basic_auth=basic,
        proxy=proxy,
        insecure=insecure,
        timeout=timeout,
    )


def parse_cookie_string(cookie_str: str) -> dict:
    """Parse string cookie menjadi dict."""
    result = {}
    for part in cookie_str.split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            result[k.strip()] = v.strip()
    return result


def _extract_forms(html: str) -> List[dict]:
    """Ekstrak form dari HTML beserta field-nya."""
    forms = []
    for m in re.finditer(r"<form[^>]*>", html, re.IGNORECASE):
        tag = m.group(0)
        action = re.search(r'action=["\']([^"\']*)["\']', tag, re.IGNORECASE)
        method = re.search(r'method=["\']([^"\']*)["\']', tag, re.IGNORECASE)
        end = html.find("</form>", m.end())
        inner = html[m.end():end] if end != -1 else html[m.end():m.end() + 5000]
        fields = {}
        for inp in re.finditer(r"<input[^>]*>", inner, re.IGNORECASE):
            t = inp.group(0)
            name = re.search(r'name=["\']([^"\']*)["\']', t, re.IGNORECASE)
            type_ = re.search(r'type=["\']([^"\']*)["\']', t, re.IGNORECASE)
            value = re.search(r'value=["\']([^"\']*)["\']', t, re.IGNORECASE)
            if name:
                fields[name.group(1)] = {
                    "type": (type_.group(1) if type_ else "text").lower(),
                    "value": (value.group(1) if value else ""),
                }
        forms.append({
            "action": action.group(1) if action else "",
            "method": (method.group(1) if method else "get").lower(),
            "fields": fields,
        })
    return forms


def _pick_login_candidate(forms: List[dict]) -> Optional[dict]:
    """Pilih form yang paling mirip login (ada input user + password)."""
    for f in forms:
        names = {k.lower() for k in f["fields"]}
        has_user = any("email" in n or "user" in n or "login" in n or "username" in n for n in names)
        has_pass = any("pass" in n for n in names)
        if has_user and has_pass:
            return f
    return None


def _auto_fill(form: dict, username: str, password: str) -> dict:
    """Isi field form dengan kredensial; pertahankan nilai hidden/CSRF."""
    data = {}
    user_key = pass_key = None
    for name, meta in form["fields"].items():
        lower = name.lower()
        if "pass" in lower:
            pass_key = name
        elif "email" in lower or "user" in lower or "login" in lower or "username" in lower:
            user_key = name
    for name, meta in form["fields"].items():
        if name == user_key:
            data[name] = username
        elif name == pass_key:
            data[name] = password
        elif meta["type"] in ("hidden", "submit", "button"):
            data[name] = meta["value"]
        else:
            data[name] = meta["value"]
    return data


def auto_login(base: str, username: str, password: str,
               login_paths: Optional[List[str]] = None,
               timeout: float = 20.0) -> KerisHTTP:
    """Coba login otomatis lewat form HTML dan kembalikan client ber-sesi.

    Strategi: buka halaman login, temukan form, isi kredensial, submit,
    lalu ambil cookie/token dari sesi. Mengembalikan KerisHTTP dengan sesi
    yang sudah terautentikasi (cookie otomatis dilacak oleh session).
    """
    paths = login_paths or ["/login", "/signin", "/auth", "/account/login", "/"]
    client = KerisHTTP(timeout=timeout)
    found_form = None
    login_page = None

    for path in paths:
        url = urljoin(base, path)
        try:
            r = client.get(url, timeout=timeout)
            if r.status_code != 200:
                continue
            forms = _extract_forms(r.text)
            candidate = _pick_login_candidate(forms)
            if candidate:
                found_form = candidate
                login_page = url
                break
        except requests.RequestException:
            continue

    if not found_form:
        warn("Form login tidak ditemukan di halaman yang dicoba")
        return client

    info(f"Form login ditemukan di {login_page}")
    target = urljoin(login_page, found_form["action"]) if found_form["action"] else login_page
    data = _auto_fill(found_form, username, password)

    # submit — pertahankan sesi yang sama (cookie CSRF) di session client
    try:
        if found_form["method"] == "post":
            r = client.post(target, data=data, allow_redirects=True, timeout=timeout)
        else:
            r = client.get(target, params=data, allow_redirects=True, timeout=timeout)
    except requests.RequestException as e:
        warn(f"Login gagal (network): {e}")
        return client

    if r.status_code == 200:
        ok(f"Login diproses (status {r.status_code})")

    # cek apakah kita sudah authenticated: coba beberapa endpoint umum
    probe = ["/dashboard", "/account", "/api/me", "/profile", "/api/user"]
    authed = False
    for p in probe:
        try:
            pr = client.get(urljoin(base, p), allow_redirects=False, timeout=10)
            if pr.status_code == 200:
                authed = True
                break
        except requests.RequestException:
            continue

    if authed:
        ok("Autentikasi terlihat berhasil (endpoint terproteksi merespons 200)")
    else:
        warn("Belum terkonfirmasi login; sesi disimpan untuk percobaan lanjutan")

    return client
