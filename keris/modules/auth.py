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
        end_m = re.search(r"</form>", html[m.end():], re.IGNORECASE)
        inner = html[m.end():m.end() + end_m.start()] if end_m else html[m.end():m.end() + 5000]
        fields = {}
        for inp in re.finditer(r"<input[^>]*>", inner, re.IGNORECASE):
            t = inp.group(0)
            name = re.search(r'name=["\']([^"\']*)["\']', t, re.IGNORECASE)
            type_ = re.search(r'type=["\']([^"\']*)["\']', t, re.IGNORECASE)
            value = re.search(r'value=["\']([^"\']*)["\']', t, re.IGNORECASE)
            if name:
                checked = re.search(r'checked\s*(?:=\s*["\']?[^"\']*["\']?)?', t, re.IGNORECASE)
                fields[name.group(1)] = {
                    "type": (type_.group(1) if type_ else "text").lower(),
                    "value": (value.group(1) if value else ""),
                    "checked": bool(checked),
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


def _field_score(name: str, kind: str) -> int:
    """Skor kecocokan field login. Semakin tinggi semakin cocok."""
    lower = name.lower()
    if kind == "password":
        if lower in ("password", "pass", "passwd", "pwd"):
            return 5
        if "password" in lower or "passwd" in lower:
            return 4
        if lower.startswith("pass") or "pass" in lower.split("_") or "pass" in lower.split("-"):
            return 3
        return 1
    # username/email
    if lower in ("username", "user", "email", "login", "userid", "user_id"):
        return 5
    if "username" in lower or "userid" in lower:
        return 4
    if lower in ("account", "acct"):
        return 3
    if lower.startswith("user") or "user" in lower.split("_") or "user" in lower.split("-"):
        return 3
    if "email" in lower or "mail" in lower:
        return 3
    return 1


def _auto_fill(form: dict, username: str, password: str) -> dict:
    """Isi field form dengan kredensial; pertahankan nilai hidden/CSRF.

    - Field dipilih berdasarkan skor kecocokan (bukan last-match-wins).
    - Checkbox/radio yang tidak dicentang tidak ikut dikirim.
    - Textarea/input kosong yang bukan user/pass/hidden tetap dikirim sesuai
      nilai aslinya (perilaku browser).
    """
    data = {}
    candidates_user = []
    candidates_pass = []
    for name, meta in form["fields"].items():
        kind = meta["type"]
        if kind == "password":
            candidates_pass.append((_field_score(name, "password"), name))
        elif kind == "text" or kind == "email":
            candidates_user.append((_field_score(name, "text"), name))

    user_key = max(candidates_user)[1] if candidates_user else None
    pass_key = max(candidates_pass)[1] if candidates_pass else None

    for name, meta in form["fields"].items():
        kind = meta["type"]
        if name == user_key:
            data[name] = username
        elif name == pass_key:
            data[name] = password
        elif kind in ("checkbox", "radio"):
            if meta.get("checked"):
                data[name] = meta["value"] or "on"
        elif kind in ("hidden", "submit", "button", "image", "reset"):
            data[name] = meta["value"]
        elif kind in ("text", "email", "tel", "url", "number", "date", "search", "textarea"):
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
