"""Validasi kredensial yang ditemukan: coba login sungguhan (authorized only).

Dipakai oleh `keris credcheck`. Kredensial bisa berasal dari hasil hunt,
bruteforce, atau daftar manual. Mencoba ke form login dan basic auth,
kemudian melaporkan mana yang BENER-BENER BERHASIL.
"""

from typing import Dict, List, Optional

import requests

from ..core.logger import debug, error, info, ok, warn

try:
    from keris.modules.auth import (
        _extract_forms,
        _pick_login_candidate,
        _auto_fill,
    )
    HAS_AUTH = True
except Exception:
    HAS_AUTH = False


def _normalize_login(base: str) -> List[str]:
    """Daftar endpoint login yang umum."""
    return [
        base.rstrip("/") + p
        for p in ("/login", "/signin", "/auth", "/api/auth/login",
                  "/wp-login.php", "/user/login", "/admin/login")
    ]


def _find_login_page(base: str, client: requests.Session) -> Optional[str]:
    """Kembalikan URL halaman yang mengandung form login."""
    for url in _normalize_login(base):
        try:
            r = client.get(url, timeout=8)
            if r.status_code == 200 and ("<form" in r.text.lower()
                                         or "<input" in r.text.lower()):
                return url
        except requests.RequestException:
            continue
    return None


def _try_form_login(base: str, client: requests.Session,
                    username: str, password: str,
                    login_url: str) -> Dict:
    """Coba login form. Kembalikan {ok, status, body_sample}."""
    result = {"ok": False, "status": 0, "url": login_url, "method": "form"}
    if not HAS_AUTH:
        return result
    try:
        r = client.get(login_url, timeout=8)
        forms = _extract_forms(r.text)
        form = _pick_login_candidate(forms)
        if form is None:
            return result
        action = form.get("action") or ""
        method = (form.get("method") or "get").lower()
        if not action.startswith("http"):
            action = base.rstrip("/") + "/" + action.lstrip("/")
        data = _auto_fill(form, username, password)
        if method.lower() == "get":
            resp = client.get(action, params=data, timeout=8, allow_redirects=True)
        else:
            resp = client.post(action, data=data, timeout=8, allow_redirects=True)
        result["status"] = resp.status_code
        result["ok"] = resp.status_code in (200, 302, 303) and (
            "logout" in resp.text.lower()
            or "welcome" in resp.text.lower()
            or "dashboard" in resp.text.lower()
            or "salah" not in resp.text.lower() and "invalid" not in resp.text.lower()
        )
        result["body_sample"] = resp.text[:120]
    except requests.RequestException as e:
        result["body_sample"] = str(e)[:120]
    return result


def _try_basic_auth(base: str, client: requests.Session,
                    username: str, password: str) -> Dict:
    """Coba basic auth via header."""
    result = {"ok": False, "status": 0, "url": base, "method": "basic"}
    try:
        r = client.get(base, auth=(username, password), timeout=8, allow_redirects=True)
        result["status"] = r.status_code
        result["ok"] = r.status_code in (200, 302, 303) and "401" not in str(r.status_code)
        result["body_sample"] = r.text[:120]
    except requests.RequestException as e:
        result["body_sample"] = str(e)[:120]
    return result


def validate_credentials(base: str,
                         credentials: List[tuple],
                         client: Optional[requests.Session] = None,
                         auth_type: str = "form") -> List[Dict]:
    """Coba setiap (username, password) ke target.

    Returns list hasil: {username, password, ok, status, url, method}.
    Hanya dipakai bila pengguna sudah punya izin tertulis.
    """
    sess = client or requests.Session()
    results: List[Dict] = []
    seen: set = set()

    login_url = _find_login_page(base, sess) if auth_type == "form" else None
    if auth_type == "form" and not login_url:
        debug(f"Tidak menemukan halaman login, coba basic auth ke {base}")
        auth_type = "basic"

    for user, pw in credentials:
        key = (user.strip().lower(), pw)
        if key in seen:
            continue
        seen.add(key)
        if auth_type == "form":
            res = _try_form_login(base, sess, user, pw, login_url or base)
        else:
            res = _try_basic_auth(base, sess, user, pw)
        res["username"] = user
        res["password"] = pw
        results.append(res)
        if res["ok"]:
            ok(f"LOGIN BERHASIL: {user}:{pw} ({res['url']})")
        else:
            debug(f"gagal: {user}:{pw} ({res.get('status')})")
    return results


def extract_creds_from_findings(findings: List[Dict]) -> List[tuple]:
    """Ambil pasangan user:pass dari temuan (misal hasil hunt/brute)."""
    creds: List[tuple] = []
    for f in findings:
        for field in ("evidence", "detail", "description"):
            text = f.get(field) or ""
            import re
            for m in re.finditer(r"([\w.@+-]{2,64}):([^\s]{4,128})", text):
                creds.append((m.group(1), m.group(2)))
    return creds
