"""Modul scanner: SQLi, XSS, SSRF, IDOR, rate limit, directory listing, auth bypass."""

import re
import time
from typing import Dict, List, Optional, Tuple

import requests

from keris.core.http import KerisHTTP
from keris.core.logger import info, ok, warn, debug, severity
from keris.core.utils import add_query, extract_urls, host_from_url, normalize_url
from keris.payloads import SQLI_ERROR, SQLI_TIME, XSS_PAYLOADS, SSRF_TARGETS

FINDING_LEVELS = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


class Finding:
    def __init__(self, severity: str, title: str, endpoint: str, detail: str, evidence: str = ""):
        self.severity = severity
        self.title = title
        self.endpoint = endpoint
        self.detail = detail
        self.evidence = evidence

    def to_dict(self) -> dict:
        return {
            "severity": self.severity,
            "title": self.title,
            "endpoint": self.endpoint,
            "detail": self.detail,
            "evidence": self.evidence[:500],
        }

    def __repr__(self):
        return f"[{self.severity}] {self.title} @ {self.endpoint}"


def _status_tag(code: int) -> str:
    if 200 <= code < 300:
        return "OK"
    if code == 401:
        return "UNAUTH"
    if code == 403:
        return "FORBIDDEN"
    if 400 <= code < 500:
        return "CLIENT_ERR"
    if 500 <= code:
        return "SERVER_ERR"
    return "REDIRECT"


def scan_sqli(client: KerisHTTP, url: str, param: str, time_delay: float = 5.0) -> List[Finding]:
    """Deteksi SQLi error-based dan time-based pada query param."""
    findings = []
    base_val = None
    # nilai baseline dari URL
    from urllib.parse import parse_qsl, urlparse
    for k, v in parse_qsl(urlparse(url).query):
        if k == param:
            base_val = v

    # baseline timing
    base_times = []
    for _ in range(2):
        t0 = time.monotonic()
        try:
            client.get(add_query(url, **{param: base_val or "1"}), timeout=15)
        except requests.RequestException:
            pass
        base_times.append(time.monotonic() - t0)
    baseline = max(base_times) if base_times else 1.0

    error_signatures = [
        "sql", "mysql", "postgres", "sqlite", "oracle", "syntax error",
        "unterminated", "quoted string", "pg_", "error in your sql",
        "warning: mysql", "psycopg", "odbc", "jdbc",
    ]

    for payload in SQLI_ERROR:
        try:
            r = client.get(add_query(url, **{param: payload}), timeout=15)
            body = r.text[:4000].lower()
            if any(sig in body for sig in error_signatures):
                findings.append(Finding(
                    "HIGH", "SQL Injection (error-based)",
                    url, f"Parameter `{param}` payload: {payload}",
                    body[:300],
                ))
                break
        except requests.RequestException:
            continue

    # time-based
    t0 = time.monotonic()
    try:
        client.get(add_query(url, **{param: SQLI_TIME[0]}), timeout=time_delay + 5)
        elapsed = time.monotonic() - t0
        if elapsed >= time_delay * 0.9:
            findings.append(Finding(
                "HIGH", "SQL Injection (time-based)",
                url, f"Parameter `{param}` delay {elapsed:.1f}s (baseline {baseline:.2f}s)",
                f"Payload: {SQLI_TIME[0]}",
            ))
    except requests.RequestException:
        pass

    return findings


def scan_xss(client: KerisHTTP, url: str, param: str) -> List[Finding]:
    """Deteksi reflected XSS sederhana pada query param."""
    findings = []
    for payload in XSS_PAYLOADS:
        try:
            r = client.get(add_query(url, **{param: payload}), timeout=15)
            if payload in r.text:
                # cek apakah dalam konteks yang bisa dieksekusi (tidak di-escape)
                findings.append(Finding(
                    "MEDIUM", "Reflected XSS (potensial)",
                    url, f"Parameter `{param}` merefleksikan payload tanpa escape",
                    f"Payload: {payload}",
                ))
                break
        except requests.RequestException:
            continue
    return findings


def scan_ssrf(client: KerisHTTP, url: str, param: str) -> List[Finding]:
    """Uji SSRF pada parameter yang menerima URL. Deteksi placeholder vs fetch internal."""
    findings = []
    for target in SSRF_TARGETS:
        try:
            r = client.get(add_query(url, **{param: target}), timeout=15)
            body = r.text[:2000]
            # tanda placeholder/svg fallback vs konten internal
            placeholder = ("<svg" in body.lower() and "xmlns" in body.lower()) or "not found" in body.lower() or len(body) < 100
            if not placeholder:
                findings.append(Finding(
                    "HIGH", "SSRF (terindikasi)",
                    url, f"Parameter `{param}` merespons target internal: {target}",
                    f"Status {r.status_code}, body: {body[:200]}",
                ))
                break
        except requests.RequestException:
            continue
    return findings


def scan_idor(client: KerisHTTP, base: str, endpoints: List[str]) -> List[Finding]:
    """Deteksi IDOR/BOLA: bandingkan respons dengan penggantian ID."""
    findings = []
    id_patterns = [
        (r"/\d+/?$", "123456"),
        (r"/([a-zA-Z0-9]{20,})/?$", "aaaaaaaaaaaaaaaaaaaa"),
    ]
    for ep in endpoints:
        for pattern, replacement in id_patterns:
            if not re.search(pattern, ep):
                continue
            full = base + ep
            try:
                r1 = client.get(full, timeout=12)
            except requests.RequestException:
                continue
            if r1.status_code not in (200, 201):
                continue
            try:
                r2 = client.get(re.sub(pattern, "/" + replacement, full), timeout=12)
            except requests.RequestException:
                continue
            if r2.status_code == 200 and r1.text[:5000] != r2.text[:5000]:
                # respons berbeda untuk ID berbeda -> indikasi BOLA/IDOR
                findings.append(Finding(
                    "MEDIUM", "IDOR/BOLA (terindikasi)",
                    full, "Respons berubah dengan penggantian ID tanpa otorisasi per-object.",
                    f"original: {r1.status_code}, replaced: {r2.status_code}",
                ))
            break
    return findings


def check_rate_limit(client: KerisHTTP, url: str, n: int = 8) -> Optional[Finding]:
    """Uji rate limiting: lakukan N request beruntun, cek apakah ada pemblokiran."""
    codes = []
    blocked = False
    for i in range(n):
        try:
            r = client.post(url, json={}, allow_redirects=False, timeout=10)
            codes.append(r.status_code)
        except requests.RequestException:
            codes.append(0)
        if codes[-1] in (429, 503) or any(h.lower() == "x-ratelimit-remaining" and v == "0" for h, v in getattr(r, "headers", {}).items()):
            blocked = True
            break
    if blocked:
        return None  # rate limiting ada -> bukan temuan
    # filter false positive: endpoint yang tidak ada (404/405) bukan indikasi celah
    if all(c in (404, 405, 0) for c in codes):
        return None
    # jika semua request diproses tanpa pembatasan -> temuan LOW
    return Finding(
        "LOW", "Tidak ada rate limiting",
        url, f"{n} request beruntun diproses tanpa pemblokiran. Status: {set(codes)}",
        f"status codes: {codes}",
    )


def check_directory_listing(client: KerisHTTP, url: str) -> Optional[Finding]:
    """Cek directory listing pada path."""
    try:
        r = client.get(url, timeout=12)
    except requests.RequestException:
        return None
    body = r.text[:4000]
    listing_marks = [
        "index of /", "directory listing", "parent directory",
        "listing directory", "&lt;dir&gt;", "&#8592;",
    ]
    for mark in listing_marks:
        if mark.lower() in body.lower():
            return Finding(
                "HIGH", "Directory listing terbuka",
                url, f"Listing direktori terekspos: {mark}",
                f"Status {r.status_code}",
            )
    return None


def check_auth_bypass(client: KerisHTTP, url: str) -> Optional[Finding]:
    """Uji akses admin/sensitif tanpa auth dan metode alternatif."""
    variants = [
        (url + "/", "GET"),
        (url, "GET"),
        (url, "POST"),
        (url, "PUT"),
        (url, "OPTIONS"),
        (url.rstrip("/") + "/..;/admin", "GET"),  # tomcat path param bypass
        (url.rstrip("/") + "/admin", "GET"),
    ]
    seen = set()
    for target, method in variants:
        key = (target, method)
        if key in seen:
            continue
        seen.add(key)
        try:
            r = client.request(method, target, allow_redirects=False, timeout=12)
        except requests.RequestException:
            continue
        if method not in ("GET", "POST"):
            continue
        if r.status_code != 200:
            continue
        body = (r.content or b"")
        stripped = body.strip()
        if len(stripped) < 10:
            continue  # respons kosong / placeholder
        # respons nyata tanpa auth pada path admin -> indikasi auth bypass
        return Finding(
            "HIGH", "Auth bypass (terindikasi)",
            target, f"{method} mengembalikan 200 tanpa autentikasi pada path terproteksi.",
            f"size: {len(body)}, content: {stripped[:200]}",
        )
    return None
