"""Auth bypass engine: multi-teknik uji kontrol akses.

Menguji endpoint yang terproteksi (401/403/redirect-login) dengan teknik
bypass yang umum:
- HTTP verb tampering (GET/POST/PUT/PATCH/OPTIONS/HEAD)
- normalisasi path: trailing slash, double slash, encoding, case
- manipulasi role param: ?admin=1, ?role=admin, header X-Forwarded-For
- path traversal ringan di URL: /admin/../admin, /./admin
- cookie/session downgrade: X-Original-URL, X-Rewrite-URL
- bypass dengan metode non-GET yang sering tidak dijaga middleware

Setiap sukses (respons berubah dari blokir ke 200/2xx/3xx konten)
dilaporkan sebagai temuan HIGH/CRITICAL.

GUARD: memerlukan `authorized=True`; tanpa itu modul menolak beroperasi.
"""

import copy
from typing import List, Optional
from urllib.parse import urlencode, urlparse

from keris.core.http import KerisHTTP
from keris.core.logger import debug, info, ok, warn
from keris.modules.scanner import Finding

VERB_TAMPERING = ["GET", "POST", "PUT", "PATCH", "OPTIONS", "HEAD", "TRACE"]
PATH_VARIANTS = [
    "{p}", "{p}/", "//{p}", "//{p}//", "/{p}/.", "/./{p}", "/{p}/..",
    "/%2e/{p}", "/{p}/%2e", "/{p}/%20", "/{p}%2f",
    "/%2e%2e/{p}", "/{p}/../{p}", "//{p}", "/.{p}",
]
ROLE_PARAMS = ["admin", "role", "isAdmin", "is_admin", "privilege", "access",
               "superuser", "root", "sudo", "group"]
ROLE_HEADERS = ["X-Original-URL", "X-Rewrite-URL", "X-Forwarded-For",
                "X-Forwarded-Host", "X-Custom-IP-Authorization"]

# teknik yang jelas-jelas berbahaya (header eksternal) dipisah agar
# user sadar; tidak mengirim ke host pihak ketiga.
VERB_METHODS = {"get": "GET", "post": "POST", "put": "PUT", "patch": "PATCH",
                "options": "OPTIONS", "head": "HEAD", "trace": "TRACE"}


def _blocked(body: str) -> bool:
    low = body.lower()
    return any(k in low for k in ("forbidden", "access denied", "unauthorized",
                                  "not authorized", "403", "401"))


def test_bypass(base: str, client: KerisHTTP,
                endpoints: Optional[List[str]] = None,
                authorized: bool = False) -> List[Finding]:
    """Uji bypass auth pada endpoint proteksi. Returns Finding list."""
    if not authorized:
        warn("Auth bypass memerlukan --authorized.")
        return []
    findings: List[Finding] = []
    targets = endpoints or ["/admin", "/dashboard", "/account", "/panel",
                            "/api/admin", "/internal", "/settings"]
    for ep in targets:
        full = base.rstrip("/") + ep if not ep.startswith("http") else ep
        # baseline: respons GET normal (harus diblokir)
        try:
            r0 = client.get(full, timeout=15)
        except Exception:
            continue
        base_code = r0.status_code
        base_len = len(r0.content or b"")
        # hanya uji endpoint yang memang tampak terproteksi
        if base_code not in (401, 403) and 200 <= base_code < 400 and base_len > 0:
            # mungkin terbuka bebas -> catat tapi jangan spam
            debug(f"  {ep}: status {base_code} (kemungkinan terbuka)")
            continue

        path = urlparse(full).path
        scheme_netloc = f"{urlparse(full).scheme}://{urlparse(full).netloc}"

        # 1. verb tampering
        for method in VERB_TAMPERING:
            try:
                r = client.request(method, full, timeout=15)
            except Exception:
                continue
            if r.status_code in (200, 201, 202, 203, 204) and \
                    not _blocked(r.text or "") and len(r.content or b"") > 0:
                findings.append(Finding(
                    "HIGH", f"Auth bypass via HTTP method tampering ({method})",
                    full,
                    f"Endpoint terproteksi (status {base_code}) merespons "
                    f"{r.status_code} untuk metode `{method}` — middleware "
                    "hanya memblokir GET.",
                    f"method={method}",
                    cwe="CWE-863",
                    references="https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/05-Authorization_Testing/02-Testing_for_Bypassing_Authorization_Schema",
                ))
                info(f"  verb bypass: {ep} via {method}")
                break  # cukup 1 bukti verb

        # 2. path normalization
        for variant in PATH_VARIANTS:
            cand = (scheme_netloc + variant.format(p=path))
            try:
                r = client.get(cand, timeout=15)
            except Exception:
                continue
            if r.status_code in (200, 201, 202, 203, 204) and \
                    not _blocked(r.text or "") and len(r.content or b"") > 0:
                findings.append(Finding(
                    "CRITICAL", "Auth bypass via path normalization",
                    full,
                    f"Varian path `{variant.format(p=path)}` melewati kontrol "
                    f"akses (status {r.status_code} vs baseline {base_code}).",
                    f"variant={variant}",
                    cwe="CWE-863",
                ))
                info(f"  path bypass: {variant.format(p=path)}")
                break

        # 3. role parameter pollution
        q = urlparse(full).query
        for rp in ROLE_PARAMS:
            for val in ("1", "true", "admin", "superadmin"):
                target = full
                sep = "&" if q else "?"
                target = f"{full}{sep}{rp}={val}"
                try:
                    r = client.get(target, timeout=15)
                except Exception:
                    continue
                if r.status_code in (200, 201, 202, 203, 204) and \
                        not _blocked(r.text or "") and len(r.content or b"") > 0:
                    findings.append(Finding(
                        "CRITICAL", "Auth bypass via role parameter pollution",
                        full,
                        f"Menambahkan `?{rp}={val}` membuka endpoint "
                        f"(status {r.status_code}). Kontrol akses bergantung "
                        "pada parameter client-side.",
                        f"param={rp}={val}",
                        cwe="CWE-639",
                    ))
                    info(f"  role bypass: {ep}?{rp}={val}")
                    break

        # 4. header-based
        for hdr in ROLE_HEADERS:
            try:
                r = client.get(full, headers={hdr: "127.0.0.1" if hdr == "X-Forwarded-For" else path}, timeout=15)
            except Exception:
                continue
            if r.status_code in (200, 201, 202, 203, 204) and \
                    not _blocked(r.text or "") and len(r.content or b"") > 0:
                findings.append(Finding(
                    "HIGH", "Auth bypass via header spoofing",
                    full,
                    f"Menambahkan header `{hdr}` membuka endpoint "
                    f"(status {r.status_code} vs {base_code}).",
                    f"header={hdr}",
                    cwe="CWE-290",
                ))
                info(f"  header bypass: {ep} via {hdr}")
                break

    return findings
