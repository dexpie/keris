"""Cloud bucket checker: deteksi bucket S3/GCS/Azure terbuka & misconfig."""

from typing import List, Optional

import requests

from keris.core.http import KerisHTTP
from keris.core.logger import debug, info, ok, warn
from keris.modules.scanner import Finding

# Nama bucket umum yang mungkin berkaitan dengan target
BUCKET_SUFFIXES = [
    "", "uploads", "assets", "media", "static", "public", "data", "backup",
    "storage", "files", "images", "docs", "prod", "staging", "test",
]


def _normalize_name(name: str) -> str:
    name = name.strip().lower()
    # ubah domain/URL menjadi bagian nama bucket
    for scheme in ("https://", "http://"):
        if name.startswith(scheme):
            name = name.split("/", 3)[2] if "://" in name else name
            name = name.split("/")[0]
            break
    name = name.replace(".", "-").replace("_", "-")
    return name.split(".")[0] if "." in name else name


def check_s3(name: str, timeout: float = 10.0) -> Optional[Finding]:
    base = f"https://{name}.s3.amazonaws.com/"
    try:
        r = requests.get(base, timeout=timeout)
    except requests.RequestException:
        return None
    if r.status_code == 200:
        # bucket publik: daftar objek
        return Finding(
            "HIGH", "Bucket S3 terbuka (public listing)",
            base, "Bucket S3 mengizinkan listing publik tanpa autentikasi.",
            f"status: 200, size: {len(r.content)}",
        )
    if r.status_code == 403 and "<ListBucketResult" not in r.text:
        # mungkin akses write terbuka (tidak bisa dipastikan tanpa PUT)
        return None
    return None


def check_gcs(name: str, timeout: float = 10.0) -> Optional[Finding]:
    base = f"https://storage.googleapis.com/{name}/"
    try:
        r = requests.get(base, timeout=timeout)
    except requests.RequestException:
        return None
    if r.status_code == 200 and "<ListBucketResult" in r.text:
        return Finding(
            "HIGH", "Bucket GCS terbuka (public listing)",
            base, "Bucket Google Cloud Storage mengizinkan listing publik.",
            "status: 200",
        )
    return None


def check_azure(name: str, timeout: float = 10.0) -> Optional[Finding]:
    base = f"https://{name}.blob.core.windows.net/?restype=container&comp=list"
    try:
        r = requests.get(base, timeout=timeout)
    except requests.RequestException:
        return None
    if r.status_code == 200 and "<EnumerationResults" in r.text:
        return Finding(
            "HIGH", "Container Azure Blob terbuka",
            base, "Container Azure Blob mengizinkan listing publik.",
            "status: 200",
        )
    return None


def check_buckets(base: str, client: KerisHTTP, name: Optional[str] = None) -> List[Finding]:
    """Cek bucket cloud untuk domain/proyek target."""
    findings = []
    candidates = []
    if name:
        candidates = [name]
    else:
        host = base.split("://")[1].split("/")[0] if "://" in base else base
        stem = _normalize_name(host)
        candidates = [f"{stem}{s}" for s in BUCKET_SUFFIXES if s]
        # juga coba domain langsung sebagai nama bucket
        candidates.insert(0, stem)

    info(f"Memeriksa {len(candidates)} nama bucket cloud ...")
    seen = set()
    for c in candidates:
        if c in seen:
            continue
        seen.add(c)
        for provider, fn in (("S3", check_s3), ("GCS", check_gcs), ("Azure", check_azure)):
            try:
                f = fn(c)
            except Exception:
                f = None
            if f:
                findings.append(f)
                severity_print(f)
                break
    if findings:
        ok(f"Bucket terbuka: {len(findings)}")
    else:
        warn("Tidak ada bucket cloud terbuka yang terdeteksi")
    return findings


def severity_print(f: Finding) -> None:
    from keris.core.logger import severity

    severity(f.severity, f"{f.title}: {f.endpoint}")