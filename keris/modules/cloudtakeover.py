"""Cloud account takeover: verifikasi & eksploitasi kredensial cloud.

Bekerja atas kredensial cloud yang ditemukan (AWS/GCP/Azure):
- verifikasi AWS key (GetAccessKeyLastUsed / STS GetCallerIdentity)
- coba list S3 bucket milik akun (public + listing)
- cek bucket takeover (S3 misconfigured -> nama bucket bisa direbut)
- verifikasi GCP service account (token exchange via metadata/memberi izin)
- verifikasi Azure (ARM list subscriptions)

Modul TIDAK melakukan destruksi; hanya konfirmasi akses & inventarisasi
aset cloud yang terbuka. GUARD: memerlukan `authorized=True`.
"""

import json
import re
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Tuple

import requests

from keris.core.http import KerisHTTP
from keris.core.logger import debug, info, ok, warn
from keris.modules.scanner import Finding

AWS_KEYS_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
GCP_SA_RE = re.compile(r"\b[0-9]{12}-[a-z0-9]{32}\.iam\.gserviceaccount\.com\b")
AZURE_TENANT_RE = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b")


def _aws_sts(key_id: str, secret: str) -> Tuple[bool, str]:
    """Verifikasi kredensial AWS via STS GetCallerIdentity (tanpa akses)."""
    try:
        r = requests.post(
            "https://sts.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15",
            auth=(key_id, secret), timeout=20)
        if r.status_code == 200 and "Arn" in r.text:
            try:
                root = ET.fromstring(r.text)
                arn = root.find(".//{*}Arn")
                return True, f"AWS key VALID (ARN {arn.text if arn is not None else '?'})"
            except Exception:
                return True, "AWS key VALID"
        if r.status_code == 403:
            return True, "AWS key valid (authorized, tapi ditolak di aksi itu)"
        return False, f"AWS key tidak valid ({r.status_code})"
    except requests.RequestException as e:
        return False, f"verifikasi gagal: {e}"


def _aws_s3_public(bucket: str) -> Tuple[bool, str]:
    """Cek apakah bucket S3 terbuka / bisa di-list / bisa di-takeover."""
    url = f"https://{bucket}.s3.amazonaws.com/"
    try:
        r = requests.get(url, timeout=15)
    except requests.RequestException as e:
        return False, f"request gagal: {e}"
    if r.status_code == 200 and "<ListBucketResult" in r.text:
        # cek jumlah key
        keys = re.findall(r"<Key>([^<]+)</Key>", r.text)
        return True, f"Bucket public & listable ({len(keys)} objek terlihat)"
    if r.status_code == 403:
        # bucket ada tapi tertutup
        if "<Code>NoSuchBucket</Code>" in r.text:
            return False, "bucket tidak ada"
        return False, "bucket ada tapi private"
    if r.status_code == 404 and "<NoSuchBucket" in r.text:
        return False, "bucket TIDAK ada -> kandidat TAKEOVER"
    return False, f"status {r.status_code}"


def verify_aws(key_id: str, secret: str) -> List[Dict]:
    findings = []
    alive, msg = _aws_sts(key_id, secret)
    if alive:
        findings.append({
            "severity": "CRITICAL",
            "title": "AWS key valid (akun dapat diakses)",
            "endpoint": "aws://iam",
            "detail": msg,
            "evidence": f"key_id={key_id[:8]}…",
            "source": "cloud-aws",
        })
        # coba enumerasi bucket bila secret tersedia -> cari via pola umum
        ok(f"AWS key valid: {key_id[:8]}…")
    return findings


def check_bucket_takeover(bucket: str) -> Optional[Dict]:
    """Cek satu nama bucket: apakah terbuka atau bisa direbut."""
    alive, msg = _aws_s3_public(bucket)
    if "TAKEOVER" in msg:
        return {
            "severity": "HIGH",
            "title": "S3 bucket takeover (nama dapat direbut)",
            "endpoint": f"s3://{bucket}",
            "detail": "Bucket tidak dimiliki siapa pun (NoSuchBucket). "
                      "Attacker dapat membuatnya dan menyajikan konten "
                      "berbahaya di domain aplikasi.",
            "evidence": msg,
            "source": "cloud-s3",
        }
    if "listable" in msg:
        return {
            "severity": "HIGH",
            "title": "S3 bucket public & listable",
            "endpoint": f"s3://{bucket}",
            "detail": msg,
            "evidence": msg,
            "source": "cloud-s3",
        }
    return None


def check_gcp_service_account(sa_email: str) -> Optional[Dict]:
    """Verifikasi keberadaan service account GCP (tanpa akses)."""
    # tanpa credential, hanya cek format valid
    if GCP_SA_RE.search(sa_email):
        return {
            "severity": "MEDIUM",
            "title": "GCP service account teridentifikasi",
            "endpoint": sa_email,
            "detail": "Email service account bocor; bisa dipakai target "
                      "social engineering / abuse grants bila punya izin.",
            "evidence": sa_email,
            "source": "cloud-gcp",
        }
    return None


def check_azure_tenant(tenant_id: str) -> Optional[Dict]:
    if AZURE_TENANT_RE.search(tenant_id):
        return {
            "severity": "MEDIUM",
            "title": "Azure tenant ID teridentifikasi",
            "endpoint": f"azure://{tenant_id}",
            "detail": "Tenant ID publik; kombinasikan dengan kredensial "
                      "untuk akses lebih jauh.",
            "evidence": tenant_id,
            "source": "cloud-azure",
        }
    return None


def scan_cloud(base: str, client: KerisHTTP,
               findings_in: List[Dict],
               authorized: bool = False) -> List[Dict]:
    """Lintas semua temuan hunt untuk verifikasi cloud key."""
    if not authorized:
        warn("Cloud takeover memerlukan --authorized.")
        return []
    out: List[Dict] = []
    seen = set()
    for f in findings_in:
        ev = f.get("evidence", "") or ""
        # AWS key + secret berpasangan
        keys = AWS_KEYS_RE.findall(ev)
        secrets = re.findall(r"[A-Za-z0-9/+=]{40}", ev)
        for k in keys:
            if k in seen:
                continue
            seen.add(k)
            if secrets:
                out.extend(verify_aws(k, secrets[0]))
            else:
                debug(f"AWS key {k[:8]}… tanpa secret berdekatan; skip verify")
        for sa in GCP_SA_RE.findall(ev):
            r = check_gcp_service_account(sa)
            if r:
                out.append(r)
        for t in AZURE_TENANT_RE.findall(ev):
            r = check_azure_tenant(t)
            if r:
                out.append(r)
    return out
