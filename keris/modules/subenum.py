"""Subdomain enumeration + wildcard DNS detection.

Menggabungkan tiga sumber:
- crt.sh (certificate transparency) - pasif
- brute wordlist - aktif
- wildcard DNS detection: mendeteksi apakah resolver mengembalikan IP untuk
  subdomain sembarang (wildcard), yang membuat hasil brute menyesatkan.

Menghasilkan daftar subdomain hidup + peringatan wildcard. Hasilnya bisa
dikorelasikan dengan modul takeover yang sudah ada.
"""

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple

import requests

from keris.core.logger import debug, info, ok, warn
from keris.modules.scanner import Finding
from keris.core.utils import host_from_url, domain_from_host

CRTSH_URL = "https://crt.sh/?q=%25.{domain}&output=json"


def _resolve(host: str, timeout: float = 5.0) -> List[str]:
    try:
        return sorted({a[4][0] for a in socket.getaddrinfo(host, None)})
    except socket.gaierror:
        return []


def detect_wildcard(domain: str, timeout: float = 5.0) -> Tuple[bool, List[str]]:
    """Cek wildcard DNS: resolve subdomain acak (nonce)."""
    import random
    import string

    nonce = "".join(random.choices(string.ascii_lowercase, k=12))
    probe = f"{nonce}.{domain}"
    ips = _resolve(probe, timeout=timeout)
    if not ips:
        return False, []
    # cek apakah IP wildcard = IP domain utama (kebanyakan wildcard)
    root_ips = _resolve(domain, timeout=timeout)
    if root_ips and set(ips) & set(root_ips):
        return True, ips
    return True, ips


def crt_sh(domain: str, timeout: float = 20.0) -> List[str]:
    """Ambil subdomain dari crt.sh (certificate transparency)."""
    try:
        r = requests.get(CRTSH_URL.format(domain=domain), timeout=timeout)
        if r.status_code != 200:
            return []
        data = r.json()
    except (requests.RequestException, ValueError):
        return []
    subs = set()
    for entry in data:
        name = entry.get("name_value", "")
        for part in name.split("\n"):
            part = part.strip().lower()
            if part and part.endswith("." + domain) and part.count(".") > 1:
                subs.add(part)
    return sorted(subs)


def brute(domain: str, wordlist: List[str], max_workers: int = 20,
          timeout: float = 5.0) -> List[str]:
    """Resolve subdomain dari wordlist (aktif)."""
    found: List[str] = []

    def one(sub: str) -> Optional[str]:
        fqdn = f"{sub}.{domain}"
        if _resolve(fqdn, timeout=timeout):
            return fqdn
        return None

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(one, s): s for s in wordlist}
        for fut in as_completed(futures):
            try:
                res = fut.result()
            except Exception:
                continue
            if res:
                found.append(res)
    return sorted(found)


def _dedup(hosts: List[str]) -> List[str]:
    return list(dict.fromkeys(h.lower() for h in hosts))


def enumerate_subdomains(domain: str, wordlist: Optional[List[str]] = None,
                         use_crt: bool = True, max_workers: int = 20,
                         timeout: float = 5.0) -> Dict:
    """Enumerasi subdomain lengkap + wildcard detection."""
    info(f"=== SUBDOMAIN ENUM ({domain}) ===")
    wildcard, wildcard_ips = detect_wildcard(domain, timeout=timeout)
    if wildcard:
        warn(f"Wildcard DNS terdeteksi ({wildcard_ips[:3]}). Hasil brute bisa menyesatkan.")

    subs: List[str] = []
    if use_crt:
        crt = crt_sh(domain, timeout=timeout)
        if crt:
            ok(f"crt.sh: {len(crt)} subdomain")
            subs.extend(crt)
        else:
            debug("crt.sh tidak mengembalikan data")

    if wordlist:
        br = brute(domain, wordlist, max_workers=max_workers, timeout=timeout)
        if br:
            ok(f"Brute: {len(br)} subdomain hidup")
            subs.extend(br)

    subs = _dedup(subs)
    if subs:
        for s in subs[:15]:
            info(f"  {s} -> {_resolve(s, timeout=timeout)[:2]}")
    else:
        warn("Tidak ada subdomain ditemukan")

    return {"domain": domain, "wildcard": wildcard, "wildcard_ips": wildcard_ips,
            "subdomains": subs, "count": len(subs)}


def subenum_findings(domain: str, result: Dict) -> List[Finding]:
    findings: List[Finding] = []
    if result.get("wildcard"):
        findings.append(Finding(
            "LOW", f"Wildcard DNS aktif pada {domain}",
            domain,
            "Resolver mengembalikan IP untuk subdomain acak. Enumerasi subdomain "
            "dan detection takeover harus memverifikasi di level HTTP.",
            f"IP: {', '.join(result['wildcard_ips'][:3])}",
        ))
    subs = result.get("subdomains", [])
    if len(subs) >= 20:
        findings.append(Finding(
            "INFO", f"Permukaan serangan luas: {len(subs)} subdomain",
            domain,
            f"{len(subs)} subdomain ditemukan; perbesar cakupan review.",
            ", ".join(subs[:5]),
        ))
    return findings