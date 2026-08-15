"""Modul passive recon: certificate transparency (crt.sh) dan whois.

Recon pasif tidak mengirim request ke target langsung, sehingga aman dan tidak
terdeteksi. Data diambil dari sumber publik:
  - crt.sh  : basis data sertifikat TLS (untuk menemukan subdomain)
  - whois   : informasi kepemilikan domain
"""

import json
import re
import socket
import time
from typing import Dict, List, Optional
from urllib.parse import urlencode

import requests

from keris.core.http import KerisHTTP
from keris.core.logger import info, ok, warn, debug
from keris.core.utils import domain_from_host, host_from_url

CRTSH_URL = "https://crt.sh/?{params}&output=json"


def crt_sh_subdomains(domain: str, timeout: float = 20.0) -> List[str]:
    """Cari subdomain dari basis data crt.sh (certificate transparency)."""
    params = urlencode({"q": f"%25.{domain}", "output": "json"})
    url = f"https://crt.sh/?{params}"
    for attempt in range(3):
        try:
            r = requests.get(url, timeout=timeout, headers={
                "User-Agent": "Mozilla/5.0 (Keris security scanner)",
                "Accept": "application/json",
            })
            if r.status_code != 200:
                debug(f"crt.sh status {r.status_code} (attempt {attempt + 1})")
                time.sleep(1 + attempt)
                continue
            data = r.json()
            break
        except (requests.RequestException, ValueError, json.JSONDecodeError) as e:
            debug(f"crt.sh gagal (attempt {attempt + 1}): {e}")
            time.sleep(1 + attempt)
    else:
        return []

    subs = set()
    for entry in data:
        name = entry.get("name_value", "")
        for line in name.split("\n"):
            line = line.strip().lower().lstrip("*.")
            if line.endswith(domain) and line != domain and "*" not in line:
                subs.add(line)
    return sorted(subs)


def whois_lookup(domain: str, timeout: float = 15.0) -> Optional[str]:
    """Ambil ringkasan whois domain (via public REST API)."""
    try:
        r = requests.get(
            f"https://rdap.iana.org/domain/{domain}",
            timeout=timeout,
            headers={"User-Agent": "Keris security scanner"},
        )
        if r.status_code == 200:
            data = r.json()
            return json.dumps(data, indent=2)[:2000]
    except requests.RequestException:
        pass
    # fallback: coba whois dari socket pada port 43 (jika tersedia)
    try:
        with socket.create_connection(("whois.iana.org", 43), timeout=timeout) as s:
            s.sendall((domain + "\r\n").encode())
            chunks = []
            while True:
                data = s.recv(4096)
                if not data:
                    break
                chunks.append(data.decode(errors="ignore"))
                if sum(len(c) for c in chunks) > 4000:
                    break
            return "".join(chunks)[:2000]
    except OSError:
        return None


def run_passive_recon(base: str) -> Dict:
    """Jalankan passive recon: subdomain via crt.sh + whois domain."""
    host = host_from_url(base)
    domain = domain_from_host(host)
    info(f"Passive recon untuk {domain or host}")

    result = {"domain": domain, "host": host, "subdomains": [], "whois": None}

    # domain kosong = target IP murni; tidak ada subdomain/whois yang valid
    if not domain:
        warn("Target berupa alamat IP; subdomain & whois dilewati")
        return result

    info("Querying crt.sh (certificate transparency)...")
    subs = crt_sh_subdomains(domain)
    if subs:
        ok(f"Subdomain ditemukan via crt.sh: {len(subs)}")
        result["subdomains"] = subs
        for s in subs[:15]:
            debug(f"  - {s}")
    else:
        warn("Tidak ada subdomain ditemukan via crt.sh")

    info("Querying whois...")
    whois = whois_lookup(domain)
    if whois:
        ok("Whois didapat")
        result["whois"] = whois
    else:
        warn("Whois tidak tersedia")

    return result
