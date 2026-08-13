"""Subdomain takeover detection: cari CNAME menggantung ke layanan pihak ketiga.

Jika record CNAME menunjuk ke layanan (GitHub Pages, S3, Heroku, Azure, dll)
tapi layanan tersebut TIDAK memilikinya (respons khusus), subdomain dapat
di-takeover oleh penyerang.
"""

import dns.resolver
import requests
from typing import Dict, List, Optional

from keris.core.http import KerisHTTP
from keris.core.logger import debug, info, ok, warn
from keris.modules.scanner import Finding

# layanan umum + indikator respons "not owned"
TAKEOVER_SIGNATURES = [
    ("GitHub Pages", ["github.io"], ["404: There isn't a GitHub Pages site here", "There isn't a GitHub Pages site"]),
    ("AWS S3", ["s3.amazonaws.com", "s3-website"], ["NoSuchBucket", "does not exist"]),
    ("Heroku", ["herokudns.com", "herokussl.com"], ["There's nothing here, yet", "No such app"]),
    ("Azure", ["azurewebsites.net", "cloudapp.azure.com"], ["404 Web Site not found"]),
    ("CloudFront", ["cloudfront.net"], ["Bad request", "ERROR: The request could not be satisfied"]),
    ("Fastly", ["fastly.net", "global.fastly.net"], ["Fastly error: unknown domain"]),
    ("Pantheon", ["pantheonsite.io"], ["The gods are angry"]),
    ("Shopify", ["shops.myshopify.com"], ["Sorry, this shop is currently unavailable"]),
    ("WordPress.com", ["wordpress.com"], ["Domain mapping is not configured", "does not exist"]),
    ("Netlify", ["netlify.app"], ["Not Found - Request ID"]),
    ("Bitbucket", ["bitbucket.io"], ["Repository not found"]),
    ("Surge.sh", ["surge.sh"], ["project not found"]),
    ("Zendesk", ["zendesk.com"], ["Help Center Closed"]),
    ("Cargo", ["cargocollective.com"], ["404 Not Found"]),
]

DNS_TIMEOUT = 8.0


def _cname_targets(host: str) -> List[str]:
    try:
        answers = dns.resolver.resolve(host, "CNAME", lifetime=DNS_TIMEOUT)
        return [str(a).rstrip(".").lower() for a in answers]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
            dns.resolver.NoNameservers, dns.resolver.LifetimeTimeout):
        return []
    except Exception:
        return []


def _match_service(cname: str) -> Optional[tuple]:
    cname = cname.lower()
    for name, domains, markers in TAKEOVER_SIGNATURES:
        for d in domains:
            if cname == d or cname.endswith("." + d):
                return name, markers
    return None


def check_takeover(host: str, client: KerisHTTP, timeout: float = 15.0) -> List[Finding]:
    """Periksa subdomain untuk kemungkinan takeover."""
    findings = []
    info(f"Cek subdomain takeover: {host}")
    cnames = _cname_targets(host)
    if not cnames:
        debug(f"{host}: tidak ada CNAME (bukan kandidat)")
        return findings

    for cname in cnames:
        svc = _match_service(cname)
        if not svc:
            debug(f"{host}: CNAME {cname} bukan layanan takeover umum")
            continue
        name, markers = svc
        try:
            r = requests.get(f"http://{host}/", timeout=timeout,
                             headers={"User-Agent": "Keris-takeover-check"})
        except requests.RequestException as e:
            debug(f"{host}: koneksi gagal {e}")
            continue
        body = r.text[:2000]
        if any(m.lower() in body.lower() for m in markers):
            findings.append(Finding(
                "HIGH", "Subdomain takeover kemungkinan besar",
                f"http://{host}/",
                f"Subdomain {host} menunjuk ke {name} (CNAME {cname}) tapi "
                "layanan merespons 'tidak dimiliki' — dapat di-takeover.",
                f"cname={cname}, status={r.status_code}",
            ))
            ok(f"Takeover terdeteksi: {host} -> {name}")
        else:
            debug(f"{host}: CNAME ke {name} tapi layanan tampak aktif")
    return findings