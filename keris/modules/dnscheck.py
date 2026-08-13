"""DNS & email security check: MX, SPF, DMARC, DKIM, TXT, subdomain resolution."""

import socket
from typing import Dict, List, Optional

import dns.resolver
import requests

from keris.core.logger import debug, info, ok, warn

RESOLVER_TIMEOUT = 8.0


def _resolve(domain: str, rtype: str) -> List[str]:
    """Resolve record DNS. Mengembalikan daftar nilai string."""
    try:
        answers = dns.resolver.resolve(domain, rtype, lifetime=RESOLVER_TIMEOUT)
        return [str(r) for r in answers]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
            dns.resolver.NoNameservers, dns.resolver.LifetimeTimeout):
        return []
    except Exception:
        return []


def check_dns(domain: str) -> Dict:
    """Kumpulkan record DNS utama dan evaluasi postur keamanan email."""
    info(f"DNS check untuk {domain}")
    result: Dict = {"domain": domain, "records": {}, "issues": []}

    for rtype in ("A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA"):
        vals = _resolve(domain, rtype)
        if vals:
            result["records"][rtype] = vals

    # SPF
    spf = []
    for txt in _resolve(domain, "TXT"):
        if txt.startswith("v=spf1"):
            spf.append(txt)
    result["records"]["SPF"] = spf
    if not spf:
        result["issues"].append(("MEDIUM", "Tidak ada record SPF — email rawan spoofing."))
    elif "~all" in spf[0] or "-all" not in spf[0]:
        result["issues"].append(("LOW", "SPF menggunakan soft-fail (~all) — pertimbangkan hard-fail (-all)."))
    elif "+all" in spf[0]:
        result["issues"].append(("HIGH", "SPF menggunakan +all — semua host diizinkan mengirim email."))

    # DMARC
    dmarc = _resolve("_dmarc." + domain, "TXT")
    result["records"]["DMARC"] = dmarc
    if not dmarc:
        result["issues"].append(("MEDIUM", "Tidak ada record DMARC."))
    elif "p=none" in dmarc[0]:
        result["issues"].append(("LOW", "DMARC policy 'none' — belum menerapkan kebijakan."))

    # DKIM selector umum
    dkim_found = []
    for sel in ("default", "selector1", "selector2", "google", "k1", "s1"):
        if _resolve(f"{sel}._domainkey.{domain}", "TXT") or _resolve(f"{sel}._domainkey.{domain}", "CNAME"):
            dkim_found.append(sel)
    result["records"]["DKIM_selectors"] = dkim_found
    if not dkim_found:
        result["issues"].append(("LOW", "Tidak ada selector DKIM umum yang ditemukan."))

    # MX tanpa TLS untuk submission — info saja
    if result["records"].get("MX"):
        ok(f"MX: {len(result['records']['MX'])} record, SPF: {'ada' if spf else 'tidak'}, "
           f"DMARC: {'ada' if dmarc else 'tidak'}")
    else:
        warn("Tidak ada record MX (bukan mail server).")

    return result


def resolve_subdomains(domain: str, subdomains: List[str]) -> List[str]:
    """Resolve daftar subdomain -> host yang aktif (A/AAAA/CNAME)."""
    active = []
    for sub in subdomains:
        fqdn = f"{sub}.{domain}" if sub else domain
        for rtype in ("A", "AAAA", "CNAME"):
            vals = _resolve(fqdn, rtype)
            if vals:
                active.append({"subdomain": sub, "type": rtype, "records": vals})
                break
    return active
