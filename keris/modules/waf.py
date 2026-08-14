"""Deteksi & fingerprinting WAF (Web Application Firewall).

Mengirimkan request polos + payload berbahaya umum, lalu mencocokkan
header/cookie/error page/challenge dengan tanda tangan WAF populer.
"""

import re
from typing import Dict, List, Optional
from urllib.parse import urlparse

from ..core.logger import debug, info, ok, warn

# tanda tangan per vendor WAF
SIGNATURES = {
    "Cloudflare": {
        "headers": [r"cf-ray", r"server:\s*cloudflare", r"__cfduid", r"cf-cache-status"],
        "body": [r"attention required!? ?cloudflare", r"cf-error-details", r"cloudflare ray id"],
    },
    "AWS WAF / CloudFront": {
        "headers": [r"x-amzn-requestid", r"awswaf-token", r"x-cache:.*cloudfront"],
        "body": [r"request blocked", r"403 ERROR"],
    },
    "Akamai Ghost": {
        "headers": [r"akamai", r"x-akamai-", r"ak_bmsc", r"bm_sz"],
        "body": [r"akamai", r"ghost watermarked"],
    },
    "Sucuri CloudProxy": {
        "headers": [r"x-sucuri-", r"sucuri"],
        "body": [r"sucuri web site firewall", r"cloudproxy"],
    },
    "ModSecurity / OWASP CRS": {
        "headers": [r"mod_security", r"x-modsec", r"sec-request"],
        "body": [r"modsecurity", r"not acceptable", r"owasp"],
    },
    "F5 BIG-IP ASM": {
        "headers": [r"x-wa-info", r"x-cnection", r"f5", r"bigip"],
        "body": [r"the requested url was rejected", r"support id"],
    },
    "Imperva Incapsula": {
        "headers": [r"x-cdn: incapsula", r"incap_ses", r"visid_incap"],
        "body": [r"incapsula", r"contact support for\s*information"],
    },
    "Fortinet FortiWeb": {
        "headers": [r"fortiwaf", r"x-request-uri", r"fortiwafsid"],
        "body": [r"fortiweb", r"top page: \d+"],
    },
    "Barracuda WAF": {
        "headers": [r"barracuda", r"x-barracuda-"],
        "body": [r"barracuda", r"blocked by barracuda"],
    },
    "Wordfence": {
        "headers": [r"wf-", r"wordfence"],
        "body": [r"wordfence", r"wordfence blocked"],
    },
    "Radware AppWall": {
        "headers": [r"radware", r"appwall"],
        "body": [r"appwall", r"request blocked by appwall"],
    },
    "Citrix NetScaler": {
        "headers": [r"x-ns-", r"ns_af", r"citrix"],
        "body": [r"citrix", r"blocked by netscaler"],
    },
}

# payload berbahaya umum untuk memicu blokir WAF
PROBE_PAYLOADS = [
    "' OR 1=1 --",
    "<script>alert(1)</script>",
    "../../../../etc/passwd",
    "1' UNION SELECT @@version--",
    "<iframe src=javascript:alert(1)>",
    "cat /etc/passwd",
]


def _signature_hits(resp, body: str) -> List[str]:
    headers = "\n".join(f"{k}: {v}" for k, v in resp.headers.items()).lower()
    body_l = body.lower()
    hits = []
    for vendor, sig in SIGNATURES.items():
        if any(re.search(p, headers) for p in sig["headers"]) or \
           any(re.search(p, body_l) for p in sig["body"]):
            hits.append(vendor)
    return hits


def detect_waf(base: str, client, timeout: float = 10.0) -> Dict:
    """Deteksi WAF pada target.

    Returns dict: {present, vendors, blocked_payloads, details}.
    """
    parsed = urlparse(base)
    path = parsed.path or "/"
    result = {
        "present": False,
        "vendors": [],
        "blocked_payloads": [],
        "details": [],
        "probe_url": base,
    }

    # 1) baseline request polos
    try:
        r0 = client.get(base, timeout=timeout)
        body0 = r0.text
        hits = _signature_hits(r0, body0)
        if hits:
            result["present"] = True
            result["vendors"].extend(hits)
            result["details"].append("tanda tangan terlihat pada respons polos")
    except Exception as e:
        result["details"].append(f"baseline gagal: {e}")
        return result

    # 2) payload berbahaya
    for payload in PROBE_PAYLOADS:
        import urllib.parse as up
        url = base if "?" in base else base + ("/" if not path.endswith("/") else "")
        url = url + "?q=" + up.quote(payload)
        try:
            r = client.get(url, timeout=timeout)
            body = r.text
            if r.status_code in (403, 406, 429, 503) or "challenge" in body.lower() \
                    or "captcha" in body.lower() or "blocked" in body.lower():
                result["blocked_payloads"].append(payload)
            hits = _signature_hits(r, body)
            if hits:
                result["present"] = True
                for v in hits:
                    if v not in result["vendors"]:
                        result["vendors"].append(v)
        except Exception:
            continue

    result["vendors"] = list(dict.fromkeys(result["vendors"]))
    if result["blocked_payloads"]:
        result["present"] = True
        result["details"].append(f"{len(result['blocked_payloads'])} payload diblokir/challenge")

    return result


def waf_finding(result: Dict) -> Optional[Dict]:
    if not result["present"]:
        return None
    return {
        "severity": "INFO",
        "title": "WAF terdeteksi: " + (", ".join(result["vendors"]) or "Unknown"),
        "endpoint": result["probe_url"],
        "evidence": "; ".join(result["details"]),
    }