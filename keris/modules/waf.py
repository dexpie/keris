"""WAF detection & fingerprinting: identifikasi Web Application Firewall."""

from typing import Dict, List, Optional

import requests

from keris.core.http import KerisHTTP
from keris.core.logger import debug, info, ok, warn

# Pola identifikasi: (nama, header yang dicocokkan, nilai, body signature)
WAF_SIGNATURES = [
    ("Cloudflare", ["server"], "cloudflare",
     ["cf-ray", "__cf_bm", "__cfduid", "cf_chl"]),
    ("AWS WAF / CloudFront", ["server"], "cloudfront",
     ["x-amz-cf-id", "x-amz-cf-pop", "AWSALB", "awswaf"]),
    ("Sucuri", ["server"], "sucuri", ["sucuri", "X-Sucuri-ID"]),
    ("Akamai", ["server"], "akamai", ["akamai", "AkamaiGHost"]),
    ("Imperva / Incapsula", ["server"], "incapsula", ["incap_ses", "X-Iinfo", "visid_incap"]),
    ("F5 BIG-IP ASM", ["server"], "big-ip", ["F5-Traffic-Shapes", "BIGipServer"]),
    ("ModSecurity (OWASP CRS)", ["server"], "mod_security", ["mod_security", "OWASP_CRS"]),
    ("Barracuda", ["server"], "barracuda", ["barracuda"]),
    ("Fastly", ["server"], "fastly", ["x-fastly", "Fastly-SSL"]),
    ("Varnish", ["server"], "varnish", ["x-varnish"]),
    ("Wordfence", ["server"], "wordfence", ["wfWAF", "wordfence"]),
    ("Comodo / cWatch", ["server"], "comodo", ["cwatch", "comodo"]),
]


def detect_waf(base: str, client: KerisHTTP, timeout: float = 15.0) -> Dict:
    """Deteksi WAF dari header respons dan body block page."""
    info("Deteksi WAF ...")
    result = {"waf": None, "evidence": [], "blocked": False}

    try:
        r = client.get(base, timeout=timeout)
    except requests.RequestException as e:
        result["evidence"].append(f"request failed: {e}")
        return result

    headers = {k.lower(): v for k, v in r.headers.items()}
    body = r.text[:4000].lower()

    # 1. cocokkan signature dari header
    matched = set()
    for name, hdr_keys, value, body_markers in WAF_SIGNATURES:
        hdr_key = hdr_keys[0] if isinstance(hdr_keys, list) else hdr_keys
        hdr_val = str(headers.get(hdr_key, "")).lower()
        hits = []
        if value in hdr_val:
            hits.append(f"{hdr_key}: {hdr_val}")
        for marker in body_markers:
            if marker.lower() in body or marker.lower() in hdr_val:
                hits.append(marker)
        if hits:
            matched.add(name)
            result["evidence"].append(f"{name}: {hits[0]}")

    # 2. tanda block page umum
    block_signals = ["access denied", "blocked", "request rejected", "cf-error",
                     "challenge", "attention required", "waf", "threat",
                     "403 forbidden"]
    if any(s in body for s in block_signals) and r.status_code in (403, 429, 503):
        result["blocked"] = True
        result["evidence"].append(f"block page: status {r.status_code}")

    if matched:
        result["waf"] = ", ".join(sorted(matched))
        ok(f"WAF terdeteksi: {result['waf']}")
    else:
        debug("WAF tidak terdeteksi dari signature umum")

    return result
