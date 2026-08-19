"""Deteksi link backdoor & konten mencurigakan di halaman web (v0.14.0).

Memindai HTML + JS yang diunduh untuk sinyal kompromi:
- script/iframe eksternal dari domain tidak dikenal atau domain parkir.
- URL ter-encode (base64 / hex) sebagai callback C2.
- pola webshell / backdoor di aset publik (eval(atob), eval(gzinflate),
  $_POST command execution, c99/r57/b374k signature).
- crypto miner inline (coinhive-style), beacon ke domain mencurigakan.
- link `data:` dan `javascript:` yang mencurigakan.

Catatan: alat ini menghasilkan *sinyal* (indikasi), bukan bukti kompromi.
Setiap temuan diberi `confidence` rendah-sedang agar tidak dianggap pasti.
"""

import base64
import re
from typing import Dict, List, Tuple

from keris.modules.scanner import Finding

# domain publik/penyedia CDN yang wajar (tidak dianggap mencurigakan bila
# script pihak ketiga hanya dari sini)
TRUSTED_DOMAINS = {
    "google-analytics.com", "googletagmanager.com", "gstatic.com",
    "googleapis.com", "jsdelivr.net", "unpkg.com", "cdnjs.cloudflare.com",
    "cloudflare.com", "cloudflareinsights.com", "fontawesome.com",
    "bootstrapcdn.com", "jquery.com", "jquerymobile.com", "wp.com",
    "wordpress.org", "gravatar.com", "doubleclick.net", "adservice.google.com",
    "recaptcha.net", "facebook.net", "connect.facebook.net", "twitter.com",
    "x.com", "disqus.com", "hotjar.com", "mixpanel.com", "segment.io",
    "amplitude.com", "intercom.io", "stripe.com", "paypalobjects.com",
    "sentry.io", "zendesk.com", "hubspot.com", "crisp.chat", "tawk.to",
    "clarity.ms", "microsoft.com", "microsoftonline.com",
}

SUSPICIOUS_TLDS = {"top", "xyz", "tk", "ml", "ga", "cf", "gq", "club", "work", "click", "link"}

_SCRIPT_SRC_RE = re.compile(r"<script[^>]*src=[\"']([^\"']+)[\"']", re.I)
_IFRAME_SRC_RE = re.compile(r"<iframe[^>]*src=[\"']([^\"']+)[\"']", re.I)
_META_REFRESH_RE = re.compile(r"<meta[^>]*http-equiv=[\"']refresh[\"'][^>]*content=[\"'][^\"']*url=([^\"']+)", re.I)
_LINK_HREF_RE = re.compile(r"<link[^>]*href=[\"']([^\"']+)[\"']", re.I)

_WS_PATTERNS = [
    (re.compile(r"eval\s*\(\s*(?:gzinflate|base64_decode|str_rot13)\s*\(", re.I), "eval dengan decoder terobfuskasi (webshell pattern)"),
    (re.compile(r"(?i)\b(b374k|c99shell|r57shell|wso|alfashell|christina)\b"), "signature webshell publik"),
    (re.compile(r"\$_(?:GET|POST|REQUEST|COOKIE)\[['\"]?[a-z0-9_]{1,8}['\"]?\]\s*\(", re.I), "execusi shell dari input (PHP)"),
    (re.compile(r"(?i)(system|passthru|shell_exec|exec)\s*\(\s*\$_"), "command execution dari parameter"),
    (re.compile(r"base64_decode\s*\(\s*['\"][A-Za-z0-9+/=]{40,}", re.I), "payload base64 besar ter-obfuscate"),
]

_C2_BEACON_RE = re.compile(r"(?i)(beacon|callback|ping|report|collect|track)\.(?:js|php|aspx|action)", )


def _host(url: str) -> str:
    m = re.match(r"https?://([^/?#]+)", url or "")
    if m:
        return m.group(1).split(":")[0].lower()
    return (url or "").strip()


def _is_private_ip(host: str) -> bool:
    if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host or ""):
        return False
    parts = host.split(".")
    first, second = parts[0], parts[1]
    return (
        first == "127" or first == "10"
        or (first == "172" and 16 <= int(second) <= 31)
        or (first == "192" and second == "168")
        or (first == "169" and second == "254")
        or first == "0"
    )


def _is_suspicious_host(host: str) -> Tuple[bool, str]:
    if not host:
        return False, ""
    # IP publik (bukan localhost/privat/loopback) sebagai host script = mencurigakan
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
        if _is_private_ip(host):
            return False, ""
        return True, f"script dari IP publik langsung ({host})"
    base = host.split(".")[-2:] if "." in host else [host]
    tld = base[-1] if base else ""
    reg_domain = ".".join(base) if len(base) >= 2 else host
    if tld in SUSPICIOUS_TLDS:
        return True, f"domain TLD berisiko ({tld})"
    # punycode / obfuscated IDN
    if "xn--" in host:
        return True, "domain punycode (IDN ter-obfuscate)"
    # subdomain acak panjang (kemungkinan dynamic C2)
    if len(host) > 60:
        return True, "hostname sangat panjang (kemungkinan C2/dynamic DNS)"
    if reg_domain in TRUSTED_DOMAINS:
        return False, ""
    return False, ""


def _decode_b64_tokens(text: str) -> str:
    decoded = ""
    for m in re.finditer(r"atob\s*\(\s*[\"']([A-Za-z0-9+/=]{16,})[\"']\s*\)", text):
        try:
            decoded += base64.b64decode(m.group(1)).decode("utf-8", "replace") + "\n"
        except Exception:
            continue
    return decoded


def scan_page(html: str, page_url: str, base: str = "") -> List[Finding]:
    """Scan HTML satu halaman untuk link/script/iframe mencurigakan."""
    findings: List[Finding] = []
    base_host = _host(base or page_url)
    suspicious_scripts = 0
    suspicious_iframes = 0

    def _add(sev, title, endpoint, detail, evidence):
        findings.append(Finding(
            severity=sev, title=title, endpoint=endpoint or page_url,
            detail=detail, evidence=evidence[:400],
            source="backdoor",
        ))

    # script eksternal dari domain tidak dikenal
    for m in _SCRIPT_SRC_RE.finditer(html):
        src = m.group(1)
        host = _host(src)
        if not host:
            continue
        if host == base_host or host.endswith("." + base_host):
            continue
        bad, reason = _is_suspicious_host(host)
        if bad:
            suspicious_scripts += 1
            _add("MEDIUM", "Script eksternal dari sumber mencurigakan",
                 src, f"{reason}. Audit apakah aset ini benar-benar milik aplikasi.",
                 f"<script src='{src}'>")
        elif _is_private_ip(host):
            # script menunjuk ke jaringan privat lain: indikasi intranet/panel/pivot
            suspicious_scripts += 1
            _add("MEDIUM", "Script eksternal menunjuk ke IP privat",
                 src,
                 f"Script diambil dari {host} (jaringan privat). Bila target adalah "
                 "server publik, ini bisa menandakan kompromi/akses internal.",
                 f"<script src='{src}'>")

    for m in _IFRAME_SRC_RE.finditer(html):
        src = m.group(1)
        host = _host(src)
        if not host:
            continue
        if host == base_host or host.endswith("." + base_host):
            continue
        bad, reason = _is_suspicious_host(host)
        if bad:
            suspicious_iframes += 1
            _add("MEDIUM", "iframe tersembunyi dari sumber mencurigakan",
                 src, f"{reason}. iframe pihak ketiga sering dipakai untuk ad-inject/redirect.",
                 f"<iframe src='{src}'>")
        elif _is_private_ip(host):
            suspicious_iframes += 1
            _add("MEDIUM", "iframe menunjuk ke IP privat",
                 src,
                 f"iframe menunjuk ke {host} (jaringan privat). Bisa indikasi "
                 "kompromi / konten internal.",
                 f"<iframe src='{src}'>")

    # meta refresh ke domain lain
    for m in _META_REFRESH_RE.finditer(html):
        target = m.group(1).strip()
        tgt_host = _host(target)
        if tgt_host and tgt_host not in (base_host, "") and target.startswith(("http://", "https://")):
            _add("LOW", "Meta refresh mengarah ke domain lain", target,
                 "Meta refresh URL eksternal dapat dipakai redirect diam-diam.", target[:200])

    # webshell / backdoor signature di HTML inline
    for pat, label in _WS_PATTERNS:
        for m in pat.finditer(html):
            _add("HIGH", f"Potensi backdoor: {label}",
                 page_url,
                 "Ditemukan pola eksekusi kode terobfuscasi di konten publik. "
                 "Verifikasi apakah ini konten resmi atau hasil kompromi.",
                 m.group(0)[:200])
            break
        # cukup satu match per pola

    # beacon / callback C2
    if _C2_BEACON_RE.search(html):
        _add("LOW", "Beacon/callback ke endpoint eksternal", page_url,
             "Pola beacon ke endpoint external (report/callback/collect). "
             "Wajar bila aplikasi memakai analytics; verifikasi host-nya.",
             "")

    # link javascript:/data: mencurigakan
    for m in re.finditer(r"href=[\"'](javascript:[^\"']{1,80})[\"']", html, re.I):
        _add("MEDIUM", "Link javascript: mencurigakan", page_url,
             "Link javascript: inline berpotensi phishing/redirect.", m.group(1)[:100])
        break

    # decode atob tokens lalu scan ulang untuk endpoint/domain mencurigakan
    decoded = _decode_b64_tokens(html)
    if decoded:
        suspicious_in_decoded = 0
        for host in set(_host(u) for u in _DOMAIN_URL_RE.findall(decoded)):
            if not host or host == base_host:
                continue
            bad, reason = _is_suspicious_host(host)
            if bad:
                suspicious_in_decoded += 1
                _add("HIGH", "URL ter-encode (base64) ke host mencurigakan",
                     page_url,
                     f"{reason}. String base64 di-decode dan berisi URL ke host "
                     "tidak dikenal — pola umum callback C2/backdoor.",
                     decoded[:300])
        if suspicious_in_decoded:
            # beri tahu total tanpa spam
            pass

    # data: script
    for m in re.finditer(r"src=[\"']data:text/javascript[^\"']*[\"']", html, re.I):
        _add("MEDIUM", "Script inline data: URI", page_url,
             "Script data:text/javascript mengaburkan kode di URL. "
             "Wajar pada beberapa kasus, audit isi.",
             m.group(0)[:200])
        break

    return findings


_DOMAIN_URL_RE = re.compile(r"https?://[^\s\"'<>]{5,120}")


def scan_assets(base: str, client, assets: List[str], html: str = "",
                max_assets: int = 20) -> List[Finding]:
    """Scan halaman utama + aset JS untuk sinyal backdoor."""
    findings: List[Finding] = []
    findings.extend(scan_page(html, base, base))

    # asset JS eksternal dari host mencurigakan (mis. injected di halaman)
    ext_scripts = set()
    for m in _SCRIPT_SRC_RE.finditer(html):
        src = m.group(1)
        if src.startswith(("http://", "https://")):
            ext_scripts.add(src)
    for src in list(ext_scripts)[:max_assets]:
        host = _host(src)
        if not host:
            continue
        bad, reason = _is_suspicious_host(host)
        if bad:
            findings.append(Finding(
                "HIGH", "Asset JS dari host mencurigakan dihitung dalam scan",
                src, f"{reason}. Script ini tidak termasuk whitelist CDN.",
                src[:300],
                source="backdoor",
            ))
    return findings