"""Correlation engine: chains low/medium findings into critical attack chains."""

from typing import Dict, List

CHAIN_RULES = [
    {
        "name": "Cache poisoning + reflected XSS",
        "needs": ["cache-poison", "xss"],
        "severity": "CRITICAL",
        "why": "Reflected XSS yang bisa disuntik lewat header cacheable menjadi stored XSS untuk semua user yang memuat cache.",
    },
    {
        "name": "Host header injection + password reset",
        "needs": ["host-header", "reset-poisoning"],
        "severity": "HIGH",
        "why": "Host header yang direfleksikan di link reset password memungkinkan akun dikompromikan oleh attacker (password-reset poisoning).",
    },
    {
        "name": "Auth bypass + sensitive endpoint",
        "needs": ["auth-bypass", "sensitive"],
        "severity": "CRITICAL",
        "why": "Bypass autentikasi plus data sensitif yang terbuka memberikan akses penuh ke informasi internal tanpa kredensial.",
    },
    {
        "name": "Weak credentials + admin panel",
        "needs": ["weak-login", "admin-panel"],
        "severity": "CRITICAL",
        "why": "Login lemah pada panel admin memungkinkan takeover langsung.",
    },
    {
        "name": "Directory listing + backup file",
        "needs": ["listing", "backup"],
        "severity": "HIGH",
        "why": "Directory listing yang membocorkan file backup membuat source code atau konfigurasi bisa diekstrak.",
    },
    {
        "name": "CORS wildcard + auth cookie",
        "needs": ["cors", "cookie"],
        "severity": "HIGH",
        "why": "CORS yang mengizinkan origin bebas plus cookie session tanpa proteksi membuat data user bisa dibaca dari situs lain.",
    },
]

_TAGS = {
    "cache-poison": ("cache", "poison"),
    "xss": ("xss", "cross-site", "cross site", "dom"),
    "host-header": ("host header", "host-header", "hostheader"),
    "reset-poisoning": ("reset", "password-reset", "forgot"),
    "auth-bypass": ("auth bypass", "authentication bypass", "bypass"),
    "sensitive": ("sensitive", "pii", "credential", "api key", "token", "secret"),
    "weak-login": ("weak", "brute", "login"),
    "admin-panel": ("admin", "panel"),
    "listing": ("directory listing", "listing"),
    "backup": ("backup", ".bak", ".zip"),
    "cors": ("cors", "cross-origin resource"),
    "cookie": ("cookie", "session"),
}


def _tag_finding(f: Dict) -> List[str]:
    text = " ".join([
        str(f.get("title", "")),
        str(f.get("detail", "")),
        str(f.get("endpoint", "")),
    ]).lower()
    tags = []
    for tag, needles in _TAGS.items():
        if any(n in text for n in needles):
            tags.append(tag)
    return tags


def build_chains(findings: List[Dict]) -> List[Dict]:
    """Returns a list of chain findings (dicts) derived from existing findings."""
    if not findings:
        return []
    tagged = [(f, set(_tag_finding(f))) for f in findings]
    chains = []
    for rule in CHAIN_RULES:
        needs = set(rule["needs"])
        hits = []
        covered = set()
        for f, tags in tagged:
            have = needs.intersection(tags)
            if have:
                hits.append(f)
                covered |= have
        if covered == needs and hits:
            chains.append({
                "severity": rule["severity"],
                "title": rule["name"],
                "endpoint": " / ".join(str(f.get("endpoint", "")) for f in hits),
                "detail": rule["why"],
                "evidence": "Chain terbentuk dari: " + "; ".join(
                    "[{s}] {t} @ {e}".format(
                        s=f.get("severity", "?"), t=f.get("title", "?"), e=f.get("endpoint", "?"))
                    for f in hits),
                "chain": rule["name"],
                "source": "correlation",
            })
    return chains