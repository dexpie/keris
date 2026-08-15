"""Favicon & tech fingerprint hash (cara Shodan).

Menghitung mmh3 + base64 hash favicon lalu membandingkannya dengan database
hash favicon yang dikenal untuk mengidentifikasi teknologi / produk. Hash
serupa juga bisa dicari di Shodan (http.favicon.hash).
"""

import base64
import hashlib
import re
from typing import Dict, List, Optional

import requests

from keris.core.http import KerisHTTP
from keris.core.logger import debug, info, ok, warn
from keris.modules.scanner import Finding
from keris.core.utils import urljoin

try:
    import mmh3  # type: ignore
    HAS_MMH3 = True
except Exception:
    HAS_MMH3 = False

# Database hash favicon -> teknologi (nilai hash mmh3)
FAVICON_DB = {
    1934113824: "WordPress",
    2144836012: "WordPress admin",
    -1395107346: "Drupal",
    1841626289: "Joomla",
    1461297618: "Plesk",
    1875556359: "cPanel",
    635140011: "Apache Tomcat",
    -819870912: "GitHub Pages",
    1423494388: "GitLab",
    1300374272: "Jenkins",
    1680815319: "Nexus",
    1658620658: "Confluence",
    472275123: "Zabbix",
    -1313913238: "Kibana",
    -915971695: "Elasticsearch",
    1419825177: "Grafana",
    -921345641: "PHPMyAdmin",
    435330340: "phpMyAdmin",
    -743637002: "Roundcube",
    -1381074755: "Odoo",
    1515323200: "Nextcloud",
    -893620889: "MinIO",
    1210424278: "Docker Registry",
    1905582615: "SonarQube",
    1520936044: "Gitea",
    -316791240: "Moodle",
    567031697: "Discourse",
    2110575277: "Flarum",
}


def _favicon_urls(base: str, html: str) -> List[str]:
    """Temukan URL favicon dari HTML."""
    urls = []
    for m in re.finditer(r'<link[^>]+rel=["\'](?:shortcut\s+)?icon["\'][^>]*>', html, re.I):
        href = re.search(r'href=["\']([^"\']+)["\']', m.group(0))
        if href:
            urls.append(href.group(1))
    if not urls:
        urls = ["/favicon.ico"]
    return [urljoin(base, u) for u in urls]


def favicon_hash(data: bytes) -> Optional[int]:
    """mmh3 hash base64 dari favicon (sama seperti Shodan)."""
    if not HAS_MMH3:
        return None
    b64 = base64.encodebytes(data)
    return mmh3.hash(b64)


def fingerprint_favicon(base: str, client: KerisHTTP,
                        html: str = "") -> Dict:
    """Ambil favicon, hash, cocokkan dengan database. Kembalikan dict."""
    info("=== FAVICON FINGERPRINT ===")
    urls = _favicon_urls(base, html) if html else [urljoin(base, "/favicon.ico")]
    for u in urls:
        try:
            r = client.get(u, timeout=12)
        except requests.RequestException:
            continue
        if r.status_code != 200 or not r.content:
            continue
        h = favicon_hash(r.content)
        if h is None:
            continue
        tech = FAVICON_DB.get(h)
        ok(f"Favicon hash {h} ({tech or 'unknown'})")
        return {"url": u, "hash": h, "tech": tech, "size": len(r.content)}
    warn("Favicon tidak ditemukan / tidak bisa di-hash")
    return {}


def fingerprint_findings(base: str, client: KerisHTTP, html: str = "") -> List[Finding]:
    res = fingerprint_favicon(base, client, html=html)
    if not res or not res.get("tech"):
        return []
    return [Finding(
        "INFO", f"Teknologi teridentifikasi via favicon hash: {res['tech']}",
        res.get("url", base),
        f"Favicon di {res['url']} memiliki hash mmh3 `{res['hash']}` yang cocok dengan "
        f"fingerprint {res['tech']}.",
        f"hash: {res['hash']}",
    )]