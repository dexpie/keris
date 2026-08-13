"""Utilitas umum: normalisasi URL, parsing, regex ekstraksi."""

import re
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode, urljoin


def normalize_url(url: str) -> str:
    """Normalisasi URL: tambah skema jika hilang, hapus trailing slash (kecuali root)."""
    url = url.strip().strip('"').strip("'")
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "https://" + url
    p = urlparse(url)
    path = p.path or "/"
    if path != "/" and path.endswith("/"):
        path = path.rstrip("/")
    netloc = p.netloc.lower()
    return urlunparse((p.scheme.lower(), netloc, path, p.params, p.query, p.fragment))


def host_from_url(url: str) -> str:
    return urlparse(normalize_url(url)).netloc


def scheme_from_url(url: str) -> str:
    return urlparse(normalize_url(url)).scheme


def add_query(url: str, **params) -> str:
    """Tambahkan/update query params pada URL."""
    p = urlparse(url)
    q = dict(parse_qsl(p.query))
    q.update({k: v for k, v in params.items() if v is not None})
    return urlunparse((p.scheme, p.netloc, p.path, p.params, urlencode(q), p.fragment))


def extract_urls(text: str) -> set:
    """Ekstrak URL absolut/relatif dari teks (HTML/JS)."""
    found = set()
    # absolut http(s)
    for m in re.finditer(r"https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+", text):
        found.add(m.group(0))
    # /api/... path relatif
    for m in re.finditer(r"['\"`]((?:/api|/v\d)/[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]*)['\"`]", text):
        found.add(m.group(1))
    return found


def extract_api_paths(text: str) -> set:
    """Ekstrak path API relatif dari JS/HTML."""
    found = set()
    for m in re.finditer(r"/api/[a-zA-Z0-9/_.?&=%\-\{}$\[\]:~]+", text):
        found.add(m.group(0))
    return found


def extract_js_assets(html: str, base: str) -> set:
    """Ekstrak URL asset JS (.js) dari HTML."""
    found = set()
    for m in re.finditer(r'(?:src|href)=["\']([^"\']+\.js[^"\']*)["\']', html):
        url = m.group(1)
        if url.startswith(("http://", "https://")):
            found.add(url)
        elif url.startswith("//"):
            p = urlparse(base)
            found.add(f"{p.scheme}:{url}")
        else:
            found.add(urljoin(base, url))
    return found


def domain_from_host(host: str) -> str:
    """Ambil domain tingkat kedua+ dari host (mis. sub.example.co.id -> example.co.id)."""
    parts = host.lower().split(".")
    if len(parts) <= 2:
        return host
    # heuristic sederhana: jika punya ccTLD dua huruf, ambil 3 part terakhir
    if len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def strip_protocol(url: str) -> str:
    return url.split("://", 1)[-1].split("/", 1)[0]
