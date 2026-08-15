"""Alat reverse engineering untuk web (v0.14.0).

Berfokus pada sisi client yang bisa di-reverse dari bundle JS:
- deobfuscation dasar: eval(atob(...)), string hex/unicode, string concat,
  variabel tunggal, minification counter (mengembalikan kode terbaca).
- source map: unduh `.map`, rekonstruksi nama file asli, konten sumber,
  dan endpoint yang disembunyikan minifier.
- endpoint & secret extraction dari kode yang sudah di-deobfuscate.

Semua murni offline (tidak mengirim payload); hanya membaca aset target.
"""

import base64
import json
import re
from typing import Dict, List, Optional, Tuple

from keris.core.http import KerisHTTP
from keris.core.logger import debug, info, ok, warn

# pola yang sering dipakai obfuscator ringan
_EVAL_ATOB_RE = re.compile(r"eval\s*\(\s*(?:atob|base64decode)\s*\(\s*[\"']([^\"']+)[\"']\s*\)\s*\)", re.I)
_ATOB_RE = re.compile(r"atob\s*\(\s*[\"']([^\"']+)[\"']\s*\)", re.I)
_HEX_STR_RE = re.compile(r"\\x([0-9a-fA-F]{2})")
_UNI_STR_RE = re.compile(r"\\u([0-9a-fA-F]{4})")

# pola secret (dipakai ulang ringkas dari payloads)
_SECRET_RE = {
    "api_key": re.compile(r"(?i)(?:api[_-]?key|apikey|access[_-]?key)\s*[:=]\s*[\"']([^\"']{8,})[\"']"),
    "aws": re.compile(r"\b(AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b"),
    "github_token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    "google_key": re.compile(r"\bAIza[0-9A-Za-z_\-]{30,}\b"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b"),
}

_DOMAIN_RE = re.compile(r"https?://[A-Za-z0-9.\-]+(?::\d+)?(?:/[A-Za-z0-9_\-./?&=%~]*)?")
_ENDPOINT_RE = re.compile(r"[\"'](/[a-zA-Z0-9_\-./]{2,120})[\"']")


def decode_string(s: str) -> str:
    """Decode string yang di-obfuscate: \\x, \\u, atob."""
    out = _HEX_STR_RE.sub(lambda m: chr(int(m.group(1), 16)), s)
    out = _UNI_STR_RE.sub(lambda m: chr(int(m.group(1), 16)), out)
    m = _ATOB_RE.search(out)
    if m:
        try:
            out = base64.b64decode(m.group(1)).decode("utf-8", "replace")
        except Exception:
            pass
    return out


def deobfuscate_js(text: str) -> str:
    """Deobfuscasi JS ringan; kembalikan kode yang lebih terbaca.

    Langkah:
    1. ubah literal eval(atob(...)) menjadi literal string.
    2. decode \\x / \\u di seluruh file.
    3. gabungkan string concat sederhana ('a' + 'b') hanya bila aman (kedua
       sisi string literal).
    4. hitung metrik: panjang, jumlah baris, identitas variabel.
    """
    out = text
    out = _EVAL_ATOB_RE.sub(lambda m: repr(_try_b64(m.group(1))), out)
    out = _ATOB_RE.sub(lambda m: repr(_try_b64(m.group(1))), out)
    out = _HEX_STR_RE.sub(lambda m: _maybe_printable(m.group(1)), out)
    out = _UNI_STR_RE.sub(lambda m: _maybe_printable_uni(m.group(1)), out)
    out = re.sub(r"([\"'])\s*\+\s*([\"'])", lambda m: m.group(1) + m.group(2), out)
    return out


def _try_b64(s: str) -> str:
    try:
        dec = base64.b64decode(s).decode("utf-8", "replace")
        return dec if all(32 <= ord(c) < 127 or c in "\r\n\t" for c in dec) else s
    except Exception:
        return s


def _maybe_printable(hex2: str) -> str:
    c = chr(int(hex2, 16))
    return c if 32 <= ord(c) < 127 or c in "\r\n\t" else "\\x" + hex2


def _maybe_printable_uni(hex4: str) -> str:
    c = chr(int(hex4, 16))
    return c if 32 <= ord(c) < 127 or c in "\r\n\t" else "\\u" + hex4


def stats(text: str) -> Dict:
    """Metrik dasar bundle untuk menilai tingkat obfuscation."""
    lines = text.count("\n") + 1
    identifiers = set(re.findall(r"[a-zA-Z_$][a-zA-Z0-9_$]{0,40}", text))
    short_ids = sum(1 for i in identifiers if len(i) <= 2)
    return {
        "chars": len(text),
        "lines": lines,
        "unique_identifiers": len(identifiers),
        "short_identifiers": short_ids,
        "obfuscation_signals": sum([
            bool(_EVAL_ATOB_RE.search(text)),
            bool(_HEX_STR_RE.search(text)),
            bool(_UNI_STR_RE.search(text)),
            short_ids > 30,
            len(identifiers) > 0 and short_ids / max(len(identifiers), 1) > 0.6,
        ]),
    }


def extract_endpoints(text: str, base: str = "") -> List[str]:
    """Ekstrak endpoint API & URL dari bundle (termasuk hasil decode)."""
    eps = set()
    for m in _ENDPOINT_RE.finditer(text):
        p = m.group(1)
        if re.match(r"^/(api|v\d|graphql|internal|admin|private|internal-api)", p, re.I):
            eps.add(p)
    for m in _DOMAIN_RE.finditer(text):
        u = m.group(0)
        if base and base.rstrip("/") in u:
            rest = u.split(base.rstrip("/"))[-1]
            if rest.startswith("/") and not rest.startswith("//"):
                eps.add(rest)
        elif "/" in u:
            eps.add(u)
    return sorted(eps)


def extract_secrets(text: str) -> List[Dict]:
    secrets = []
    for name, pat in _SECRET_RE.items():
        for m in pat.finditer(text):
            secrets.append({"type": name, "match": m.group(0)[:120]})
    return secrets


def fetch_and_analyze(base: str, client: KerisHTTP, asset_url: str) -> Dict:
    """Unduh satu asset JS dan analisis penuh (deobfuscate + extract)."""
    if asset_url.startswith(("http://", "https://")):
        url = asset_url
    else:
        url = base.rstrip("/") + asset_url
    r = client.get(url, timeout=15)
    if r.status_code != 200:
        raise ValueError(f"HTTP {r.status_code} untuk {url}")
    text = r.text
    before = stats(text)
    cleaned = deobfuscate_js(text)
    after = stats(cleaned)

    endpoints = extract_endpoints(cleaned, base)
    secrets = extract_secrets(cleaned)

    # source map: unduh .map bila tersedia
    sources = []
    src_map = _fetch_source_map(client, url, text)
    if src_map:
        sources = _parse_source_map(src_map, base)

    return {
        "url": url,
        "obfuscated": before["obfuscation_signals"] >= 2,
        "stats_before": before,
        "stats_after": after,
        "endpoints": endpoints,
        "secrets": secrets,
        "sources": sources,
        "deobfuscated_len": len(cleaned),
    }


def _fetch_source_map(client: KerisHTTP, js_url: str, js_text: str) -> Optional[dict]:
    m = re.search(r"//# sourceMappingURL=(\S+)", js_text)
    if not m:
        m = re.search(r"/*# sourceMappingURL=(\S+)", js_text)
    if not m:
        return None
    map_url = m.group(1)
    if not map_url.startswith(("http://", "https://")):
        map_url = js_url.rsplit("/", 1)[0] + "/" + map_url
    try:
        r = client.get(map_url, timeout=15)
        if r.status_code == 200:
            return json.loads(r.text)
    except Exception:
        return None
    return None


def _parse_source_map(src_map: dict, base: str) -> List[Dict]:
    sources = src_map.get("sources", []) or []
    contents = src_map.get("sourcesContent", []) or []
    out = []
    for i, s in enumerate(sources):
        url = s if s.startswith(("http://", "https://")) else base.rstrip("/") + (s if s.startswith("/") else "/" + s)
        content = contents[i] if i < len(contents) else ""
        eps = extract_endpoints(content, base) if content else []
        sec = extract_secrets(content) if content else []
        out.append({
            "source": url,
            "has_content": bool(content),
            "endpoints": eps,
            "secrets": sec,
        })
    return out


def analyze_assets(base: str, client: KerisHTTP, assets: List[str], max_assets: int = 20) -> Dict:
    """Analisis beberapa asset JS; kembalikan ringkasan agregat."""
    results = []
    endpoint_set = set()
    secret_list = []
    source_list = []
    for a in assets[:max_assets]:
        try:
            res = fetch_and_analyze(base, client, a)
            results.append(res)
            endpoint_set.update(res["endpoints"])
            secret_list.extend(res["secrets"])
            source_list.extend(res["sources"])
        except Exception as e:
            debug(f"RE {a} gagal: {e}")
    return {
        "assets": results,
        "endpoints": sorted(endpoint_set),
        "secrets": secret_list,
        "sources": source_list,
    }